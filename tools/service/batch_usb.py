"""Bounded read queries over one claimed USB interface.

The caller owns the device guard and lock for the entire session. Per-query
closure means a fresh, strictly parsed reply and two quiet phases, not an idle
USB interface. Only close() restores/releases USB. No print or reset operation.
"""
import base64
import ctypes as C
import ctypes.util
import datetime as dt
import re
import secrets
import sys
from pathlib import Path
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'firmware'))
import probe_printer as probe
from framebuffer_memory import extract_tagged_value,extract_addressed_reply
from run_service_read import safe_memory_command


def payload_for(kind,nonce,memory=None):
    if memory is None:
        allowed=(kind in ('fw_info_tagged','telemetry_serial','lcd_pointer_tagged','reset_info_native')
                 or kind.startswith('telemetry_'))
        if not allowed or kind not in probe.SMALL_READ_COMMANDS:
            raise ValueError('only fixed scalar/LCD-pointer reads are allowed')
        return probe.make_small_read_query(kind,nonce,129)
    if kind!='runtime_mem' or not isinstance(memory,(list,tuple)) or len(memory)!=2:
        raise ValueError('memory requires a bounded address/length pair')
    if not re.fullmatch(r'[a-f0-9]{6}',nonce):raise ValueError('invalid nonce')
    command=safe_memory_command(*memory)
    script=b'puts B'+nonce.encode()+b'\n'+command+b'\nputs E'+nonce.encode()+b'\nexit\n'
    prefix=probe.UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail=b'\n'+probe.UEL+b'\r\n';padding=129-len(prefix)-len(tail)
    if padding<0:raise ValueError('bounded memory query exceeds 129 bytes')
    return prefix+(b'#'+b' '*(padding-1) if padding else b'')+tail


class ReadSession:
    def __init__(self,bus,address,cutoff,lib=None,alt_observer=None,now=None,
                 sleep=None,nonce_factory=None,refresh_id_each_query=False,comment_bytes=64):
        if cutoff.tzinfo is None:raise ValueError('session deadline needs timezone')
        self.bus=bus;self.address=address;self.cutoff=cutoff
        self.lib=lib if lib is not None else C.CDLL(ctypes.util.find_library('usb-1.0'))
        self.alt_observer=alt_observer or (lambda:probe.observe_host_alt(bus,address))
        self.now=now or time.monotonic;self.sleep=sleep or time.sleep
        self.nonce_factory=nonce_factory or (lambda:secrets.token_hex(3))
        if type(refresh_id_each_query) is not bool:raise ValueError('identity refresh policy must be boolean')
        self.refresh_id_each_query=refresh_id_each_query
        if type(comment_bytes) is not int or comment_bytes not in (63,64):
            raise ValueError('comment length must explicitly be 63 or 64 bytes')
        self.comment_bytes=comment_bytes
        self.ctx=C.c_void_p();self.handle=None;self.initialized=False;self.claimed=False
        self.previous=None;self.alt_attempted=False;self.closed=False
        self.stream_closed=True;self.poisoned=False;self.used=set()
        self.queries=[];self.controls=[];self.cleanup={};self.cleanup_verified=False
        ptr=C.c_void_p;integer=C.c_int
        def bind(name,args,result):
            f=getattr(self.lib,'libusb_'+name);f.argtypes=args;f.restype=result;return f
        self.init=bind('init',[C.POINTER(ptr)],integer)
        self.leave=bind('exit',[ptr],None)
        self.open=bind('open_device_with_vid_pid',[ptr,C.c_uint16,C.c_uint16],ptr)
        self.close_handle=bind('close',[ptr],None)
        self.device=bind('get_device',[ptr],ptr)
        self.get_bus=bind('get_bus_number',[ptr],C.c_uint8)
        self.get_address=bind('get_device_address',[ptr],C.c_uint8)
        self.active=bind('kernel_driver_active',[ptr,integer],integer)
        self.claim=bind('claim_interface',[ptr,integer],integer)
        self.release=bind('release_interface',[ptr,integer],integer)
        self.alternate=bind('set_interface_alt_setting',[ptr,integer,integer],integer)
        self.control=bind('control_transfer',[ptr,C.c_uint8,C.c_uint8,C.c_uint16,
                          C.c_uint16,ptr,C.c_uint16,C.c_uint],integer)
        self.bulk=bind('bulk_transfer',[ptr,C.c_ubyte,ptr,integer,C.POINTER(integer),C.c_uint],integer)

    def read_alt(self):
        value=C.c_ubyte();rc=self.control(self.handle,0x81,10,0,0,C.byref(value),1,1000)
        host=self.alt_observer()
        self.controls.append({'operation':'GET_INTERFACE','rc':rc,
                              'device':value.value,'host':host})
        if rc!=1 or host not in (0,1):raise RuntimeError('interface observation failed')
        return host

    def __enter__(self):
        try:
            if (self.cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<90:
                raise RuntimeError('not enough authorized session time')
            rc=self.init(C.byref(self.ctx))
            if rc:raise RuntimeError(('libusb_init',rc))
            self.initialized=True
            self.handle=self.open(self.ctx,0x1a86,0x7584)
            if not self.handle:raise RuntimeError('adapter open failed')
            dev=self.device(self.handle)
            if (self.get_bus(dev),self.get_address(dev))!=(self.bus,self.address):
                raise RuntimeError('adapter changed after preflight')
            if self.active(self.handle,0)!=0:
                raise RuntimeError('batch session requires explicit unbound idle policy')
            rc=self.claim(self.handle,0)
            if rc:raise RuntimeError(('claim interface',rc))
            self.claimed=True;self.previous=self.read_alt()
            if self.previous!=0:raise RuntimeError('batch session must begin at alt0')
            self.alt_attempted=True;rc=self.alternate(self.handle,0,1)
            self.controls.append({'operation':'SET_INTERFACE','alternate':1,'rc':rc})
            if rc or self.read_alt()!=1:raise RuntimeError('bidirectional interface not selected')
            self.read_identity()
            return self
        except BaseException:
            self.close();raise

    def read_identity(self):
        for attempt in range(2):
            buf=C.create_string_buffer(1024)
            rc=self.control(self.handle,0xa1,0,0,1,buf,len(buf),5000)
            raw=buf.raw[:max(0,rc)]
            self.controls.append({'operation':'GET_DEVICE_ID','rc':rc,'hex':raw.hex(),
                                  'before_query_index':len(self.queries)})
            if rc!=0:break
            self.sleep(.005)
        if rc<=0 or not probe.parse_device_id(raw)['hp_c7769b_identified']:
            raise RuntimeError('fresh HP C7769B identity not confirmed')

    def command_payload(self,kind,nonce,memory=None):
        return payload_for(kind,nonce,memory)

    def query(self,kind,memory=None):
        if self.closed or not self.handle or self.poisoned or not self.stream_closed:
            raise RuntimeError('session is closed or has an uncertain prior query')
        if len(self.queries)>=87:raise RuntimeError('session query limit reached')
        if (self.cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<90:
            raise RuntimeError('not enough authorized time for query and cleanup')
        for _ in range(8):
            nonce=self.nonce_factory()
            if not re.fullmatch(r'[a-f0-9]{6}',nonce):raise ValueError('invalid nonce')
            if nonce not in self.used:break
        else:raise RuntimeError('could not allocate a unique session nonce')
        payload=self.command_payload(kind,nonce,memory);self.used.add(nonce)
        if self.refresh_id_each_query and self.queries:self.read_identity()
        report={'kind':kind,'memory':memory,'nonce':nonce,
                'observed_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
                'payload_hex':payload.hex(),'transport_scope':'same_open_session',
                'identity_refreshed':not self.queries or self.refresh_id_each_query,
                'comment_bytes':self.comment_bytes,
                'phases':[],'out_attempts':0,'out_bytes':0,'stream_closed':False}
        self.queries.append(report);response=bytearray();quiet=0
        try:
            for index in range(9):
                block=payload if index==0 else probe.make_drain_comment(self.comment_bytes)
                phase={'name':kind if index==0 else 'comment_tick_'+str(index),
                       'payload_hex':block.hex(),'response_offset':len(response)}
                report['phases'].append(phase)
                buf=C.create_string_buffer(block);count=C.c_int()
                report['out_attempts']+=1;self.stream_closed=False
                rc=self.bulk(self.handle,1,buf,len(block),C.byref(count),1500)
                phase.update(write_rc=rc,written_bytes=count.value)
                report['out_bytes']+=count.value
                if rc or count.value!=len(block):
                    raise RuntimeError('incomplete OUT; no query replay')
                self.sleep(.25);offset=len(response);until=self.now()+1
                rx=C.create_string_buffer(64);phase['reads']=[]
                try:
                    while self.now()<until and len(response)<65536:
                        received=C.c_int()
                        rc=self.bulk(self.handle,0x82,rx,min(64,65536-len(response)),
                                     C.byref(received),1000)
                        if not 0<=received.value<=64:raise RuntimeError('invalid IN count')
                        phase['reads'].append({'rc':rc,'bytes':received.value})
                        response.extend(rx.raw[:received.value])
                        if rc not in (0,-7):raise RuntimeError(('IN failed',rc))
                        if (rc==0 and received.value<64) or (rc==-7 and not received.value):break
                    if len(response)>=65536:raise RuntimeError('reply byte limit')
                finally:
                    phase['received_hex']=bytes(response[offset:]).hex()
                    phase['received_bytes']=len(response)-offset
                if not phase['reads']:
                    raise RuntimeError('phase did not perform a bounded IN')
                end=bool(re.search(rb'(?:\A|\n)E'+nonce.encode()+rb'\n',response))
                quiet=quiet+1 if end and phase['received_bytes']==0 else 0
                if quiet==2:
                    raw=bytes(response)
                    if memory is not None:
                        _,proof=extract_addressed_reply(raw,nonce,*memory)
                        report['address_proof']=proof
                    elif kind=='reset_info_native':
                        from reset_info import parse_reply
                        report['reset_info_proof']=parse_reply(raw,nonce)
                    else:
                        tag,separator=(('F','_') if kind=='fw_info_tagged' else
                                       (('P',' ') if kind=='lcd_pointer_tagged' else ('R','_')))
                        extract_tagged_value(raw,nonce,tag,separator)
                    report['stream_closed']=True;self.stream_closed=True
                    break
            if not self.stream_closed:raise RuntimeError('fresh end and two quiet phases not proven')
            return report
        except BaseException as error:
            report['error']=str(error);self.poisoned=True;raise
        finally:
            report['received_base64']=base64.b64encode(response).decode()
            report['ended_utc']=dt.datetime.now(dt.timezone.utc).isoformat()

    def close(self):
        if self.closed:return
        self.closed=True
        if not self.handle:
            self.cleanup.update(handle_closed=True,kernel_verified=not self.claimed)
        if self.handle:
            if self.claimed:
                if self.alt_attempted:
                    try:
                        rc=self.alternate(self.handle,0,self.previous)
                        self.cleanup['restore_alt_rc']=rc
                        self.controls.append({'operation':'SET_INTERFACE','alternate':self.previous,'rc':rc})
                    except Exception as e:self.cleanup['restore_error']=str(e)
                if self.previous is not None:
                    try:self.cleanup['alt_verified']=self.read_alt()==self.previous
                    except Exception as e:self.cleanup['alt_error']=str(e)
                try:self.cleanup['release_rc']=self.release(self.handle,0)
                except Exception as e:self.cleanup['release_error']=str(e)
            try:self.cleanup['kernel_verified']=self.active(self.handle,0)==0
            except Exception as e:self.cleanup['kernel_error']=str(e)
            try:self.close_handle(self.handle);self.cleanup['handle_closed']=True
            except Exception as e:self.cleanup['close_error']=str(e)
        if self.initialized:
            try:self.leave(self.ctx);self.cleanup['context_closed']=True
            except Exception as e:self.cleanup['context_error']=str(e)
        else:self.cleanup['context_closed']=True
        self.cleanup_verified=(self.cleanup.get('handle_closed') is True
            and self.cleanup.get('context_closed') is True
            and self.cleanup.get('kernel_verified') is True
            and (not self.claimed or (self.cleanup.get('alt_verified') is True
                and self.cleanup.get('release_rc')==0))
            and self.cleanup.get('restore_alt_rc',0)==0
            and not any(k.endswith('_error') for k in self.cleanup))

    def __exit__(self,*args):self.close()
