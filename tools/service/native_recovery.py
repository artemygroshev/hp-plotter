"""One native A.04.02 recovery preset, with bounded transport and no replay.

Level zero services all four heads. This is separate from the normal IQ
troubleshooting dialogue and does not prove that ink delivery has recovered.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from access_lock import usb_lock
from batch_read import USBTrace, BatchClient, check_queue, check_active, restored
from batch_usb import ReadSession
from device_guard import DeviceGuard, guard_path
from framebuffer_memory import extract_tagged_value
from local_config import configuration, capture_directory
from panel_keys import KeySession
from storage import atomic_json
from trace_sequential_echo import idle_adapter
import probe_printer as probe
import status_snapshot as support

RECOVERY_PROOFS = (
    ('Tcl_native_recovery_wrapper', 0xa026a884, 108,
     '42a40222a3e921e2e4684485b5ee29087cd0f02c149dbf36d72526c15d8b3da3'),
    ('native_recovery_bridge', 0xa0279a78, 20,
     '1c0758984d80e759541f1af1d0fd234b86b5ba22105ed67791af0b4e89afd955'),
    ('recovery_mutex_level_dispatch', 0xa023e9e0, 304,
     '0ef789ecd6e263afdfd6fefe0b98651f241332242a7890dfc20d99c543599373'),
    ('lowest_recovery_preset', 0xa023e81c, 124,
     'e35e916a240bac8492644bebe0da3e6adc28d800a9bcfd64c9ba2ed266b4f25c'),
)


def recovery_payload(nonce):
    if not re.fullmatch(r'[a-f0-9]{6}',nonce):
        raise ValueError('require a fresh six-hex nonce')
    script=('puts S'+nonce+'\nflush stdout\n'
            'puts R'+nonce+'_[catch {svsOnIntervention_set 0}]\n'
            'puts E'+nonce+'\nexit\n').encode('ascii')
    prefix=probe.UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail=b'\n'+probe.UEL+b'\r\n'
    padding=257-len(prefix)-len(tail)
    if padding<1:raise ValueError('recovery frame exceeds reviewed size')
    return prefix+b'#'+b' '*(padding-1)+tail


def returned_close_payload():
    prefix=probe.UEL+b'@PJL\r\n@PJL EOJ\r\n@PJL COMMENT CLOSE_READ'
    tail=b'\r\n'+probe.UEL+b'\r\n'
    padding=63-len(prefix)-len(tail)
    if padding<0:raise ValueError('returned-call close frame exceeds 63 bytes')
    return prefix+b' '*padding+tail


def parse_recovery_reply(raw,nonce,closed_by_eoj=False):
    if not re.fullmatch(r'[a-f0-9]{6}',nonce):raise ValueError('invalid nonce')
    start=b'S'+nonce.encode()+b'\n'
    if not raw.startswith(start) or raw.count(start)!=1:
        raise ValueError('fresh recovery start marker required')
    original_end=raw.endswith(b'E'+nonce.encode()+b'\n')
    if closed_by_eoj and raw==start+b'R'+nonce.encode()+b'_0\n':
        pass
    elif extract_tagged_value(raw[len(start):],nonce,'R','_')!='0':
        raise ValueError('native recovery did not return success')
    return {'fresh_start_and_return_verified':True,'native_function_returned':True,
            'level':0,'head_mask':15,'automatic_retry':False,
            'original_final_marker_verified':original_end,
            'explicit_EOJ_closure_verified':bool(closed_by_eoj),
            'physical_ink_restoration_proven':False}


class RecoverySession(KeySession):
    recovery_nonce=None
    return_clock_scheduled=False
    def command_payload(self,kind,nonce,memory=None):
        if kind!='normal_recovery':return super().command_payload(kind,nonce,memory)
        if memory is not None:raise ValueError('recovery has no memory arguments')
        if self.recovery_nonce is not None:raise RuntimeError('one recovery call per session; no replay')
        self.recovery_nonce=nonce
        return recovery_payload(nonce)

    def phase_limit(self,kind):
        return 240 if kind=='normal_recovery' else super().phase_limit(kind)

    def drain_payload(self,kind,response=b''):
        if kind!='normal_recovery':return super().drain_payload(kind,response)
        # The tested native call stopped consuming OUT while it ran: even Tcl
        # ticks filled the forward path. Wait on IN only after the one command.
        # Close the old job only after its exact return marker. The original
        # end marker may be missing; an explicit EOJ and two quiet reads are
        # then a separate closure proof, followed by fresh identity/status.
        if self.recovery_nonce and not self.return_clock_scheduled:
            nonce=self.recovery_nonce.encode('ascii')
            if response==b'S'+nonce+b'\nR'+nonce+b'_0\n':
                self.return_clock_scheduled=True
                return returned_close_payload()
        return None

    def returned_close_written(self,report):
        return any(p.get('payload_hex')==returned_close_payload().hex()
                   and p.get('write_rc')==0 and p.get('written_bytes')==63
                   for p in report['phases'])

    def reply_end_seen(self,kind,nonce,response,report):
        if (kind=='normal_recovery' and self.returned_close_written(report)
                and response==b'S'+nonce.encode()+b'\nR'+nonce.encode()+b'_0\n'):
            return True
        return super().reply_end_seen(kind,nonce,response,report)

    def validate_reply(self,kind,nonce,raw,memory,report):
        if kind!='normal_recovery':return super().validate_reply(kind,nonce,raw,memory,report)
        report['recovery_reply_proof']=parse_recovery_reply(
            raw,nonce,closed_by_eoj=self.returned_close_written(report))


def require_compatible_session():
    needed={'command_payload','validate_reply','phase_limit','drain_payload','reply_end_seen'}
    if not needed.issubset(ReadSession.query.__code__.co_names):
        raise RuntimeError('native recovery requires matching batch_usb.py interfaces')


STATUS_KINDS=('telemetry_diag_peripheral_blocking','telemetry_diag_mechanical',
              'telemetry_diag_writing_system','telemetry_diag_pdl',
              'telemetry_diag_spooler','telemetry_diag_cover_open',
              'telemetry_diag_busy','telemetry_diag_printing')


def check_status(client,kinds):
    values={kind:client.value(kind) for kind in kinds}
    for kind,value in values.items():
        # PRINTING is a raw multi-value field; 2 alone does not demonstrate
        # physical activity. Busy, blocking faults, ownership and cover are
        # checked independently. No bool conversion is applied to these enums.
        allowed=('0','2') if kind=='telemetry_diag_printing' else ('0',)
        if value not in allowed:raise RuntimeError('HP prerequisite failed: '+kind+'='+value)
    return values


def recover(cutoff):
    require_compatible_session()
    remaining=(cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds() if cutoff.tzinfo else 0
    if not 720<=remaining<=1800:
        raise ValueError('require a bounded 720..1800 second operation window')
    config=configuration()
    if (os.geteuid()!=0 or config['executor']!='local' or config['idle_driver']!='none'
            or config['small_query_bytes']!=129):
        raise RuntimeError('require the configured local root none/alt0/129 profile')
    for name,value in (('MACHINE_ID',config['machine_id']),
                       ('ADAPTER_DESCRIPTOR_SHA256',config['adapter_descriptor_sha256']),
                       ('QUEUE',config['queue']),('URI','ipp://localhost:631/printers/'+config['queue']),
                       ('IDLE_DRIVER',None),('IDLE_ALTERNATE',0)):
        setattr(support,name,value)
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target=capture_directory(config)/('native-recovery-'+stamp+'.json')
    report={'native_command':'svsOnIntervention_set 0','head_mask':15,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'automatic_retry':False,'recovery_attempted':0,'recovery_acknowledged':0,
            'normal_IQ_UI_accounting_bypassed':True,'physical_result_confirmed':False,
            'print_jobs_created':False,'complete':False}
    session=trace=client=None
    unverified=False
    with usb_lock(config['lock_file']):
        before=support.snapshot(class_read=False);check_queue(before)
        adapter=idle_adapter(before['adapters'],support.__dict__)
        with DeviceGuard(str(guard_path(config)),'normal-native-recovery-level0') as lease:
            was_loaded=Path('/sys/module/usbmon').exists()
            try:
                report['preflight']=before
                trace=USBTrace(int(adapter['busnum']),int(adapter['devnum']),cutoff);trace.start()
                session=RecoverySession(int(adapter['busnum']),int(adapter['devnum']),cutoff,
                                        key='ENTER',refresh_id_each_query=True,comment_bytes=63)
                def prior():
                    if trace.errors:raise RuntimeError('USB trace stopped')
                    check_active(support.snapshot(class_read=False),before,os.getpid())
                with session:
                    client=BatchClient(cutoff,'native-recovery',1,session,prior);client.identify()
                    for name,address,length,digest in RECOVERY_PROOFS:
                        data=b''.join(client.memory(address+offset,min(128,length-offset))
                                      for offset in range(0,length,128))
                        if hashlib.sha256(data).hexdigest()!=digest:
                            raise RuntimeError('live native recovery code differs: '+name)
                    context,=struct.unpack('>I',client.memory(0xa03ad59c,4))
                    if context%4 or not 0xa044d000<=context<0xa1000000:
                        raise RuntimeError('native servicing context unavailable')
                    report['servicing_context']=hex(context)
                    report['status_before']=check_status(client,STATUS_KINDS)
                    ink=client.value('telemetry_ink_out');report['ink_status_raw']=ink
                    if ink not in ('0','3'):
                        raise RuntimeError('ink state outside observed nonblocking profile')
                    check_status(client,('telemetry_diag_cover_open','telemetry_diag_busy'))
                    report.update(recovery_attempted=1,phase='native_recovery_attempt_started')
                    unverified=True;atomic_json(target,report)
                    reply=client.query('normal_recovery')
                    report.update(recovery_acknowledged=1,phase='native_recovery_returned',
                                  native_reply_proof=reply['transport']['recovery_reply_proof'])
                    atomic_json(target,report)
                    report['status_after']=check_status(client,STATUS_KINDS)
                    client.identify()
                    unverified=False;report.update(complete=True,phase='closed_and_idle_verified')
            except BaseException as error:
                report['error']=str(error)
            finally:
                if session:session.close()
                tr=trace.close() if trace else {'reader_closed':True,
                    'module_loaded_before':was_loaded,
                    'module_loaded_after':Path('/sys/module/usbmon').exists(),'errors':[]}
                after=support.snapshot(class_read=False)
                clean=restored(before,after,session,tr)
                if clean and (session is None or session.stream_closed) and not unverified:
                    lease.clear()
                report.update(postflight=after,trace=tr,hardware_cleanup_verified=clean,
                    device_guard_cleared=lease.cleared,
                    queries=session.queries if session else [],controls=session.controls if session else [],
                    transport_cleanup=session.cleanup if session else {},
                    complete=report['complete'] and clean and lease.cleared)
                atomic_json(target,report)
    return target,report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-level0',action='store_true',required=True,
                        help='send one normal preset to all four heads')
    parser.add_argument('--until-utc',required=True)
    args=parser.parse_args()
    target,report=recover(dt.datetime.fromisoformat(args.until_utc))
    print(json.dumps({'evidence':str(target),'complete':report['complete'],
                      'recovery_attempted':report['recovery_attempted'],
                      'native_function_returned':report['recovery_acknowledged']==1,
                      'physical_result_confirmed':False,'error':report.get('error')}))
    return 0 if report['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
