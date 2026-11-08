"""Local read-only collection with one USB claim for the whole collection.

Whole-session hardware cleanup and per-query framing are recorded separately.
The ordinary on-demand client and its 73-query monitor remain separate modes.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time

from access_lock import usb_lock
from batch_usb import ReadSession
from device_guard import DeviceGuard,guard_path
from designjet_readonly import Client,STATUS_KINDS,HEAD_KINDS,DIAGNOSTIC_KINDS,SERIAL,PrintPriority
from local_config import configuration,capture_directory
from storage import atomic_json
import status_snapshot as support
from trace_sequential_echo import idle_adapter,PreflightError
from capture_usblp_readonly import address_of

ROOT=Path(__file__).resolve().parents[1]


class USBTrace:
    def __init__(self,bus,device,cutoff):
        self.bus=bus;self.device=device;self.cutoff=cutoff
        self.was_loaded=Path('/sys/module/usbmon').exists();self.loaded=False
        self.stop=threading.Event();self.ready=threading.Event()
        self.data=bytearray();self.errors=[];self.thread=None
    def collect(self):
        fd=None
        try:
            fd=os.open('/sys/kernel/debug/usb/usbmon/%du'%self.bus,os.O_RDONLY|os.O_NONBLOCK)
            self.ready.set()
            end=min(time.monotonic()+1200,time.monotonic()+max(0,(self.cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds())+10)
            while not self.stop.is_set() and time.monotonic()<end:
                if len(self.data)>=2*1024*1024:raise RuntimeError('whole-session trace byte limit')
                if select.select([fd],[],[],.1)[0]:
                    try:data=os.read(fd,min(4096,2*1024*1024-len(self.data)))
                    except BlockingIOError:continue
                    if not data:raise RuntimeError('USB trace ended before collection closed')
                    self.data.extend(data)
            if not self.stop.is_set():raise RuntimeError('whole-session trace timed out')
        except Exception as error:self.errors.append(str(error));self.ready.set()
        finally:
            if fd is not None:os.close(fd)
    def start(self):
        if not self.was_loaded:
            p=subprocess.run(['modprobe','usbmon'],capture_output=True,text=True,timeout=5)
            self.loaded=Path('/sys/module/usbmon').exists()
            if p.returncode or not self.loaded:raise RuntimeError('usbmon unavailable')
        self.thread=threading.Thread(target=self.collect,name='batch-read-usbmon')
        self.thread.start()
        if not self.ready.wait(2) or self.errors:raise RuntimeError('USB trace was not ready')
    def close(self):
        time.sleep(.1)  # Let the trace reader consume the final restoration URBs.
        self.stop.set()
        if self.thread:
            try:self.thread.join(2)
            except RuntimeError as error:self.errors.append(str(error))
        if self.loaded:
            try:
                p=subprocess.run(['modprobe','-r','usbmon'],capture_output=True,text=True,timeout=5)
                if p.returncode:self.errors.append('own usbmon module did not unload')
            except Exception as error:self.errors.append(str(error))
        rows=[]
        for line in self.data.decode('ascii','backslashreplace').splitlines():
            address=address_of(line)
            if address and address[2:4]==(self.bus,self.device):rows.append(line)
        return {'text':'\n'.join(rows),'reader_closed':not self.thread or not self.thread.is_alive(),
                'module_loaded_before':self.was_loaded,
                'module_loaded_after':Path('/sys/module/usbmon').exists(),'errors':self.errors}


def check_queue(snapshot,own_pid=None):
    cups=snapshot['cups'];jobs=cups['unfinished_job_ids']
    if isinstance(jobs,list) and jobs:raise PrintPriority('CUPS job has priority')
    if (jobs!=[] or cups['queue_command']['rc'] or cups['queue_command']['out'].strip()
            or cups['usb_backend_pids']
            or cups['attributes'].get('printer-state',{}).get('raw_value')!='idle'):
        raise PreflightError('queue cannot be confirmed empty')
    handles=snapshot['usb_handles']
    if not handles['inspection_complete'] or any(x['pid']!=own_pid for x in handles['open_handles']):
        raise PreflightError('USB ownership cannot be confirmed')


def restored(before,after,transport,trace):
    if transport and not transport.cleanup_verified:return False
    if (not trace.get('reader_closed')
            or trace.get('module_loaded_before')!=trace.get('module_loaded_after')):return False
    if after.get('snapshot_error'):return False
    if (not after['usb_handles']['inspection_complete'] or after['usb_handles']['open_handles']):return False
    return (before['machine_id']==after['machine_id']
        and before['btt_boot']['boot_id']==after['btt_boot']['boot_id']
        and len(before['adapters'])==len(after['adapters'])==1
        and all(before['adapters'][0].get(k)==after['adapters'][0].get(k) for k in
                ('path','alternate','driver','descriptor_sha256','busnum','devnum')))


def check_active(snapshot,before,own_pid):
    check_queue(snapshot,own_pid)
    found=snapshot['adapters'];expected=before['adapters'][0]
    # Linux devio.c claims through usbfs_driver. Idle is unbound/alt0;
    # our exclusively claimed interface is usbfs/alt1 until final cleanup.
    if (len(found)!=1 or found[0]['alternate']!=1
            or found[0]['driver']!='/sys/bus/usb/drivers/usbfs'
            or any(found[0].get(k)!=expected.get(k) for k in
                   ('path','descriptor_sha256','busnum','devnum'))
            or snapshot['machine_id']!=before['machine_id']
            or snapshot['btt_boot']['boot_id']!=before['btt_boot']['boot_id']):
        raise PreflightError('active session identity or binding changed')


class BatchClient(Client):
    def __init__(self,cutoff,mode,passes,session,before_query):
        super().__init__(cutoff,mode,passes)
        self.session=session;self.before_query=before_query
        self.state['transport_mode']='one_claim_per_collection'
    def query(self,kind,memory=None):
        self.before_query()
        index=len(self.session.queries)
        try:item=self.session.query(kind,memory)
        finally:
            if len(self.session.queries)>index:
                item=self.session.queries[-1]
                path=self.folder/(self.target.stem+'-query-%03d.json'%(index+1))
                atomic_json(path,item)
                metadata={'kind':kind,'memory':memory,'source':str(path),'observed_utc':item['observed_utc']}
                if item['stream_closed']:self.state['queries'].append(metadata)
                else:self.state['failed_query']=metadata
                self.checkpoint()
        return {'nonce':item['nonce'],'transport':item}


def read_content(client,mode,include_diagnostics=False):
    client.identify()
    if mode=='journal':
        from error_journal import read_journal
        read_journal(client)
    if mode=='head-journal':
        from head_journal import read_history
        read_history(client)
    if mode=='all':
        descriptor,header,pointer=client.locate()
        frames=[client.capture(i+1,descriptor,header,pointer) for i in range(2)]
        client.state['screen_passes_identical']=frames[0]==frames[1]
        if frames[0]!=frames[1]:raise RuntimeError('LCD differs between complete passes')
        client.include_other_phase(descriptor)
        client.status(STATUS_KINDS+HEAD_KINDS)
    if mode=='diagnostics' or include_diagnostics:
        client.status(DIAGNOSTIC_KINDS)
        client.state['diagnostics_included']=True
    if client.value('telemetry_serial')!=SERIAL:raise RuntimeError('final printer identity differs')
    client.state['complete']=True


def collect(cutoff,mode='all',include_diagnostics=False,refresh_id_each_query=False,comment_bytes=64):
    if mode not in ('all','diagnostics','journal','head-journal'):raise ValueError('only fixed read plans exist')
    if type(comment_bytes) is not int or comment_bytes not in (63,64):raise ValueError('comment length must be 63 or 64')
    if cutoff.tzinfo is None or (cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<90:
        raise ValueError('allow 90 seconds for query and cleanup')
    config=configuration()
    if config['executor']!='local' or config['idle_driver']!='none' or config['small_query_bytes']!=129:
        raise RuntimeError('batch reads require the explicit local none/alt0/129 profile')
    if os.geteuid()!=0:raise RuntimeError('local device ownership inspection requires root')
    for key,value in (('MACHINE_ID',config['machine_id']),('ADAPTER_DESCRIPTOR_SHA256',config['adapter_descriptor_sha256']),
                      ('QUEUE',config['queue']),('URI','ipp://localhost:631/printers/'+config['queue']),
                      ('IDLE_DRIVER',None),('IDLE_ALTERNATE',0)):
        setattr(support,key,value)
    client=None;session=None;trace=None;report={};trace_result={};error=None
    with usb_lock(config['lock_file']):
        before=support.snapshot(class_read=False);check_queue(before)
        adapter=idle_adapter(before['adapters'],support.__dict__)
        bus,address=int(adapter['busnum']),int(adapter['devnum'])
        with DeviceGuard(str(guard_path(config)),'batch:'+mode) as lease:
            was_loaded=Path('/sys/module/usbmon').exists()
            try:
                report={'preflight':before,'source_sha256':{},'mode':mode,
                        'include_diagnostics':include_diagnostics,'print_jobs_created':False,
                        'refresh_id_each_query':refresh_id_each_query}
                report['comment_bytes']=comment_bytes
                for folder in (ROOT/'service',ROOT/'firmware'):
                    for path in folder.glob('*.py'):
                        report['source_sha256'][str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
                trace=USBTrace(bus,address,cutoff);trace.start()
                session=ReadSession(bus,address,cutoff,refresh_id_each_query=refresh_id_each_query,comment_bytes=comment_bytes)
                def before_query():
                    if trace.errors:raise RuntimeError('USB trace stopped during collection')
                    check_active(support.snapshot(class_read=False),before,os.getpid())
                with session:
                    client=BatchClient(cutoff,mode,2,session,before_query)
                    client.state['refresh_id_each_query']=refresh_id_each_query
                    client.state['comment_bytes']=comment_bytes
                    read_content(client,mode,include_diagnostics)
            except BaseException as caught:
                error=caught;report['error']=str(caught)
                if client:client.state['error']=str(caught)
            finally:
                if session:session.close()
                if trace:trace_result=trace.close()
                if trace is None:
                    trace_result={'reader_closed':True,'module_loaded_before':was_loaded,
                                  'module_loaded_after':Path('/sys/module/usbmon').exists(),'errors':[]}
                try:after=support.snapshot(class_read=False)
                except Exception as caught:after={'snapshot_error':str(caught)}
                clean=restored(before,after,session,trace_result)
                report.update(postflight=after,trace=trace_result,
                    hardware_cleanup_verified=clean,
                    all_query_streams_closed=not session or session.stream_closed,
                    controls=session.controls if session else [],
                    transport_cleanup=session.cleanup if session else {},
                    queries=session.queries if session else [])
                if clean and (not session or session.stream_closed):lease.clear()
                report['device_guard_cleared']=lease.cleared
                if client:
                    client.state['elapsed_seconds']=round(time.monotonic()-client.started,3)
                    client.state['hardware_cleanup_verified']=clean
                    client.state['device_guard_cleared']=lease.cleared
                    if not clean or not lease.cleared or trace_result.get('errors'):
                        client.state['complete']=False
                    client.checkpoint()
                    path=client.target.with_name(client.target.stem+'-batch.json')
                    report['session']=str(client.target);atomic_json(path,report)
                    client.state['batch_report']=str(path);client.checkpoint()
                else:
                    folder=capture_directory(config);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
                    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                    atomic_json(folder/('batch-refused-'+stamp+'.json'),report)
    if error:
        if client:setattr(error,'client',client)
        raise error
    if not client or not client.state['complete']:
        error=RuntimeError('batch read was not accepted')
        if client:setattr(error,'client',client)
        raise error
    return client


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('diagnostics','all','journal','head-journal'))
    parser.add_argument('--include-diagnostics',action='store_true')
    parser.add_argument('--refresh-id',action='store_true',help='refresh class device ID before every query')
    parser.add_argument('--short-comment',action='store_true',help='separate experimental 63-byte COMMENT profile')
    parser.add_argument('--until-utc',required=True)
    args=parser.parse_args()
    client=collect(dt.datetime.fromisoformat(args.until_utc),args.mode,args.include_diagnostics,args.refresh_id,63 if args.short_comment else 64)
    print(json.dumps({'session':str(client.target),'batch':client.state['batch_report'],
                      'complete':client.state['complete'],'queries':len(client.state['queries']),
                      'fields':len(client.state['status']),'seconds':client.state['elapsed_seconds']}),flush=True)


if __name__=='__main__':main()
