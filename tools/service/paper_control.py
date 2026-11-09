"""Explicit, bounded A.04.02 paper-profile control through the shared USB lock.

This is a device operation, distinct from CUPS media options. Read is the
default. A write needs --set, an idle HP, vendor HP, a recognized previous
profile and a fresh read-back. There are no print, load, cut or reset commands.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re

from access_lock import usb_lock
from batch_read import USBTrace, check_queue, check_active, restored
from batch_usb import ReadSession
from device_guard import DeviceGuard, guard_path
from framebuffer_memory import extract_tagged_value
from local_config import configuration, capture_directory
from storage import atomic_json
from trace_sequential_echo import idle_adapter
import status_snapshot as support
import probe_printer as probe

PAPERS = {'plain': 'Plain Paper', 'coated': 'Coated', 'heavy-coated': 'Heavy Coated'}
KNOWN_PREVIOUS = frozenset(('Bright White Inkjet', 'Bright White Inkjet 2',
    'Plain Paper', 'Plain Paper 2', 'Vellum', 'Vellum 2', 'Natural Tracing',
    'Natural Tracing 2', 'Translucent', 'Translucent 2', 'Matte Film', 'Matte Film 2',
    'Clear Film', 'Clear Film 2', 'Coated', 'Coated 2', 'Heavy Coated',
    'Heavy Coated 2', 'Glossy Photo', 'Glossy Photo 2', 'Satin Poster Paper',
    'Studio Canvas', 'Studio Canvas 2'))
MEDIA_SET = 'paper_profile_set'
MEDIA_VENDOR = 'paper_vendor_read'
PAPER_PRESENT = 'paper_present_read'
PAPER_TRAY = 'paper_tray_read'
READ_COMMANDS = {MEDIA_VENDOR:'sysODBGet FP-MEDIA-VENDOR s',
                 PAPER_PRESENT:'sysODBGet MEDIA-INPUT-PRESENT b',
                 PAPER_TRAY:'sysODBGet MEDIA-INPUT-TRAY u'}


def fixed_payload(kind,nonce,paper=None):
    if not re.fullmatch(r'[a-f0-9]{6}',nonce):
        raise ValueError('invalid paper request nonce')
    if kind in READ_COMMANDS:
        if paper is not None:raise ValueError('read has no paper argument')
        command = READ_COMMANDS[kind]
    elif kind == MEDIA_SET:
        if paper not in PAPERS:raise ValueError('unknown paper profile')
        command = 'sysODBSet FP-MEDIA-NAME {'+PAPERS[paper]+'} s'
    else:
        raise ValueError('unknown paper operation')
    # The bounded stream parser accepts the fresh R/E pair without a B line.
    # Keeping that pair makes all three fixed setters fit the 129-byte profile.
    script=('puts R'+nonce+'_['+command+']\nputs E'+nonce+'\nexit\n').encode('ascii')
    prefix=probe.UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail=b'\n'+probe.UEL+b'\r\n'
    padding=129-len(prefix)-len(tail)
    if padding<0:raise ValueError('paper command exceeds bounded frame')
    return prefix+(b'#'+b' '*(padding-1) if padding else b'')+tail


class PaperSession(ReadSession):
    def __init__(self,*args,paper=None,**kwargs):
        if paper is not None and paper not in PAPERS:raise ValueError('unknown paper profile')
        self.paper=paper
        super().__init__(*args,**kwargs)

    def command_payload(self,kind,nonce,memory=None):
        if kind==MEDIA_SET or kind in READ_COMMANDS:
            if memory is not None:raise ValueError('paper operation has no memory arguments')
            return fixed_payload(kind,nonce,self.paper if kind==MEDIA_SET else None)
        return super().command_payload(kind,nonce,memory)


def perform(query,serial,paper=None):
    """Perform a fixed plan; query returns strictly parsed fresh scalar values."""
    if paper is not None and paper not in PAPERS:raise ValueError('unknown paper profile')
    if query('fw_info_tagged')!='A.04.02':raise RuntimeError('unreviewed HP firmware')
    if query('telemetry_serial')!=serial:raise RuntimeError('printer serial differs')
    vendor=query(MEDIA_VENDOR)
    previous=query('telemetry_media')
    present=query(PAPER_PRESENT)
    tray=query(PAPER_TRAY)
    # Sample activity last, immediately before deciding whether to write.
    busy=query('telemetry_diag_busy')
    printing=query('telemetry_diag_printing')
    result={'firmware':'A.04.02','vendor':vendor,'before':previous,'after':previous,
            'busy_raw':busy,'printing_raw':printing,'paper_present_raw':present,
            'paper_tray_raw':tray,'requested':PAPERS.get(paper),
            'write_attempted':False,'changed':False,'verified':False}
    if paper is not None:
        if busy!='0' or printing!='0':raise RuntimeError('HP is busy or printing; paper unchanged')
        if present!='1' or tray!='0':raise RuntimeError('require loaded roll paper before changing its profile')
        if vendor!='HP':raise RuntimeError('only the reviewed HP media catalogue is supported')
        if previous not in KNOWN_PREVIOUS:
            raise RuntimeError('previous paper is outside the reviewed profile set')
        if previous!=PAPERS[paper]:
            result['write_attempted']=True
            rc=query(MEDIA_SET)
            if rc!='0':raise RuntimeError('HP rejected the paper setting; no automatic retry')
            after=query('telemetry_media')
            result['after']=after
            if after!=PAPERS[paper]:raise RuntimeError('paper read-back differs; inspect HP before repeating')
            if query(MEDIA_VENDOR)!=vendor:raise RuntimeError('paper vendor changed unexpectedly')
            result['changed']=True
        result['verified']=True
    if query('telemetry_serial')!=serial:raise RuntimeError('final printer serial differs')
    return result


def control(cutoff,paper=None):
    if paper is not None and paper not in PAPERS:raise ValueError('unknown paper profile')
    if cutoff.tzinfo is None or not 90<=(cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<=900:
        raise ValueError('allow a bounded 90..900 second operation window')
    config=configuration()
    if (os.geteuid()!=0 or config['executor']!='local' or config['idle_driver']!='none'
            or config['small_query_bytes']!=129):
        raise RuntimeError('paper control requires the pinned local root none/alt0/129 profile')
    for key,value in (('MACHINE_ID',config['machine_id']),('ADAPTER_DESCRIPTOR_SHA256',config['adapter_descriptor_sha256']),
                      ('QUEUE',config['queue']),('URI','ipp://localhost:631/printers/'+config['queue']),
                      ('IDLE_DRIVER',None),('IDLE_ALTERNATE',0)):
        setattr(support,key,value)
    folder=capture_directory(config)
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target=folder/('paper-control-'+stamp+'.json')
    report={'operation':'set' if paper else 'read','requested':paper,'complete':False,
            'print_jobs_created':False,'automatic_retry':False,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    error=None;session=None;trace=None;trace_result={};plan_complete=False
    with usb_lock(config['lock_file']):
        before=support.snapshot(class_read=False);check_queue(before)
        adapter=idle_adapter(before['adapters'],support.__dict__)
        with DeviceGuard(str(guard_path(config)),'paper:'+str(paper or 'read')) as lease:
            was_loaded=Path('/sys/module/usbmon').exists()
            try:
                report['preflight']=before
                trace=USBTrace(int(adapter['busnum']),int(adapter['devnum']),cutoff);trace.start()
                session=PaperSession(int(adapter['busnum']),int(adapter['devnum']),cutoff,
                                     paper=paper,refresh_id_each_query=True,comment_bytes=63)
                with session:
                    def query(kind):
                        if trace.errors:raise RuntimeError('USB trace stopped')
                        check_active(support.snapshot(class_read=False),before,os.getpid())
                        value=session.query(kind)
                        tag='F' if kind=='fw_info_tagged' else 'R'
                        return extract_tagged_value(base64.b64decode(value['received_base64']),value['nonce'],tag,'_')
                    report['result']=perform(query,config['printer_serial'],paper)
                    plan_complete=True
            except BaseException as caught:
                error=caught;report['error']=str(caught)
            finally:
                if session:session.close()
                if trace:trace_result=trace.close()
                if trace is None:
                    trace_result={'reader_closed':True,'module_loaded_before':was_loaded,
                                  'module_loaded_after':Path('/sys/module/usbmon').exists(),'errors':[]}
                try:after=support.snapshot(class_read=False)
                except Exception as caught:after={'snapshot_error':str(caught)}
                clean=restored(before,after,session,trace_result)
                closed=not session or session.stream_closed
                writes=[q for q in (session.queries if session else []) if q['kind']==MEDIA_SET]
                # A completed response alone does not prove the requested profile.
                # An unverified write keeps the durable marker even with clean USB.
                if clean and closed and (not writes or plan_complete):lease.clear()
                report.update(postflight=after,trace=trace_result,hardware_cleanup_verified=clean,
                    all_query_streams_closed=closed,device_guard_cleared=lease.cleared,
                    controls=session.controls if session else [],
                    queries=session.queries if session else [],transport_cleanup=session.cleanup if session else {},
                    complete=plan_complete and clean and closed and lease.cleared)
                atomic_json(target,report)
    if error:raise RuntimeError(str(error)+'; evidence: '+str(target)) from error
    if not report['complete']:raise RuntimeError('paper operation not accepted; evidence: '+str(target))
    return {'evidence':str(target),**report['result'],'complete':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--set',choices=tuple(PAPERS),dest='paper')
    parser.add_argument('--until-utc',required=True)
    args=parser.parse_args()
    print(json.dumps(control(dt.datetime.fromisoformat(args.until_utc),args.paper),ensure_ascii=False))


if __name__=='__main__':main()
