"""On-demand, read-only DesignJet 500 LCD and status through the recorded BTT.

Discovers the bitmap address on every run. Requires the current authorized
deadline; never starts a daemon or installs anything on the BTT/printer.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import time

from run_service_read import execute, ROOT, PROJECT
from framebuffer_memory import extract_addressed_reply, extract_tagged_value, native_png
from storage import atomic_json
from local_config import configuration, capture_directory

_CONFIG = configuration(required=False)
SERIAL = _CONFIG['printer_serial']
MACHINE_ID = _CONFIG['machine_id']
GETTER_ADDRESS = 0xa017d468
GETTER_LENGTH = 96
GETTER_SHA256 = '0c8fc4be733ef9accb4911bfb6ce5466656aca2ebfff1d7484084dfdd6492538'
STATUS_KINDS = ('telemetry_part','telemetry_model','telemetry_error','telemetry_ram',
                'telemetry_media','telemetry_ink_out')+tuple(
                    'telemetry_%s_%d'%(name,index) for index in range(4)
                    for name in ('head','color','cartridge','level'))
HEAD_KINDS = tuple('telemetry_head_%s_%d'%(name,index) for index in range(4)
                   for name in ('native','model'))
DIAGNOSTIC_KINDS = tuple('telemetry_diag_'+name for name in (
    'peripheral_blocking','peripheral_nonblocking','mechanical','media',
    'writing_system','writing_system_nonblocking','pdl','spooler','rmc',
    'intervention','cover_open','paper_jam','busy','printing'))


class PrintPriority(RuntimeError):
    """The queue owns the next transaction; the read left USB restored."""


def checked_pointer(value, span=12):
    raw = int(value)
    if not -(1 << 31) <= raw < (1 << 32):
        raise ValueError('pointer is not a 32-bit value')
    pointer = raw & 0xffffffff
    if pointer % 4 or pointer < 0xa044d000 or pointer+span > 0xa1000000:
        raise ValueError('pointer is outside the bounded engine heap RAM window')
    return pointer


def bitmap_header(data):
    if len(data) != 12:
        raise ValueError('bitmap descriptor is incomplete')
    width,height,pointer = struct.unpack('>III',data)
    if (width,height) != (128,64):
        raise ValueError('this client only handles the verified 128x64 LCD layout')
    return checked_pointer(pointer,1024)


def display_metadata(data):
    if len(data)!=18:
        raise ValueError('display phase metadata is incomplete')
    first,second,count,flash,pad,index=struct.unpack('>IIIBBI',data)
    if count!=2 or flash not in (0,1) or index>=count:
        raise ValueError('display phase metadata differs from the verified A04 layout')
    return {'pointers':[checked_pointer(first),checked_pointer(second)],
            'count':count,'flashing_enabled':bool(flash),'sampled_active_index':index}


class Client:
    def __init__(self, cutoff, mode, passes):
        self.cutoff = cutoff
        self.started = time.monotonic()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        self.folder = capture_directory(_CONFIG)/('panel-live-'+stamp[:8])
        self.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.target = self.folder/('readonly-session-'+stamp+'.json')
        self.state = {'mode':mode,'requested_passes':passes,'complete':False,
                      'print_jobs_created':False,'persistent_device_changes':False,
                      'atomic_snapshot_claimed':False,'queries':[],'status':{},'screens':[]}

    def checkpoint(self):
        atomic_json(self.target,self.state)

    def query(self, kind, memory=None):
        if (self.cutoff-datetime.datetime.now(datetime.timezone.utc)).total_seconds() < 90:
            raise RuntimeError('not enough authorized time for another bounded query and cleanup')
        path,report,_ = execute(kind,memory=memory,print_summary=False,finish_on_short=True,
                                deadline_utc=self.cutoff.isoformat())
        t = report.get('transport',{})
        if report.get('yield_to_print') is True:
            raise PrintPriority('CUPS job has priority; service query deferred')
        if (report.get('error') or t.get('error') or t.get('read_error')
                or not report['cleanup'].get('usb_restored',report['cleanup'].get('verified')) or not t['cleanup_verified']
                or not t['write_completed'] or not t.get('small_stopped_after_end_and_two_quiet_phases')
                or report['preflight']['machine_id'] != MACHINE_ID):
            raise RuntimeError('query or restoration did not pass: '+kind)
        self.state['queries'].append({'kind':kind,'memory':memory,
            'source':str(path),'observed_utc':report['preflight']['observed_utc']})
        self.checkpoint()
        jobs=report['postflight']['cups']['unfinished_job_ids']
        if jobs is None:raise RuntimeError('CUPS postflight could not be verified')
        if jobs:raise PrintPriority('CUPS job arrived during the read; USB is restored')
        return report

    def value(self, kind, tag='R', separator='_'):
        report = self.query(kind)
        value = extract_tagged_value(base64.b64decode(report['transport']['received_base64']),
                                     report['nonce'],tag,separator)
        print(json.dumps({'verified':kind,'value':value}),flush=True)
        return value

    def memory(self,address,length):
        report = self.query('runtime_mem',(address,length))
        data,coverage = extract_addressed_reply(base64.b64decode(report['transport']['received_base64']),
                                                report['nonce'],address,length)
        self.state['queries'][-1]['validation'] = coverage
        self.checkpoint()
        return data

    def identify(self):
        firmware = self.value('fw_info_tagged','F')
        serial = self.value('telemetry_serial')
        self.state['identity'] = {'model':'HP DesignJet 500 (C7769B)',
                                  'serial':serial,'engine_firmware':firmware}
        self.checkpoint()
        if serial != SERIAL:
            raise RuntimeError('printer serial differs from the recorded target; no memory access')
        if firmware != 'A.04.02':
            raise RuntimeError('firmware-specific screen access is only verified for A.04.02')

    def locate(self):
        code = self.memory(GETTER_ADDRESS,GETTER_LENGTH)
        if hashlib.sha256(code).hexdigest() != GETTER_SHA256:
            raise RuntimeError('live framebuffer getter code differs; no native function call')
        pointer = checked_pointer(self.value('lcd_pointer_tagged','P',' '))
        header = self.memory(pointer,12)
        data_pointer = bitmap_header(header)
        self.state['bitmap'] = {'descriptor':hex(pointer),'data':hex(data_pointer),
                                'geometry':[128,64],'bytes':1024,'getter_sha256':GETTER_SHA256}
        self.checkpoint()
        return pointer,header,data_pointer

    def phases(self):
        root=checked_pointer(struct.unpack('>I',self.memory(0xa03a74b0,4))[0],0x63c)
        metadata=display_metadata(self.memory(root+0x62a,18))
        metadata['root']=hex(root)
        self.state.setdefault('display_phase_samples',[]).append(metadata)
        self.checkpoint()
        return metadata

    def capture(self,number,descriptor,header,data_pointer,phase_index=0):
        began = datetime.datetime.now(datetime.timezone.utc).isoformat()
        blocks = []
        for index in range(8):
            blocks.append(self.memory(data_pointer+128*index,128))
            print(json.dumps({'screen_pass':number,'verified_blocks':index+1,'of':8}),flush=True)
        after_pointer = (checked_pointer(self.value('lcd_pointer_tagged','P',' ')) if phase_index==0
                         else self.phases()['pointers'][phase_index])
        if after_pointer != descriptor or self.memory(after_pointer,12) != header:
            raise RuntimeError('bitmap object changed during the screen read')
        serial_after = self.value('telemetry_serial')
        if serial_after != SERIAL:
            raise RuntimeError('target printer changed during capture')
        data = b''.join(blocks)
        stem = self.target.stem+'-screen-'+str(number)
        binary = self.folder/(stem+'.bin')
        png = self.folder/(stem+'.png')
        large = self.folder/(stem+'-8x.png')
        with os.fdopen(os.open(binary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
            out.write(data)
        for path,scale in ((png,1),(large,8)):
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
                out.write(native_png(data,scale))
        self.state['screens'].append({'pass':number,'phase_index':phase_index,'began_utc':began,
            'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'geometry':[128,64],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'all_requested_bytes_accounted':True,'binary':str(binary),
            'png':str(png),'large_png':str(large)})
        self.checkpoint()
        return data

    def include_other_phase(self,primary_descriptor):
        metadata=self.phases()
        if metadata['pointers'][0]!=primary_descriptor:
            raise RuntimeError('primary bitmap changed before blink-phase capture')
        if metadata['flashing_enabled'] or metadata['sampled_active_index']==1:
            descriptor=metadata['pointers'][1]
            header=self.memory(descriptor,12)
            self.capture('blink1',descriptor,header,bitmap_header(header),phase_index=1)

    def status(self,kinds=STATUS_KINDS):
        for kind in kinds:
            # A malformed/mismatched fresh tag is a transport validation
            # failure, not an unavailable field. Never accept it silently.
            value = self.value(kind)
            self.state['status'][kind.removeprefix('telemetry_')] = {
                'raw':value,'available':value not in ('(null)','(meta)',''),
                'units':None,'percentage_claimed':False}
            self.checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('screen','status','all','heads','diagnostics'))
    parser.add_argument('--passes',type=int,choices=(1,2),default=2)
    parser.add_argument('--include-blink',action='store_true',help='also read the alternate native phase of flashing icons')
    parser.add_argument('--until-utc',required=True,help='authorized session deadline, ISO8601 including timezone')
    args = parser.parse_args()
    cutoff = datetime.datetime.fromisoformat(args.until_utc)
    if cutoff.tzinfo is None or cutoff <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('the authorized deadline must be a future timezone-aware time')
    client = Client(cutoff,args.mode,args.passes)
    try:
        client.identify()
        if args.mode in ('screen','all'):
            descriptor,header,pointer = client.locate()
            captures = [client.capture(i+1,descriptor,header,pointer) for i in range(args.passes)]
            client.state['screen_passes_identical'] = len(captures)>1 and all(x==captures[0] for x in captures)
            if len(captures)>1 and not client.state['screen_passes_identical']:
                raise RuntimeError('screen passes differ; preserve both for inspection, do not claim a stable snapshot')
            if args.include_blink:
                client.include_other_phase(descriptor)
        if args.mode in ('status','all'):
            client.status()
        if args.mode in ('heads','all'):
            client.status(HEAD_KINDS)
        if args.mode=='diagnostics':
            client.status(DIAGNOSTIC_KINDS)
            if client.value('telemetry_serial')!=SERIAL:
                raise RuntimeError('printer identity changed at the end of diagnostics')
        client.state['complete'] = True
    except Exception as error:
        client.state['error'] = str(error)
        raise
    finally:
        client.state['elapsed_seconds'] = round(time.monotonic()-client.started,3)
        client.checkpoint()
        print(json.dumps({'session':str(client.target),'complete':client.state['complete'],
                          'elapsed_seconds':client.state['elapsed_seconds']}),flush=True)


if __name__ == '__main__':
    main()
