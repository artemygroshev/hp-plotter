"""Bounded local LCD/status collection; no print, flash or reset operations."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
from local_config import configuration,capture_directory
from storage import atomic_json
from transaction_outcome import safely_closed
from device_guard import guard_path


class CycleFailure(RuntimeError):
    def __init__(self,client,cause):
        super().__init__(str(cause));self.client=client;self.cause=cause


def utc():
    return dt.datetime.now(dt.timezone.utc)


def cycle_window(settings):
    value=settings.get('minimum_cycle_window_seconds',90)
    if type(value) is not int or not 90<=value<=7200:
        raise ValueError('minimum cycle window must be 90..7200 seconds')
    return value


def publish(view,state):
    """Publish sanitized cache atomically, readable by the unprivileged server."""
    target=view/'status.json'
    atomic_json(target,state)
    target.chmod(0o644)


def public_snapshot(client,view,include_diagnostics=False):
    """Copy complete immutable PNGs before publishing their manifest."""
    state=client.state
    screens=[]
    from framebuffer_memory import native_png
    for item in state['screens']:
        source=Path(item['png'])
        raw=Path(item['binary']).read_bytes()
        if len(raw)!=1024 or hashlib.sha256(raw).hexdigest()!=item['sha256']:
            raise ValueError('cached native LCD differs from the verified session')
        expected=native_png(raw)
        if source.read_bytes()!=expected:
            raise ValueError('cached PNG differs from the verified native LCD')
        name='lcd-'+item['sha256']+'.png'
        target=view/name
        if not target.exists():
            temp=view/('.'+name)
            with temp.open('wb') as out:out.write(source.read_bytes())
            temp.chmod(0o644);os.replace(temp,target)
        elif target.read_bytes()!=expected:
            raise ValueError('public cached PNG differs from the verified native LCD')
        screens.append({key:item[key] for key in ('phase_index','began_utc','ended_utc','sha256')}
                       | {'file':name})
    from designjet_readonly import STATUS_KINDS,HEAD_KINDS,DIAGNOSTIC_KINDS
    kinds=STATUS_KINDS+HEAD_KINDS+(DIAGNOSTIC_KINDS if include_diagnostics else ())
    allowed={name.removeprefix('telemetry_') for name in kinds}
    return {'firmware':state['identity']['engine_firmware'],
            'model':state['identity']['model'],
            'fields':{key:value for key,value in state['status'].items() if key in allowed},
            'screens':screens,'atomic_snapshot':False,
            'complete':state['complete'],'fields_expected':len(allowed),
            'screen_passes_identical':state.get('screen_passes_identical'),
            'elapsed_seconds':state.get('elapsed_seconds')}


def unsafe_new_capture(folder,began,guard_file=None):
    """An uncertain write/restoration is a stop condition, never auto-replayed."""
    if Path(guard_file or folder/'transaction-unverified.json').exists():return True
    for path in folder.glob('panel-live-*/read-*.json'):
        if path.stat().st_mtime < began:continue
        report=json.loads(path.read_text())
        if report.get('no_usb_started') or 'transport' not in report:continue
        if not safely_closed(report):return True
    return False


def collect(cutoff):
    from designjet_readonly import Client,STATUS_KINDS,HEAD_KINDS
    client=Client(cutoff,'all',2)
    try:
        client.identify()
        descriptor,header,pointer=client.locate()
        frames=[client.capture(i+1,descriptor,header,pointer) for i in range(2)]
        client.state['screen_passes_identical']=frames[0]==frames[1]
        if frames[0]!=frames[1]:
            raise RuntimeError('LCD changed between full passes; no stable image published')
        client.include_other_phase(descriptor)
        client.status(STATUS_KINDS+HEAD_KINDS)
        # Bind the completed telemetry sequence to the same physical printer.
        from designjet_readonly import SERIAL
        if client.value('telemetry_serial')!=SERIAL:
            raise RuntimeError('printer identity changed at the end of the cycle')
        client.state['complete']=True
    except Exception as error:
        client.state['error']=str(error)
        raise CycleFailure(client,error) from error
    finally:
        client.state['elapsed_seconds']=round(time.monotonic()-client.started,3)
        client.checkpoint()
    return client


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings',required=True)
    args=parser.parse_args()
    settings=json.loads(Path(args.settings).read_text())
    cutoff=dt.datetime.fromisoformat(settings['until_utc'])
    if cutoff.tzinfo is None:raise ValueError('monitor deadline needs timezone')
    interval=settings.get('interval_seconds',1800)
    if type(interval) is not int or not 900<=interval<=7200:
        raise ValueError('collection interval must be 900..7200 seconds')
    window=cycle_window(settings)
    config=configuration()
    from designjet_readonly import PrintPriority
    if config['executor']!='local' or os.geteuid()!=0:
        raise RuntimeError('monitor requires the configured local root executor')
    folder=capture_directory(config)
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    view=Path(settings['view_root']);view.mkdir(mode=0o755,parents=True,exist_ok=True)
    journal=folder/'monitor-events.jsonl'
    state={'version':1,'run_id':settings.get('run_id'),'release_id':settings.get('release_id'),
           'started_utc':utc().isoformat(),'state':'starting',
           'until_utc':cutoff.isoformat(),'last_success_utc':None,'latest':None,
           'last_screen_utc':None,
           'attempts':0,'successes':0,'failures':0,'fault_latched':False}
    state['minimum_cycle_window_seconds']=window
    state['consecutive_failures']=0
    state['printing_yields']=0
    previous=view/'status.json'
    if previous.exists():
        old=json.loads(previous.read_text())
        if state['run_id'] and old.get('run_id')==state['run_id']:
            for key in ('last_success_utc','latest','attempts','successes','failures','fault_latched'):
                state[key]=old[key]
            state['last_screen_utc']=old.get('last_screen_utc')
            state['consecutive_failures']=old.get('consecutive_failures',0)
            state['printing_yields']=old.get('printing_yields',0)
    def event(kind,**fields):
        item={'utc':utc().isoformat(),'event':kind,'release_id':state['release_id'],**fields}
        with os.fdopen(os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'a') as out:
            out.write(json.dumps(item)+'\n')
    publish(view,state);event('started',until_utc=cutoff.isoformat(),minimum_cycle_window_seconds=window)
    try:
        while (cutoff-utc()).total_seconds()>window:
            if state['fault_latched'] or guard_path(config).exists():
                state['fault_latched']=True;state['state']='stopped_unsafe_transport';break
            began=time.time();start=time.monotonic()
            total=sum(p.stat().st_size for p in folder.rglob('*') if p.is_file())
            if total>256*1024*1024 or shutil.disk_usage(folder).free<256*1024*1024:
                state['state']='storage_limit';publish(view,state);event('storage_limit');break
            state['attempts']+=1;state['state']='collecting'
            state['last_attempt']={'started_utc':utc().isoformat(),'outcome':'running'}
            publish(view,state)
            try:
                client=collect(cutoff)
                state['latest']=public_snapshot(client,view)
                state['last_screen_utc']=max(s['ended_utc'] for s in client.state['screens'])
                state['last_success_utc']=utc().isoformat()
                state['successes']+=1;state['state']='waiting';state['consecutive_failures']=0
                state['last_attempt'].update(outcome='success',queries=len(client.state['queries']))
                event('cycle_success',session=str(client.target),queries=len(client.state['queries']),
                      seconds=client.state['elapsed_seconds'])
            except Exception as error:
                priority=isinstance(getattr(error,'cause',None),PrintPriority)
                if priority:
                    state['printing_yields']+=1;state['state']='waiting_for_print'
                    state['last_attempt'].update(outcome='yielded_to_print',message=str(error)[:240])
                else:
                    state['failures']+=1;state['state']='retry_wait';state['consecutive_failures']+=1
                    state['last_attempt'].update(outcome='failed',message=str(error)[:240])
                partial=getattr(error,'client',None)
                if (partial is not None and partial.state.get('screen_passes_identical') is True
                        and not (state['latest'] or {}).get('complete')):
                    state['latest']=public_snapshot(partial,view)
                    state['last_screen_utc']=max(s['ended_utc'] for s in partial.state['screens'])
                state['fault_latched']=unsafe_new_capture(folder,began,guard_path(config))
                event('cycle_yielded' if priority else 'cycle_failed',error=str(error),fault_latched=state['fault_latched'])
                if state['fault_latched']:state['state']='stopped_unsafe_transport'
            state['last_attempt']['ended_utc']=utc().isoformat();publish(view,state)
            if state['fault_latched']:break
            # No new transaction while waiting; next cycle re-identifies both
            # host/adapter and physical printer before accessing dynamic RAM.
            wait=60 if state['state']=='waiting_for_print' else (interval if not state['consecutive_failures'] else min(interval,120*2**min(4,state['consecutive_failures']-1)))
            due=(time.monotonic()+wait if state['consecutive_failures'] or state['state']=='waiting_for_print'
                 else max(start+interval,time.monotonic()+15))
            while time.monotonic()<due and (cutoff-utc()).total_seconds()>window:
                time.sleep(min(15,max(0,due-time.monotonic())))
        if state['state'] not in ('storage_limit','stopped_unsafe_transport'):
            state['state']='stopped_deadline'
    except BaseException:
        state['state']='stopped_interrupted'
        raise
    finally:
        state['stopped_utc']=utc().isoformat();publish(view,state)
        event('stopped',state=state['state'])


if __name__=='__main__':main()
