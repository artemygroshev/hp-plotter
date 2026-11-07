"""Bounded read-only service queries through explicitly pinned SSH.

No stored site credential or host key is distributed. Key/agent authentication
with noninteractive sudo is the default. An optional private password file
supports existing lab installations without including credentials in Git.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import signal
import zlib
from local_config import configuration, private_password, capture_directory, idle_binding

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent


def packed_program(source):
    encoded=base64.b64encode(zlib.compress(source.encode())).decode()
    program='import base64,zlib;exec(zlib.decompress(base64.b64decode('+repr(encoded)+')))'
    if len(program)>110000:raise ValueError('in-memory program exceeds bounded command size')
    return program


def prepared_kinds():
    tree = ast.parse((ROOT/'firmware/probe_printer.py').read_text())
    commands = next(ast.literal_eval(node.value) for node in tree.body
        if isinstance(node, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SMALL_READ_COMMANDS' for t in node.targets))
    return ('echo','snapshot')+tuple(k for k in commands if k.startswith('telemetry_') or k in ('fw_info_tagged','lcd_pointer_tagged'))


def safe_memory_command(address,length):
    if (type(address) is not int or type(length) is not int or not 1<=length<=128
            or address<0xa0001000 or address+length>0xa1000000):
        raise ValueError('memory read must remain a short span in the engine RAM window')
    return ('osMemDump 0x%08x %d'%(address,length)).encode('ascii')


def execute(kind,memory=None,print_summary=True,finish_on_short=False,deadline_utc=None):
    command = None
    if memory is None:
        if kind not in prepared_kinds():
            raise ValueError('query is not in the fixed read-only set')
    elif kind!='runtime_mem' or len(memory)!=2:
        raise ValueError('runtime memory requires a bounded address/length pair')
    else:
        command = safe_memory_command(*memory)
    if deadline_utc is None:
        raise ValueError('an explicit authorized deadline is required')
    cutoff = datetime.datetime.fromisoformat(deadline_utc)
    if cutoff.tzinfo is None or cutoff<=datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('deadline must be a future timezone-aware ISO8601 value')
    if kind!='snapshot' and (cutoff-datetime.datetime.now(datetime.timezone.utc)).total_seconds()<90:
        raise ValueError('allow at least 90 seconds for a bounded transaction and cleanup')
    config = configuration()
    sources = {
        'snapshot':(ROOT/'firmware/status_snapshot.py').read_text(),
        'probe':(ROOT/'firmware/probe_printer.py').read_text(),
        'address':(ROOT/'service/capture_usblp_readonly.py').read_text(),
        'trace':(ROOT/'service/trace_sequential_echo.py').read_text(),
        'locking':(ROOT/'service/access_lock.py').read_text(),
        'outcome':(ROOT/'service/transaction_outcome.py').read_text(),
        'guard':(ROOT/'service/device_guard.py').read_text(),
        'idle':(ROOT/'service/usb_idle.py').read_text(),
    }
    if command is not None:
        sources['probe'] += '\nSMALL_READ_COMMANDS[\'runtime_mem\'] = '+repr(command)+'\n'
    remote="import json,sys,types\nsupport=types.ModuleType('status_snapshot')\n"
    remote+='exec('+repr(sources['snapshot'])+',support.__dict__)\n'
    idle_driver,idle_alt=idle_binding(config)
    for name,value in (('MACHINE_ID',config['machine_id']),('ADAPTER_DESCRIPTOR_SHA256',config['adapter_descriptor_sha256']),('QUEUE',config['queue']),('URI','ipp://localhost:631/printers/'+config['queue']),('IDLE_DRIVER',idle_driver),('IDLE_ALTERNATE',idle_alt)):
        remote+='support.'+name+'='+repr(value)+'\n'
    remote+='support.SMALL_QUERY_BYTES='+repr(config['small_query_bytes'])+'\n'
    remote+="sys.modules['status_snapshot']=support\n"
    for key,name in (('outcome','transaction_outcome'),('guard','device_guard'),('idle','usb_idle')):
        remote+=key+'=types.ModuleType('+repr(name)+')\nexec('+repr(sources[key])+','+key+'.__dict__)\nsys.modules['+repr(name)+']='+key+'\n'
    for name in ('probe','address','trace','locking'):
        remote+=name+"={'__name__':'"+name+"_support'}\nexec("+repr(sources[name])+','+name+')\n'
    if kind=='snapshot':
        remote+="try:\n with locking['usb_lock']("+repr(config['lock_file'])+"):\n  r=support.snapshot(class_read=False)\nexcept BlockingIOError as error:\n r={'kind':'snapshot','snapshot_deferred':True,'no_usb_started':True,'error':'USB transaction in progress; use cached status'}\n"
    else:
        remote+="try:\n with locking['usb_lock']("+repr(config['lock_file'])+"):\n"
        remote+="  with guard.DeviceGuard("+repr(config['device_guard_file'])+','+repr('read:'+kind)+") as lease:\n"
        remote+="   preparation=None\n   try:\n    preparation=idle.ensure_idle(support.__dict__,"+repr({k:config[k] for k in ('idle_driver','machine_id','adapter_descriptor_sha256')})+")\n"
        remote+="    r=trace['run'](support.__dict__,probe,address['address_of'],kind="+repr(kind)+",finish_on_short="+repr(bool(finish_on_short))+",deadline_utc="+repr(deadline_utc)+")\n    r['idle_preparation']=preparation\n"
        remote+="   except (trace['PreflightError'],idle.PreparationRefused) as error:\n    r={'no_usb_started':not bool((preparation or {}).get('changed')),'no_query_started':True,'no_bulk_out_attempted':True,'idle_preparation':preparation or {},'yield_to_print':error.print_pending,'error':str(error)}\n"
        remote+="   if outcome.safely_closed(r,"+repr(kind)+"):lease.clear()\n   r['device_guard_cleared']=lease.cleared\n"
        remote+="except BlockingIOError as error:\n r={'no_usb_started':True,'error':str(error)}\nexcept guard.UnverifiedTransport as error:\n r={'no_usb_started':True,'blocked_by_device_guard':True,'error':str(error)}\n"
    remote+="r['executed_source_sha256']="+repr({k:hashlib.sha256(v.encode()).hexdigest() for k,v in sources.items()})+"\nprint('BTT_RESULT:'+json.dumps(r))\n"
    capture_root=capture_directory(config)
    capture_root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if kind!='snapshot' and config['executor']=='ssh' and (capture_root/'transaction-unverified.json').exists():
        raise RuntimeError('legacy controller-side guard requires inspection before new hardware work')
    remote=packed_program(remote)
    if config['executor']=='local':
        proc=subprocess.Popen([sys.executable,'-u','-c',remote],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            output,errors=proc.communicate(timeout=50)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:output,errors=proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill();proc.communicate();raise RuntimeError('USB child exceeded cleanup grace; restoration unverified')
        if proc.returncode:
            raise RuntimeError('local read failed; restoration unverified: '+errors[-600:])
    else:
        output=ssh_execute(config,remote)
    report=json.loads(output.split('BTT_RESULT:',1)[1].strip())
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    folder=capture_directory(config)/('panel-live-'+stamp[:8]);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    target=folder/('read-'+kind+'-'+stamp+'.json')
    with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
        json.dump(report,out,indent=2)
    transport=report.get('transport',{})
    summary={'result_file':str(target),'kind':kind,
             'write_completed':transport.get('write_completed'),
             'received_bytes':len(base64.b64decode(transport.get('received_base64',''))),
             'cleanup':report.get('cleanup'),'error':report.get('error')}
    if print_summary:print(json.dumps(summary,indent=2))
    return target,report,summary


def ssh_execute(config,remote):
    import pexpect
    password=private_password(config)
    args=['-o','ConnectTimeout=7','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+config['known_hosts']]
    args+=['-o','BatchMode=yes'] if password is None else ['-o','PubkeyAuthentication=no','-o','IdentityAgent=none','-o','NumberOfPasswordPrompts=1']
    args += [config['ssh_target'],('sudo -n ' if password is None else 'sudo -S -p BTT_SUDO_PASSWORD: ')+'python3 -u -c '+shlex.quote(remote)]
    child=pexpect.spawn('ssh',args,encoding='utf-8',timeout=55,echo=False,maxread=150000)
    try:
        if password is not None:
            child.expect('(?i)password:');child.sendline(password)
            child.expect('BTT_SUDO_PASSWORD:');child.sendline(password)
        child.expect(pexpect.EOF)
        output=child.before
    finally:
        child.close(force=True)
    if child.exitstatus!=0:
        raise RuntimeError('remote read failed; verify pinned SSH, existing authentication and sudo access')
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind',choices=tuple(k for k in prepared_kinds() if k!='lcd_pointer_tagged'),required=True)
    parser.add_argument('--until-utc',required=True)
    args=parser.parse_args()
    execute(args.kind,deadline_utc=args.until_utc)
