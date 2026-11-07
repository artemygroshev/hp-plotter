"""Compare CUPS filter output for native and coordinated USB URIs.

Runs filters only, under an lp systemd service with PrivateDevices. Does not
submit a CUPS job, start a backend, or access USB. Requires an idle window.
"""
import argparse
import sys
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time


def swatch_pdf():
    content=b'q\n'
    for x,color in [(15,'0 0 0 1'),(60,'1 0 0 0'),(105,'0 1 0 0'),(150,'0 0 1 0')]:
        content+=(color+' k %d 45 35 110 re f\n'%x).encode()
    content+=b'0 0 0 1 K 0.5 w 195 45 35 110 re S\nQ\n'
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 255.11811 198.425197] /Resources << >> /Contents 4 0 R >>',
        b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'endstream']
    raw=b'%PDF-1.4\n';offsets=[0]
    for index,obj in enumerate(objects,1):
        offsets.append(len(raw));raw+=str(index).encode()+b' 0 obj\n'+obj+b'\nendobj\n'
    start=len(raw);raw+=b'xref\n0 5\n0000000000 65535 f \n'
    raw+=b''.join(('%010d 00000 n \n'%offset).encode() for offset in offsets[1:])
    return raw+b'trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n'+str(start).encode()+b'\n%%EOF\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings',required=True,help='local monitor settings JSON')
    parser.add_argument('--backend-settings',required=True,help='private native URI JSON')
    parser.add_argument('--until-utc',required=True,help='authorized timezone-aware deadline')
    args=parser.parse_args()
    cutoff=dt.datetime.fromisoformat(args.until_utc)
    if cutoff.tzinfo is None or (cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<180:
        raise ValueError('allow at least 180 authorized seconds for both bounded renders')
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'service'))
    from local_config import configuration,capture_directory
    config=configuration()
    if os.geteuid()!=0 or config['executor']!='local':raise RuntimeError('configured local root executor required')
    assert Path('/etc/machine-id').read_text().strip()==config['machine_id']
    settings=json.loads(Path(args.settings).read_text())
    view=json.loads((Path(settings['view_root'])/'status.json').read_text())
    assert view['state']=='waiting' and view['last_attempt']['outcome']=='success'
    elapsed=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(view['last_attempt']['started_utc'])).total_seconds()
    assert elapsed<settings.get('interval_seconds',1800)-120 and not Path(config['device_guard_file']).exists()
    job=subprocess.run(['lpstat','-W','not-completed','-o',config['queue']],capture_output=True,text=True,timeout=6)
    assert job.returncode==0 and not job.stdout.strip()
    available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])
    assert available>300000
    ppd=Path('/etc/cups/ppd')/(config['queue']+'.ppd');ppd_bytes=ppd.read_bytes()
    for line in ppd_bytes.decode('latin1').splitlines():
        if line.startswith('*FoomaticRIPPostPipe:'):
            assert line.split(':',1)[1].strip() in ('','""')
        match=re.match(r'^\*cupsFilter2?:\s*"(.*)"',line)
        if match:assert not match[1].split()[-1].startswith('/')
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    evidence=capture_directory(config)/('pipeline-uri-'+stamp)
    evidence.mkdir(mode=0o700)
    pdf=swatch_pdf();(evidence/'input.pdf').write_bytes(pdf);(evidence/'input.pdf').chmod(0o600)
    lp=pwd.getpwnam('lp')
    temporary=Path(tempfile.mkdtemp(prefix='hp-plotter-rip-',dir='/var/tmp'))
    temporary.chmod(0o750);os.chown(temporary,0,lp.pw_gid)
    result={'input_sha256':hashlib.sha256(pdf).hexdigest(),'ppd_sha256':hashlib.sha256(ppd_bytes).hexdigest(),
        'evidence_directory':str(evidence),'physical_print_job_created':False,'private_devices':True,'runs':{}}
    try:
        input_file=temporary/'input.pdf';input_file.write_bytes(pdf)
        input_file.chmod(0o640);os.chown(input_file,0,lp.pw_gid)
        native_uri=json.loads(Path(args.backend_settings).read_text())['native_uri']
        for label,uri in [('native',native_uri),('wrapper','hpplotter:/usb')]:
            if (cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds()<75:
                raise RuntimeError('deadline reserve for the next renderer exhausted')
            mode=temporary/label;mode.mkdir(mode=0o750);os.chown(mode,0,lp.pw_gid)
            bindir=mode/'bin';bindir.mkdir(mode=0o750);os.chown(bindir,0,lp.pw_gid)
            filters=bindir/'filter';filters.mkdir(mode=0o750);os.chown(filters,0,lp.pw_gid)
            for program in Path('/usr/lib/cups/filter').iterdir():
                if not program.is_file() or not os.access(program,os.X_OK):continue
                wrapper=filters/program.name
                lines=['#!/usr/bin/python3','import json,os,sys',
                    "os.environ['DEVICE_URI']="+repr(uri),
                    "sys.stderr.write('HP_URI_CHECK:'+json.dumps({'filter':"+repr(program.name)+",'uri':os.environ['DEVICE_URI']})+'\\n')",
                    "os.execve("+repr(str(program.resolve()))+",[os.environ.get('PRINTER','Unknown')]+sys.argv[1:],os.environ)"]
                wrapper.write_text('\n'.join(lines)+'\n')
                wrapper.chmod(0o750);os.chown(wrapper,0,lp.pw_gid)
            conf=mode/'cups-files.conf';conf.write_text('ServerBin '+str(bindir)+'\n')
            conf.chmod(0o640);os.chown(conf,0,lp.pw_gid)
            args=['/usr/sbin/cupsfilter','-c',str(conf),'-p',str(ppd),'-e','-i','application/pdf',
                '-m','printer/foo','-U','validation','-t','HP path validation','-n','1',
                '-o','PageSize=Custom.90x70mm','-o','Quality=normal','-o','InputSlot=RollPaperCut',str(input_file)]
            listing=subprocess.run(['/usr/sbin/runuser','-u','lp','--']+args[:1]+['--list-filters']+args[1:],
                capture_output=True,text=True,timeout=10)
            assert listing.returncode==0,listing.stderr
            output=evidence/(label+'.prn');errors=evidence/(label+'.stderr')
            command=['systemd-run','--quiet','--wait','--collect','--pipe',
                '--unit=hp-plotter-rip-'+label+'-'+stamp.lower(),'-p','User=lp','-p','Group=lp',
                '-p','PrivateDevices=yes','-p','RuntimeMaxSec=45','-p','TimeoutStopSec=5',
                '-p','MemoryMax=256M','-p','TasksMax=32']+args
            began=time.monotonic()
            with output.open('wb') as out,errors.open('wb') as err:
                output.chmod(0o600);errors.chmod(0o600)
                completed=subprocess.run(command,stdout=out,stderr=err,timeout=60)
            text=errors.read_text(errors='replace')
            checks=[json.loads(line.split(':',1)[1]) for line in text.splitlines() if line.startswith('HP_URI_CHECK:')]
            result['runs'][label]={'rc':completed.returncode,'seconds':time.monotonic()-began,
                'bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                'uri_injected_in_filters':checks,'filter_list':listing.stdout,'stderr_file':str(errors)}
            if completed.returncode:
                result['failure_detail']=text[-3000:]
                break
            assert checks and all(check['uri']==uri for check in checks),'URI injection not observed'
        if len(result['runs'])==2 and all(item['rc']==0 for item in result['runs'].values()):
            result['rendered_bytes_identical']=(evidence/'native.prn').read_bytes()==(evidence/'wrapper.prn').read_bytes()
        assert ppd.read_bytes()==ppd_bytes
        result['ppd_unchanged']=True
    finally:
        shutil.rmtree(temporary)
    (evidence/'result.json').write_text(json.dumps(result,indent=2));(evidence/'result.json').chmod(0o600)
    print('RESULT:'+json.dumps(result))


if __name__=='__main__':main()
