"""Unprivileged LAN dashboard: cached HP telemetry and an optional CUPS client."""
import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import hashlib
import ipaddress
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit, unquote
from cups_api import CupsClient, CupsError, MAX_UPLOAD


def current_status(root):
    state=json.loads((root/'status.json').read_text())
    stamp=state.get('last_screen_utc') or state.get('last_success_utc')
    age=None if stamp is None else max(0,(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(stamp)).total_seconds())
    state['age_seconds']=age
    state['stale']=age is None or age>3600
    state['server_utc']=dt.datetime.now(dt.timezone.utc).isoformat()
    return state


def current_history(root,kind):
    name={'system':'system-journal.json','heads':'head-history.json','reset':'reset-info.json'}[kind]
    state=json.loads((root/name).read_text())
    if state.get('version')!=1 or state.get('kind')!=kind or state.get('current_fault_proven') is not False:
        raise ValueError('unverified history cache')
    stamp=dt.datetime.fromisoformat(state['observed_utc'])
    if stamp.tzinfo is None:raise ValueError('history time needs timezone')
    state['age_seconds']=max(0,(dt.datetime.now(dt.timezone.utc)-stamp).total_seconds())
    state['stale']=state['age_seconds']>3600
    return state


def handler(root, cups=None, enable_print=False):
    root=Path(root)
    cups=cups or CupsClient()
    token=secrets.token_hex(32)
    writes={}
    write_lock=threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def reply(self, data, mime='application/json', status=200):
            if not isinstance(data, bytes):data=json.dumps(data,ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'")
            self.end_headers();self.wfile.write(data)

        def do_GET(self):
            path=urlsplit(self.path).path
            try:
                if path=='/':
                    data=Path(__file__).with_name('viewer.html').read_bytes();mime='text/html; charset=utf-8'
                elif path in ('/viewer.css','/viewer.js'):
                    data=Path(__file__).with_name(path[1:]).read_bytes()
                    mime='text/css; charset=utf-8' if path.endswith('.css') else 'text/javascript; charset=utf-8'
                elif path in ('/assets/IBMPlexSans-Regular.ttf','/assets/IBMPlexSans-Medium.ttf',
                              '/assets/IBMPlexSans-SemiBold.ttf','/assets/LICENSE-IBM-Plex.txt'):
                    data=(Path(__file__).parent/'assets'/path.split('/')[-1]).read_bytes()
                    mime='text/plain; charset=utf-8' if path.endswith('.txt') else 'font/ttf'
                elif path=='/api/queue':
                    self.reply({**cups.status(), 'can_print':enable_print,
                                'csrf_token':token if enable_print else None});return
                elif path in ('/api/status','/health'):
                    state=current_status(root)
                    data=json.dumps(state if path=='/api/status' else {
                        'server':'ok','collector_state':state['state'],'stale':state['stale'],
                        'age_seconds':state['age_seconds']}).encode();mime='application/json'
                elif path in ('/api/system-journal','/api/head-history','/api/reset-info'):
                    state=current_history(root,{'/api/system-journal':'system',
                        '/api/head-history':'heads','/api/reset-info':'reset'}[path])
                    data=json.dumps(state).encode();mime='application/json'
                elif path in ('/screen/0.png','/screen/1.png'):
                    state=current_status(root);phase=int(path.split('/')[2].split('.')[0])
                    screens=[s for s in (state.get('latest') or {}).get('screens',[]) if s['phase_index']==phase]
                    if not screens:self.send_error(404);return
                    name=screens[-1]['file']
                    if not re.fullmatch(r'lcd-[a-f0-9]{64}\.png',name):raise ValueError('invalid cached filename')
                    data=(root/name).read_bytes();mime='image/png'
                else:self.send_error(404);return
                self.reply(data,mime)
            except CupsError as exc:self.reply({'error':str(exc)},status=exc.status)
            except (FileNotFoundError,ValueError,KeyError,json.JSONDecodeError):
                self.send_error(503,'No verified cached snapshot')
            except (BrokenPipeError,ConnectionResetError):pass

        def do_POST(self):
            try:
                path=urlsplit(self.path).path
                action=re.fullmatch(r'/api/jobs/([1-9][0-9]{0,8})/(cancel|release|hold)',path)
                if path!='/api/print' and not action:
                    self.reply({'error':'Действие не найдено.'},status=404);return
                if not enable_print:
                    raise CupsError('Отправка заданий отключена в этой установке.',403)
                if not secrets.compare_digest(self.headers.get('X-Plotter-Token','').encode(),token.encode()):
                    raise CupsError('Обновите панель перед отправкой действия.',403)
                host=urlsplit('http://'+self.headers.get('Host','')).hostname
                named={'localhost',socket.gethostname(),socket.gethostname()+'.local'}
                if host not in named:
                    try:address=ipaddress.ip_address(host or '')
                    except ValueError:raise CupsError('Откройте панель по локальному IP-адресу BTT.',403)
                    if not (address.is_private or address.is_loopback):
                        raise CupsError('Отправка доступна через локальный адрес BTT.',403)
                origin=self.headers.get('Origin')
                if origin and urlsplit(origin).netloc!=self.headers.get('Host'):
                    raise CupsError('Откройте панель по её основному адресу.',403)
                if self.headers.get('Sec-Fetch-Site','same-origin') not in ('same-origin','none'):
                    raise CupsError('Действие разрешено только из панели плоттера.',403)
                ident=self.headers.get('X-Request-Id','')
                if not re.fullmatch(r'[a-f0-9]{32}',ident):
                    raise CupsError('Идентификатор действия не распознан. Обновите панель.',400)
                try:size=int(self.headers.get('Content-Length','0'))
                except ValueError:raise CupsError('Размер файла не распознан.',400)
                if not 0<size<=(MAX_UPLOAD if path=='/api/print' else 512):
                    raise CupsError('Файл слишком большой или пустой. Допустимо до 25 МиБ.',413)
                self.connection.settimeout(30)
                body=self.rfile.read(size)
                if len(body)!=size:raise CupsError('Файл передан не полностью. Задание не отправлено.',400)
                mime=self.headers.get('Content-Type','').split(';')[0]
                name=unquote(self.headers.get('X-Filename',''),errors='strict')
                options=self.headers.get('X-Print-Options','')
                fingerprint=hashlib.sha256(path.encode()+mime.encode()+name.encode()+options.encode()+body).hexdigest()
                with write_lock:
                    old=writes.get(ident)
                    if old is not None:
                        if old['fingerprint']!=fingerprint:raise CupsError('Идентификатор уже использован для другого действия.',409)
                        if old['result'] is None:raise CupsError('Действие уже выполняется. Обновите очередь.',409)
                        self.reply(old['result'],status=old['status']);return
                    now=time.monotonic()
                    for key in list(writes):
                        if now-writes[key]['time']>3600 and writes[key]['result'] is not None:del writes[key]
                    if len(writes)>=256:raise CupsError('Слишком много действий. Повторите позже.',429)
                    writes[ident]={'fingerprint':fingerprint,'time':now,'result':None}
                try:
                    if path=='/api/print':result=cups.submit(body,mime,name,json.loads(options))
                    else:result=cups.action(int(action[1]),action[2])
                    status=200
                except (ValueError,TypeError):result={'error':'Параметры действия не распознаны.'};status=400
                except CupsError as exc:result={'error':str(exc)};status=exc.status
                with write_lock:writes[ident].update(result=result,status=status)
                self.reply(result,status=status)
            except CupsError as exc:self.reply({'error':str(exc)},status=exc.status)
            except (ValueError,UnicodeError):self.reply({'error':'Заголовки действия не распознаны.'},status=400)
            except (BrokenPipeError,ConnectionResetError):pass
            except TimeoutError:self.reply({'error':'Передача файла прервана. Проверьте очередь перед повтором.'},status=408)
        def log_message(self,*args):pass
    return Handler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--view-root',required=True)
    parser.add_argument('--bind',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8088)
    parser.add_argument('--queue',default='HP-DesignJet-500')
    parser.add_argument('--enable-print',action='store_true',help='allow explicit CUPS submissions and own-job actions')
    args=parser.parse_args()
    server=ThreadingHTTPServer((args.bind,args.port),handler(args.view_root,CupsClient(args.queue),args.enable_print))
    server.daemon_threads=True
    try:server.serve_forever()
    finally:server.server_close()


if __name__=='__main__':main()
