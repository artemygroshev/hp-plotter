"""Unprivileged, read-only HTTP viewer for the collector's sanitized cache."""
import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def current_status(root):
    state=json.loads((root/'status.json').read_text())
    stamp=state.get('last_screen_utc') or state.get('last_success_utc')
    age=None if stamp is None else max(0,(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(stamp)).total_seconds())
    state['age_seconds']=age
    state['stale']=age is None or age>3600
    state['server_utc']=dt.datetime.now(dt.timezone.utc).isoformat()
    return state


def handler(root):
    root=Path(root)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path=urlsplit(self.path).path
            try:
                if path=='/':
                    data=Path(__file__).with_name('viewer.html').read_bytes();mime='text/html; charset=utf-8'
                elif path in ('/api/status','/health'):
                    state=current_status(root)
                    data=json.dumps(state if path=='/api/status' else {
                        'server':'ok','collector_state':state['state'],'stale':state['stale'],
                        'age_seconds':state['age_seconds']}).encode();mime='application/json'
                elif path in ('/screen/0.png','/screen/1.png'):
                    state=current_status(root);phase=int(path.split('/')[2].split('.')[0])
                    screens=[s for s in (state.get('latest') or {}).get('screens',[]) if s['phase_index']==phase]
                    if not screens:self.send_error(404);return
                    name=screens[-1]['file']
                    if not re.fullmatch(r'lcd-[a-f0-9]{64}\.png',name):raise ValueError('invalid cached filename')
                    data=(root/name).read_bytes();mime='image/png'
                else:self.send_error(404);return
                self.send_response(200)
                self.send_header('Content-Type',mime)
                self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; object-src 'none'; frame-ancestors 'none'")
                self.end_headers();self.wfile.write(data)
            except (FileNotFoundError,ValueError,KeyError,json.JSONDecodeError):
                self.send_error(503,'No verified cached snapshot')
            except (BrokenPipeError,ConnectionResetError):pass
        def log_message(self,*args):pass
    return Handler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--view-root',required=True)
    parser.add_argument('--bind',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8088)
    args=parser.parse_args()
    server=ThreadingHTTPServer((args.bind,args.port),handler(args.view_root))
    server.daemon_threads=True
    try:server.serve_forever()
    finally:server.server_close()


if __name__=='__main__':main()
