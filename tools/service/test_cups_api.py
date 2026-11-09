import json, plistlib, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from cups_api import CupsClient, CupsError, MAX_UPLOAD, USER
from status_server import handler


class CupsChecks(unittest.TestCase):
    def response(self, groups):
        return plistlib.dumps({'Successful':True,'Tests':[{'Successful':True,'ResponseAttributes':g} for g in groups]}).decode()

    def test_plist_preserves_titles_and_live_queue_is_separate_from_hp(self):
        client=CupsClient()
        raw=self.response([[{'printer-state':3,'printer-is-accepting-jobs':True}],
            [{'job-id':12,'job-state':4,'job-name':'A <script>\njob-id = 99','job-originating-user-name':USER}],[]])
        with patch.object(client,'run',return_value=raw) as run:
            data=client.status()
            self.assertEqual(data['active'][0]['id'],12)
            self.assertEqual(data['active'][0]['name'],'A <script> job-id = 99')
            self.assertTrue(data['active'][0]['can_control'])
            self.assertEqual(data['source'],'CUPS')
            self.assertNotIn('ready',data)
            self.assertIs(client.status(),data)
            self.assertEqual(run.call_count,1)

    def test_incomplete_or_failed_response_never_means_empty_queue(self):
        client=CupsClient()
        for raw in ['not a plist',plistlib.dumps({'Successful':False,'Tests':[]}).decode(),self.response([[],[],[]])]:
            with self.subTest(raw=raw),patch.object(client,'run',return_value=raw):
                with self.assertRaises(CupsError):client.status(force=True)
                self.assertIsNone(client.cached)

    def test_cups_multi_test_summary_is_verified_outside_the_xml(self):
        client=CupsClient();base=self.response([[{'printer-state':3}],[],[]])
        with patch.object(client,'run',return_value=base+'\nSummary: 3 tests, 3 passed, 0 failed, 0 skipped\nScore: 100%\n'):
            self.assertEqual(client.status()['active'],[])
        with patch.object(client,'run',return_value=base+'\nSummary: 3 tests, 2 passed, 1 failed, 0 skipped\nScore: 66%\n'):
            with self.assertRaises(CupsError):client.status(force=True)

    def test_submission_uses_fixed_queue_bounded_options_and_always_cleans_tempfile(self):
        client=CupsClient()
        seen=[]
        def run(args,**kwargs):
            path=Path(args[-1]);self.assertTrue(path.exists());self.assertEqual(path.read_bytes(),b'%PDF-test')
            seen.append((args,path));return 'request id is HP-DesignJet-500-7 (1 file(s))\n'
        with patch.object(client,'run',side_effect=run):
            result=client.submit(b'%PDF-test','application/pdf','Тест.pdf',{'length_mm':430,'quality':'normal','hold':True})
        self.assertEqual(result['job_id'],7);self.assertTrue(result['held'])
        args,path=seen[0];self.assertFalse(path.exists())
        self.assertIn('PageSize=Custom.610x430.00mm',args)
        self.assertEqual(args[args.index('-H')+1],'hold')
        self.assertIn('page-ranges=1',args)
        self.assertNotIn('sudo',args)

    def test_rejected_upload_never_runs_a_command(self):
        client=CupsClient();valid={'length_mm':430,'quality':'normal','hold':True}
        examples=[(b'x','application/pdf','a.pdf',valid),(b'%PDF-x','text/plain','a.pdf',valid),
            (b'%PDF-x','application/pdf','../a.pdf',valid),(b'%PDF-x','application/pdf','a\nb.pdf',valid),
            (b'%PDF-x','application/pdf','a.pdf',{**valid,'length_mm':float('nan')}),
            (b'%PDF-x','application/pdf','a.pdf',{**valid,'length_mm':2001}),
            (b'%PDF-x','application/pdf','a.pdf',{**valid,'hold':'yes'}),
            (b'%PDF-x','application/pdf','a.pdf',{**valid,'quality':'normal;reboot'})]
        with patch.object(client,'run') as run:
            for args in examples:
                with self.subTest(args=args),self.assertRaises(CupsError):client.submit(*args)
            run.assert_not_called()

    def test_actions_cannot_target_another_queue_owner_or_completed_job(self):
        client=CupsClient()
        for active in [[],[{'id':7,'state':4,'can_control':False}],[{'id':7,'state':3,'can_control':True}]]:
            with patch.object(client,'status',return_value={'active':active}),patch.object(client,'run') as run:
                with self.assertRaises(CupsError):client.action(7,'release')
                run.assert_not_called()

    def test_exact_job_cancel_and_release_never_cancel_all(self):
        client=CupsClient()
        with patch.object(client,'status',return_value={'active':[{'id':7,'state':4,'can_control':True}]}),patch.object(client,'run') as run:
            client.action(7,'cancel');self.assertEqual(run.call_args.args[0],['cancel','-h','localhost:631','-U',USER,'HP-DesignJet-500-7'])
            client.action(7,'release');self.assertIn('resume',run.call_args.args[0]);self.assertNotIn('-a',run.call_args.args[0])

    def test_hold_targets_only_an_own_pending_job(self):
        client=CupsClient()
        for state in [3,4,5,9]:
            with patch.object(client,'status',return_value={'active':[{'id':7,'state':state,'can_control':True}]}),patch.object(client,'run') as run:
                if state==3:
                    client.action(7,'hold');self.assertEqual(run.call_args.args[0],['lp','-h','localhost:631','-U',USER,'-i','HP-DesignJet-500-7','-H','hold'])
                else:
                    with self.assertRaises(CupsError):client.action(7,'hold')
                    run.assert_not_called()


class FakeCups:
    def __init__(self):self.calls=0
    def status(self):return {'active':[],'recent':[],'queue':'HP-DesignJet-500'}
    def submit(self,*args):self.calls+=1;return {'job_id':7,'held':True}
    def action(self,*args):self.calls+=1;return {'job_id':7}


class DashboardHttpChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.client=FakeCups()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.tmp.name,self.client,True))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.token=json.load(urlopen(self.base+'/api/queue'))['csrf_token']
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def post(self,**overrides):
        headers={'Content-Type':'application/pdf','X-Plotter-Token':self.token,'X-Request-Id':'a'*32,'X-Filename':'test.pdf','X-Print-Options':'{"length_mm":430,"quality":"normal","hold":true}'}
        headers.update(overrides)
        return urlopen(Request(self.base+'/api/print',data=b'%PDF-test',headers=headers,method='POST'))
    def test_repeat_post_returns_original_result_without_printing_again(self):
        self.assertEqual(json.load(self.post())['job_id'],7)
        self.assertEqual(json.load(self.post())['job_id'],7)
        self.assertEqual(self.client.calls,1)
        with self.assertRaises(HTTPError) as exc:self.post(**{'X-Filename':'other.pdf'})
        self.assertEqual(exc.exception.code,409);self.assertEqual(self.client.calls,1)
    def test_foreign_origin_missing_token_and_cross_site_are_denied(self):
        for h in [{'Origin':'http://other.local'},{'X-Plotter-Token':'wrong'},{'Sec-Fetch-Site':'cross-site'},
                  {'Host':'rebinding.example','Origin':'http://rebinding.example'}]:
            with self.subTest(h=h),self.assertRaises(HTTPError) as exc:self.post(**h)
            self.assertEqual(exc.exception.code,403)
        self.assertEqual(self.client.calls,0)
    def test_assets_are_explicitly_whitelisted_and_external_scripts_are_allowed(self):
        for path in ['/','/viewer.js','/viewer.css','/assets/IBMPlexSans-Regular.ttf']:
            with urlopen(self.base+path) as r:
                self.assertEqual(r.status,200);self.assertIn("script-src 'self'",r.headers['Content-Security-Policy'])
        with self.assertRaises(HTTPError) as exc:urlopen(self.base+'/assets/../../config.json')
        self.assertEqual(exc.exception.code,404)
    def test_unknown_write_and_bad_length_do_not_reach_cups(self):
        with self.assertRaises(HTTPError) as exc:urlopen(Request(self.base+'/api/reset',data=b'{}'))
        self.assertEqual(exc.exception.code,404);self.assertEqual(self.client.calls,0)
