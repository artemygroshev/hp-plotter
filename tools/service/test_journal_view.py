import datetime as dt,json,struct,unittest,tempfile,threading
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from urllib.error import HTTPError
import error_journal,head_journal,journal_view
from status_server import current_history,handler


class JournalViewChecks(unittest.TestCase):
    def session(self,mode):
        state={'mode':mode,'complete':True,'hardware_cleanup_verified':True,
            'device_guard_cleared':True,'identity':{'engine_firmware':'A.04.02','serial':'PRIVATE_SERIAL'},
            'password':'PRIVATE_PASSWORD','private_path':'/private/original.json'}
        batch={'hardware_cleanup_verified':True,'all_query_streams_closed':True,'device_guard_cleared':True,
            'postflight':{'observed_utc':'2026-11-08T02:49:00+00:00'}}
        if mode=='journal':
            raw=bytearray(201);raw[0]=1
            struct.pack_into('>HHH14s',raw,1,0,7904,268,b'pjl_events.c\0')
            journal=error_journal.decode_ring(raw);journal.update(two_copies_identical=True,mirror_header_stable=True)
            state['system_error_journal']=journal
        else:
            raw=bytearray(302);struct.pack_into('>IIHHHB',raw,2,123,0x80000,12,35,0,2)
            journal=head_journal.decode_history(raw);journal.update(two_copies_identical=True,mirror_header_stable=True)
            for color in journal['colors']:
                active=next((r for r in color['records'] if r['current_slot']),None)
                color.update(current_ODB_status_raw='524288' if active else '2',current_mask_matches_history=bool(active))
            state['head_history']=journal
        return state,batch

    def test_system_whitelist_preserves_literal_location_without_private_state(self):
        state,batch=self.session('journal');result=journal_view.public_history(state,batch)
        row=result['records'][0]
        self.assertEqual((row['code'],row['source_file'],row['source_line']),('79:04','pjl_events.c',268))
        self.assertFalse(result['current_fault_proven']);self.assertFalse(row['date_units_confirmed'])
        text=json.dumps(result)
        for private in ('PRIVATE_','private_path','record_hex','raw_hex','identity_raw'):self.assertNotIn(private,text)

    def test_head_whitelist_keeps_sampled_mask_and_derived_code_separate(self):
        state,batch=self.session('head-journal');result=journal_view.public_history(state,batch)
        row=result['colors'][0]['records'][0]
        self.assertEqual((row['status_mask_raw'],row['derived_code']),(524288,'0033'))
        self.assertEqual(row['used_ink_cc'],12)
        self.assertNotIn('identity_raw',json.dumps(result))
        self.assertFalse(result['current_fault_proven'])

    def test_partial_or_inconsistent_history_is_never_published(self):
        state,batch=self.session('journal');state['complete']=False
        with self.assertRaises(ValueError):journal_view.public_history(state,batch)
        state,batch=self.session('journal');state['system_error_journal']['records'][0]['system_code_text']='02:10'
        with self.assertRaises(ValueError):journal_view.public_history(state,batch)
        state,batch=self.session('head-journal');state['head_history']['colors'][0]['records'][0]['native_format_code_derived']='0000'
        with self.assertRaises(ValueError):journal_view.public_history(state,batch)

    def test_history_cache_has_its_own_time_and_kind(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);state,batch=self.session('journal')
            public=journal_view.public_history(state,batch)
            public['observed_utc']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=2)).isoformat()
            path=root/'system-journal.json';path.write_text(json.dumps(public))
            self.assertTrue(current_history(root,'system')['stale'])
            with self.assertRaises(FileNotFoundError):current_history(root,'heads')
            public['kind']='heads';path.write_text(json.dumps(public))
            with self.assertRaises(ValueError):current_history(root,'system')

    def test_http_serves_histories_without_requiring_a_current_lcd(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);state,batch=self.session('journal')
            (root/'system-journal.json').write_text(json.dumps(journal_view.public_history(state,batch)))
            server=ThreadingHTTPServer(('127.0.0.1',0),handler(root))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                with urlopen(base+'/api/system-journal') as response:
                    self.assertEqual(json.load(response)['records'][0]['source_file'],'pjl_events.c')
                with self.assertRaises(HTTPError) as error:urlopen(base+'/api/head-history')
                self.assertEqual(error.exception.code,503)
                with self.assertRaises(HTTPError) as error:urlopen(base+'/api/status')
                self.assertEqual(error.exception.code,503)
            finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
