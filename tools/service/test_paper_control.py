import ctypes as C
import datetime as dt
import re
import unittest
from paper_control import PAPERS,MEDIA_SET,MEDIA_VENDOR,PAPER_PRESENT,PAPER_TRAY,PaperSession,fixed_payload,perform
from batch_usb import payload_for
from test_batch_usb import Fake,Clock


class PaperFake(Fake):
    def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
        if endpoint!=1:return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        raw=C.string_at(data,length)
        if b'FP-MEDIA-' not in raw:return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        self.events.append(('out',length));count._obj.value=length;self.primary+=1
        if self.scenario=='partial_paper':count._obj.value=8;return -7
        nonce=re.search(rb'puts R([a-f0-9]{6})_',raw)[1]
        if self.scenario=='old_paper':nonce=b'ffffff'
        value=b'0' if b'sysODBSet' in raw else b'HP'
        self.pending=b'R'+nonce+b'_'+value+b'\nE'+nonce+b'\n'
        return 0


class PaperControlTests(unittest.TestCase):
    def test_fixed_frames_fit_and_do_not_accept_injection(self):
        for paper,name in PAPERS.items():
            data=fixed_payload(MEDIA_SET,'abcdef',paper)
            self.assertEqual(len(data),129)
            self.assertIn(('sysODBSet FP-MEDIA-NAME {'+name+'} s').encode(),data)
            self.assertIn(b'puts Rabcdef_',data)
            self.assertIn(b'puts Eabcdef\nexit\n',data)
            self.assertNotIn(b'@PJL SET',data)
        for paper in ('plain;sysReset','Plain Paper','glossy',None):
            with self.assertRaises(ValueError):fixed_payload(MEDIA_SET,'abcdef',paper)

    def test_vendor_query_remains_read_only(self):
        self.assertIn(b'sysODBGet FP-MEDIA-VENDOR s',fixed_payload(MEDIA_VENDOR,'abcdef'))
        with self.assertRaises(ValueError):fixed_payload(MEDIA_VENDOR,'abcdef','plain')
        with self.assertRaises(ValueError):fixed_payload(MEDIA_VENDOR,'xx;exit')

    def test_normal_read_session_cannot_build_a_write(self):
        with self.assertRaises(ValueError):payload_for(MEDIA_SET,'abcdef')

    def fixture(self,before='Coated',vendor='HP',busy='0',printing='0',present='1',tray='0',firmware='A.04.02',after='Plain Paper',rc='0'):
        calls=[]
        def query(kind):
            calls.append(kind)
            return {'fw_info_tagged':firmware,'telemetry_serial':'SERIAL',
                    'telemetry_diag_busy':busy,'telemetry_diag_printing':printing,
                    PAPER_PRESENT:present,PAPER_TRAY:tray,
                    MEDIA_VENDOR:vendor,MEDIA_SET:rc,
                    'telemetry_media':after if MEDIA_SET in calls else before}[kind]
        return query,calls

    def test_write_and_verify_without_blind_keypresses(self):
        q,calls=self.fixture()
        r=perform(q,'SERIAL','plain')
        self.assertTrue(r['changed']);self.assertTrue(r['verified'])
        self.assertEqual(r['after'],'Plain Paper');self.assertEqual(calls.count(MEDIA_SET),1)
        self.assertEqual(calls[calls.index(MEDIA_SET)-1],'telemetry_diag_printing')
        self.assertEqual(calls[-1],'telemetry_serial')

    def test_plain_already_selected_does_not_write(self):
        q,calls=self.fixture(before='Plain Paper')
        r=perform(q,'SERIAL','plain')
        self.assertFalse(r['write_attempted']);self.assertTrue(r['verified'])
        self.assertNotIn(MEDIA_SET,calls)

    def test_explicit_reapply_does_not_claim_a_profile_change(self):
        q,calls=self.fixture(before='Plain Paper')
        r=perform(q,'SERIAL','plain',True)
        self.assertTrue(r['write_attempted']);self.assertTrue(r['verified']);self.assertFalse(r['changed'])
        self.assertEqual(calls.count(MEDIA_SET),1)
        with self.assertRaises(ValueError):perform(q,'SERIAL',None,True)

    def test_read_is_default_and_does_not_need_idle_or_known_vendor(self):
        q,calls=self.fixture(vendor='OTHER',busy='1',before='Other paper')
        r=perform(q,'SERIAL')
        self.assertEqual(r['before'],'Other paper');self.assertFalse(r['verified'])
        self.assertNotIn(MEDIA_SET,calls)

    def test_busy_printing_unknown_vendor_previous_and_firmware_block_write(self):
        for settings in ({'busy':'1'},{'printing':'1'},{'busy':'unknown'},
                         {'present':'0'},{'tray':'1'},
                         {'vendor':'OTHER'},{'before':'Other paper'},{'firmware':'A.05.01'}):
            with self.subTest(settings=settings):
                q,calls=self.fixture(**settings)
                with self.assertRaises(RuntimeError):perform(q,'SERIAL','plain')
                self.assertNotIn(MEDIA_SET,calls)

    def test_glossy_can_be_corrected_to_plain(self):
        q,calls=self.fixture(before='Glossy Photo')
        r=perform(q,'SERIAL','plain')
        self.assertEqual(r['before'],'Glossy Photo');self.assertTrue(r['changed'])

    def test_serial_mismatch_prevents_write(self):
        q,calls=self.fixture()
        with self.assertRaises(RuntimeError):perform(q,'WRONG','plain')
        self.assertNotIn(MEDIA_SET,calls)

    def test_rejected_setting_and_readback_failure_never_retry(self):
        for settings in ({'rc':'-1'},{'after':'Coated'}):
            with self.subTest(settings=settings):
                q,calls=self.fixture(**settings)
                with self.assertRaises(RuntimeError):perform(q,'SERIAL','plain')
                self.assertEqual(calls.count(MEDIA_SET),1)

    def session(self,fake):
        return PaperSession(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5),
            paper='plain',lib=fake,alt_observer=lambda:fake.alt,now=Clock(),
            sleep=lambda _:None,nonce_factory=lambda:'abcdef',comment_bytes=63)

    def test_session_closes_fresh_setter_reply_without_begin_line(self):
        fake=PaperFake();s=self.session(fake)
        with s:reply=s.query(MEDIA_SET)
        self.assertTrue(reply['stream_closed']);self.assertTrue(s.cleanup_verified)
        self.assertEqual([p['written_bytes'] for p in reply['phases']],[129,63,63])

    def test_partial_setter_out_is_never_replayed(self):
        fake=PaperFake('partial_paper');s=self.session(fake)
        with self.assertRaises(RuntimeError):
            with s:s.query(MEDIA_SET)
        self.assertFalse(s.stream_closed);self.assertTrue(s.cleanup_verified)
        self.assertEqual(fake.primary,1);self.assertEqual(s.queries[0]['out_attempts'],1)

    def test_old_setter_reply_is_rejected(self):
        fake=PaperFake('old_paper');s=self.session(fake)
        with self.assertRaises(RuntimeError):
            with s:s.query(MEDIA_SET)
        self.assertFalse(s.stream_closed);self.assertTrue(s.cleanup_verified)


if __name__=='__main__':unittest.main()
