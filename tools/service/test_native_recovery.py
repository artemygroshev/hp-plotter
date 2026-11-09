"""A blocking native operation must not be restarted or cut by PJL ticks."""
import ctypes as C
import datetime as dt
import re
import unittest
from native_recovery import (RecoverySession, recovery_payload,
                             parse_recovery_reply, check_status,
                             require_compatible_session,returned_close_payload)
from test_batch_usb import Fake, Clock


class RecoveryFake(Fake):
    def __init__(self,partial=False,clock_final=False,omit_end=False):
        super().__init__()
        self.partial=partial;self.frames=[];self.wait_reads=0
        self.native_started=False;self.native_finished=False
        self.clock_final=clock_final;self.final_clocks=0
        self.omit_end=omit_end
    def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
        if endpoint==1:
            raw=C.string_at(data,length);self.frames.append(raw)
            if b'svsOnIntervention_set' in raw:
                self.primary+=1;count._obj.value=8 if self.partial else length
                self.events.append(('out',length))
                if self.partial:return -7
                self.nonce=re.search(rb'puts S([a-f0-9]{6})\n',raw)[1]
                self.pending=b'S'+self.nonce+b'\n';self.native_started=True
                return 0
            if self.clock_final and b'@PJL EOJ' in raw:
                assert self.native_finished,'forward clock before native return'
                self.final_clocks+=1
                self.pending=b'' if self.omit_end else b'E'+self.nonce+b'\n'
            return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        if self.native_started:
            self.wait_reads+=1
            if self.wait_reads>=12 and not self.native_finished:
                self.pending=b'R'+self.nonce+b'_0\n'
                if not self.clock_final:self.pending+=b'E'+self.nonce+b'\n'
                self.native_finished=True
        return super().bulk_transfer(handle,endpoint,data,length,count,timeout)


class NativeRecoveryTests(unittest.TestCase):
    def session(self,fake):
        return RecoverySession(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),
            key='ENTER',lib=fake,alt_observer=lambda:fake.alt,now=Clock(),sleep=lambda _:None,
            nonce_factory=lambda:'123abc',refresh_id_each_query=True,comment_bytes=63)

    def test_delayed_completion_keeps_one_action_and_uses_only_IN_to_wait(self):
        require_compatible_session()
        fake=RecoveryFake();session=self.session(fake)
        with session:report=session.query('normal_recovery')
        self.assertGreater(len(report['phases']),9)
        self.assertEqual(fake.primary,1)
        self.assertEqual(sum(b'svsOnIntervention_set' in f for f in fake.frames),1)
        self.assertEqual(len(fake.frames),1)
        self.assertTrue(all(p['waiting_without_OUT'] for p in report['phases'][1:]))
        self.assertTrue(report['recovery_reply_proof']['native_function_returned'])
        self.assertFalse(report['recovery_reply_proof']['physical_ink_restoration_proven'])
        self.assertTrue(session.stream_closed);self.assertTrue(session.cleanup_verified)

    def test_partial_action_write_blocks_following_queries_without_replay(self):
        fake=RecoveryFake(partial=True);session=self.session(fake)
        with session:
            with self.assertRaisesRegex(RuntimeError,'incomplete OUT'):
                session.query('normal_recovery')
            with self.assertRaisesRegex(RuntimeError,'uncertain prior'):
                session.query('normal_recovery')
        self.assertEqual(fake.primary,1);self.assertEqual(len(fake.frames),1)
        self.assertFalse(session.stream_closed);self.assertTrue(session.cleanup_verified)

    def test_one_forward_clock_only_after_return_releases_the_final_marker(self):
        fake=RecoveryFake(clock_final=True);session=self.session(fake)
        with session:report=session.query('normal_recovery')
        self.assertTrue(report['stream_closed'])
        self.assertEqual(fake.primary,1);self.assertEqual(fake.final_clocks,1)
        self.assertEqual(len(fake.frames),2)
        self.assertEqual(fake.frames[1],returned_close_payload())

    def test_missing_original_end_needs_a_real_explicit_close_and_is_recorded(self):
        fake=RecoveryFake(clock_final=True,omit_end=True);session=self.session(fake)
        with session:report=session.query('normal_recovery')
        proof=report['recovery_reply_proof']
        self.assertFalse(proof['original_final_marker_verified'])
        self.assertTrue(proof['explicit_EOJ_closure_verified'])
        self.assertEqual(fake.primary,1);self.assertEqual(fake.final_clocks,1)
        self.assertEqual(len(returned_close_payload()),63)
        with self.assertRaises(ValueError):
            parse_recovery_reply(b'S123abc\nR123abc_0\n','123abc')

    def test_a_stale_return_cannot_trigger_a_forward_clock(self):
        session=self.session(RecoveryFake());session.recovery_nonce='123abc'
        self.assertIsNone(session.drain_payload('normal_recovery',b'Sffffff\nRffffff_0\n'))
        self.assertFalse(session.return_clock_scheduled)
        self.assertEqual(len(session.drain_payload('normal_recovery',b'S123abc\nR123abc_0\n')),63)
        self.assertIsNone(session.drain_payload('normal_recovery',b'S123abc\nR123abc_0\n'))

    def test_completion_requires_its_start_success_and_fresh_end(self):
        good=b'S123abc\nR123abc_0\nE123abc\n'
        self.assertEqual(parse_recovery_reply(good,'123abc')['head_mask'],15)
        bads=(good.replace(b'_0',b'_1'),good.replace(b'E123abc',b'Effffff'),
              good[8:],good+b'invalid command name "\x02"\n',
              good.replace(b'S123abc',b'Sffffff'),good+good)
        for bad in bads:
            with self.subTest(raw=bad),self.assertRaises(ValueError):
                parse_recovery_reply(bad,'123abc')

    def test_payload_has_one_fixed_lowest_preset_and_no_head_or_thermal_parameters(self):
        frame=recovery_payload('123abc')
        self.assertEqual(len(frame),257)
        self.assertEqual(frame.count(b'catch {svsOnIntervention_set 0}'),1)
        self.assertNotIn(b'ssSpit',frame)
        self.assertNotIn(b'fpSimulateKey',frame)
        for nonce in ('123abg','123abc\nexit','short'):
            with self.assertRaises(ValueError):recovery_payload(nonce)

    def test_cover_and_busy_are_independent_of_the_raw_printing_enum(self):
        class Client:
            def __init__(self,values):self.values=values
            def value(self,kind):return self.values[kind]
        values={'telemetry_diag_busy':'0','telemetry_diag_cover_open':'0',
                'telemetry_diag_printing':'2'}
        self.assertEqual(check_status(Client(values),tuple(values)),values)
        for key in ('telemetry_diag_busy','telemetry_diag_cover_open'):
            with self.assertRaises(RuntimeError):
                check_status(Client(dict(values,**{key:'1'})),tuple(values))


if __name__=='__main__':unittest.main()
