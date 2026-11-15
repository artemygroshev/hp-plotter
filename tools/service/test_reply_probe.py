"""A control reply must never turn a missing result into servicing success."""
import ctypes as C
import datetime as dt
import re
import shutil
import subprocess
import unittest

from reply_probe import (PROFILES, ReplyProbeSession, parse_probe_reply,
                         probe_payload, probe_script)
from test_batch_usb import Clock, Fake


class ReplyFake(Fake):
    def __init__(self, mode='ok'):
        super().__init__()
        self.mode = mode

    def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
        if endpoint == 1 and b'LANGUAGE=TCLWARE' in C.string_at(data, length):
            raw = C.string_at(data, length)
            self.primary += 1
            count._obj.value = 8 if self.mode == 'partial' else length
            if self.mode == 'partial':
                return -7
            nonce = re.search(rb'puts S([a-f0-9]{6})\n', raw)[1]
            result = b'1' if b'catch {error REPLY_PROBE}' in raw else b'0'
            middle = b'' if self.mode == 'missing_result' else b'R' + nonce + b'_' + result + b'\n'
            self.pending = b'S' + nonce + b'\n' + middle + b'E' + nonce + b'\n'
            return 0
        return super().bulk_transfer(handle, endpoint, data, length, count, timeout)


class ReplyProbeTests(unittest.TestCase):
    def session(self, fake):
        return ReplyProbeSession(5, 2, dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
                                 lib=fake, alt_observer=lambda: fake.alt,
                                 now=Clock(), sleep=lambda _: None,
                                 nonce_factory=lambda: '123abc', comment_bytes=63)

    @unittest.skipUnless(shutil.which('tclsh'), 'host Tcl interpreter unavailable')
    def test_actual_host_tcl_emits_all_three_lines_for_each_control(self):
        for kind in PROFILES:
            with self.subTest(kind=kind):
                result = subprocess.run(['tclsh'], input=probe_script(kind, '123abc'),
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b'')
                proof = parse_probe_reply(kind, '123abc', result.stdout)
                self.assertFalse(proof['previous_recovery_success_proven'])

    def test_fixed_payloads_never_include_native_servicing_or_memory_commands(self):
        for kind in PROFILES:
            raw = probe_payload(kind, '123abc')
            self.assertEqual(len(raw), 257)
            self.assertEqual(raw.count(b'catch {'), 1)
            for forbidden in (b'svs', b'Pump', b'ssSpit', b'fpSimulateKey', b'sysODB', b'md ', b'mm '):
                self.assertNotIn(forbidden, raw)
        for bad in ('123abc\nexit', 'short', 'ABC123'):
            with self.assertRaises(ValueError):
                probe_payload('reply_probe_flushed_zero', bad)
        with self.assertRaises(ValueError):
            probe_payload('arbitrary_script', '123abc')

    def test_strict_result_validation_rejects_missing_stale_wrong_or_extra_lines(self):
        good = b'S123abc\nR123abc_0\nE123abc\n'
        for raw in (good.replace(b'R123abc_0\n', b''), good.replace(b'_0', b'_1'),
                    good.replace(b'E123abc', b'Effffff'), good + good,
                    good + b'extra\n', good[8:]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_probe_reply('reply_probe_flushed_zero', '123abc', raw)

    def test_complete_control_uses_two_actual_quiet_IN_phases_after_end(self):
        fake = ReplyFake()
        session = self.session(fake)
        with session:
            report = session.query('reply_probe_flushed_zero')
        self.assertEqual(fake.primary, 1)
        self.assertEqual(report['out_attempts'], 1)
        self.assertTrue(report['stream_closed'])
        self.assertTrue(session.cleanup_verified)
        for phase in report['phases'][-2:]:
            self.assertIsNone(phase['write_rc'])
            self.assertTrue(phase['reads'])
            self.assertEqual(phase['received_bytes'], 0)

    def test_missing_result_poisons_session_without_following_query(self):
        fake = ReplyFake('missing_result')
        session = self.session(fake)
        with session:
            with self.assertRaises(ValueError):
                session.query('reply_probe_flushed_zero')
            with self.assertRaisesRegex(RuntimeError, 'uncertain prior'):
                session.query('reply_probe_flushed_error')
        self.assertEqual(fake.primary, 1)
        self.assertFalse(session.stream_closed)
        self.assertTrue(session.cleanup_verified)

    def test_partial_probe_is_not_replayed(self):
        fake = ReplyFake('partial')
        session = self.session(fake)
        with session:
            with self.assertRaisesRegex(RuntimeError, 'incomplete OUT'):
                session.query('reply_probe_flushed_zero')
            with self.assertRaisesRegex(RuntimeError, 'uncertain prior'):
                session.query('reply_probe_flushed_zero')
        self.assertEqual(fake.primary, 1)
        self.assertTrue(session.cleanup_verified)


if __name__ == '__main__':
    unittest.main()
