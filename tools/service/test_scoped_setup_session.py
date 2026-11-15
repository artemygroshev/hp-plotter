import datetime as dt
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'firmware'))
from scoped_setup_session import ScopedSetupSession
from ram_rollback_probe import fixed_call
from ram_rollback_program import COPY, CACHE_CLEAR
from setup_scoped_roundtrip import build
from test_batch_usb import Fake
from tick_guarded_native import frame as guarded_frame, SUPPRESSED


class ScopedSessionChecks(unittest.TestCase):
    def session(self):
        s = ScopedSetupSession(5, 2, dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
                               lib=Fake(), comment_bytes=63)
        s.workspace = 0xa0800000
        s.stream_closed = True
        return s

    def test_copy_accepts_new_tail_but_never_leaves_832_owned_bytes(self):
        s = self.session()
        s.schedule('ram_load_000', [fixed_call(COPY, 0xa0001000, s.workspace + 800, 32)])
        for args in ((0xa0001000, s.workspace + 800, 33),
                     (0xa0001000, s.workspace - 1, 1),
                     (0xa0380000, s.workspace, 1)):
            with self.assertRaises(ValueError):
                s.schedule('ram_load_004', [fixed_call(COPY, *args)])

    def test_execution_requires_full_readback_and_matching_acknowledged_cache_range(self):
        s = self.session()
        command = ['osFuncCall ' + hex(s.workspace) + ' 0']
        with self.assertRaises(ValueError):
            s.schedule('ram_scoped', command)
        blob = build(s.workspace)['blob']
        for bad in (blob[:-1], blob[:600] + b'X' + blob[601:]):
            with self.assertRaises(ValueError):
                s.accept_construction(bad)
        s.accept_construction(blob)
        with self.assertRaises(ValueError):
            s.schedule('ram_program_cache_clear', [fixed_call(CACHE_CLEAR, 0, s.workspace, 576)])
        s.schedule('ram_program_cache_clear', [fixed_call(CACHE_CLEAR, 0, s.workspace, 832)])
        with self.assertRaises(ValueError):
            s.schedule('ram_scoped', command)
        s.validate_reply('ram_program_cache_clear', '123abc', b'B123abc\n0\nE123abc\n', None, {})
        self.assertTrue(s.cache_verified)
        s.schedule('ram_scoped', command)

    def test_new_copy_revokes_execution_approval_and_old_modes_remain_disabled(self):
        s = self.session()
        s.accept_construction(build(s.workspace)['blob'])
        s.cache_verified = True
        s.schedule('ram_load_000', [fixed_call(COPY, 0xa0001000, s.workspace, 1)])
        self.assertFalse(s.construction_verified)
        self.assertFalse(s.cache_verified)
        for mode in ('ram_shadow', 'ram_production', 'ram_arbitrary'):
            with self.assertRaises(ValueError):
                s.schedule(mode, ['osFuncCall ' + hex(s.workspace) + ' 0'])

    def test_poisoned_or_unclosed_readback_cannot_authorize_execution(self):
        for field in ('poisoned', 'stream_closed'):
            s = self.session()
            setattr(s, field, field == 'poisoned')
            with self.assertRaises(ValueError):
                s.accept_construction(build(s.workspace)['blob'])

    def test_failed_or_suppressed_acknowledgment_does_not_approve_cache_or_free(self):
        s = self.session()
        s.accept_construction(build(s.workspace)['blob'])
        s.schedule('ram_program_cache_clear', [fixed_call(CACHE_CLEAR, 0, s.workspace, 832)])
        with self.assertRaises(RuntimeError):
            s.validate_reply('ram_program_cache_clear', '123abc', b'B123abc\n1\nE123abc\n', None, {})
        self.assertFalse(s.cache_verified)
        address = s.workspace
        s.schedule('ram_free', ['osMemFree ' + hex(address)])
        with self.assertRaises(RuntimeError):
            s.validate_reply('ram_free', '123abc', ('B123abc\n%d\nE123abc\n' % SUPPRESSED).encode(), None, {})
        self.assertEqual(s.workspace, address)
        s.validate_reply('ram_free', '123abc', b'B123abc\n0\nE123abc\n', None, {})
        self.assertIsNone(s.workspace)
        self.assertFalse(s.construction_verified)

    def test_every_native_frame_requires_a_same_job_tick_guard(self):
        s = self.session()
        command = ['osMemFree ' + hex(s.workspace)]
        s.schedule('ram_free', command)
        with self.assertRaises(RuntimeError):
            s.command_payload('ram_free', '123abc')
        s.floor = 123
        self.assertEqual(s.command_payload('ram_free', '123abc'), guarded_frame(command, '123abc', 123))


if __name__ == '__main__':
    unittest.main()
