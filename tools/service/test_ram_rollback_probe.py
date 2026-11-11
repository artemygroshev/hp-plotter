import unittest

from ram_rollback_probe import RamSession, frame, parse, fixed_call, COPY, CACHE_CLEAR, expected_blob, validate_plan


class RamProbeTests(unittest.TestCase):
    def test_hardware_entrypoint_is_blocked_before_any_io(self):
        from unittest.mock import patch
        from ram_rollback_probe import execute
        with patch('ram_rollback_probe.configuration') as config, patch('ram_rollback_probe.usb_lock') as lock:
            with self.assertRaisesRegex(RuntimeError, 'hardware RAM execution disabled'):
                execute(None, None, None, None, production_roundtrip=True)
            config.assert_not_called()
            lock.assert_not_called()

    def session(self, workspace=0xa1800000):
        session = object.__new__(RamSession)
        session.plans = {}; session.queries = []; session.workspace = workspace
        return session

    def test_fixed_frame_and_exact_native_reply(self):
        self.assertEqual(len(frame(['osMemAlloc 1024'], '123abc')), 257)
        self.assertEqual(len(frame(['osMemAlloc 1024'] * 4, '123abc')), 513)
        self.assertEqual(parse(b'B123abc\n-1\n7\nE123abc\n', '123abc', 2), [-1, 7])
        for raw in (b'B123abc\n7\n', b'B123abc\n7\nE123abc\nnoise', b'Babcdef\n7\nEabcdef\n'):
            with self.assertRaises(ValueError):
                parse(raw, '123abc', 1)
        with self.assertRaises(ValueError):
            frame(['osMemAlloc 1024\nexit'], '123abc')

    def test_only_owned_memory_and_fixed_routines_may_be_written_or_freed(self):
        session = self.session()
        good = fixed_call(COPY, 0xa0001000, session.workspace, 16)
        session.schedule('ram_load_000', [good])
        for kind, commands in (
            ('ram_load_001', [fixed_call(COPY, 0xa0001000, 0xa00f1798, 4)]),
            ('ram_load_002', [fixed_call(COPY, 0xb0000000, session.workspace, 4)]),
            ('ram_free', ['osMemFree 0xa1800004']),
            ('ram_production', ['osFuncCall 0xa00f1710 1 0']),
            ('ram_program_cache_clear', [fixed_call(CACHE_CLEAR, 0, 0xa00f1798, 4)])):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                session.schedule(kind, commands)

    def test_repeat_action_is_rejected(self):
        session = self.session()
        session.schedule('ram_shadow', ['osFuncCall 0xa1800000 1 0'])
        session.command_payload('ram_shadow', '123abc')
        session.queries.append({'kind': 'ram_shadow'})
        with self.assertRaises(RuntimeError):
            session.command_payload('ram_shadow', 'abcdef')

    def test_upper_ram_window_is_limited_to_the_owned_block(self):
        session = self.session()
        self.assertEqual(len(session.command_payload('runtime_mem', '123abc', (0xa1800000, 128))), 129)
        with self.assertRaises(ValueError):
            session.command_payload('runtime_mem', '123abc', (0xa1800400, 4))

    def test_copy_plan_requires_exact_coverage_and_program_digest(self):
        import hashlib
        workspace = 0xa1800000
        _, blob = expected_blob(workspace)
        copies = [[0xa0001000, workspace + i, min(64, len(blob)-i)] for i in range(0, len(blob), 64)]
        plan = {'workspace': workspace, 'blob_sha256': hashlib.sha256(blob).hexdigest(), 'copies': copies}
        validate_plan(plan, workspace)
        for bad in ({**plan, 'workspace': workspace + 4}, {**plan, 'copies': copies[:-1]},
                    {**plan, 'copies': [[0xa0001000, 0xa00f1798, 4]]}):
            with self.assertRaises(ValueError):
                validate_plan(bad, workspace)


if __name__ == '__main__':
    unittest.main()
