import unittest

from setup_worker_probe import SetupWorkerSession, KIND, COMMAND, audit_payload


class SetupWorkerChecks(unittest.TestCase):
    def session(self):
        s = object.__new__(SetupWorkerSession)
        s.queries = []
        s.floor = 100
        s.proofs_verified = True
        return s

    def test_fixed_command_and_fresh_tick_guard(self):
        p = audit_payload('abcdef', 100)
        self.assertEqual(len(p), 257)
        self.assertIn(COMMAND.encode(), p)
        self.assertIn(b'[sysTickGet] >= 100', p)
        self.assertEqual(p.count(b'osFuncCall'), 1)

    def test_live_entry_disabled_even_with_proofs_and_after_an_attempt(self):
        with self.assertRaises(RuntimeError):
            self.session().command_payload(KIND, 'abcdef')
        for setting, value in (('proofs_verified', False), ('floor', None),
                               ('queries', [{'kind': KIND}])):
            s = self.session()
            setattr(s, setting, value)
            with self.assertRaises(RuntimeError):
                s.command_payload(KIND, 'abcdef')
        with self.assertRaises(RuntimeError):
            self.session().command_payload(KIND, 'abcdef', (0, 1))

    def test_requires_complete_fresh_boolean_result(self):
        for value in (0, 1):
            r = {}
            self.session().validate_reply(KIND, 'abcdef',
                ('Babcdef\n%d\nEabcdef\n' % value).encode(), None, r)
            self.assertEqual(r['setup_worker_result'], value)
        for raw in (b'Babcdef\n-2147483648\nEabcdef\n',
                    b'Babcdef\n7\nEabcdef\n', b'Babcdef\nEabcdef\n',
                    b'Babcdef\n1\nE123456\n'):
            with self.assertRaises((ValueError, RuntimeError)):
                self.session().validate_reply(KIND, 'abcdef', raw, None, {})
