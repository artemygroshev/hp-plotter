import unittest

from native_recovery import returned_close_payload
from stock_recovery_level1 import StockLevelOne, level1_payload


class StockRecoveryChecks(unittest.TestCase):
    def session(self):
        session = object.__new__(StockLevelOne)
        session.recovery_nonce = None
        session.return_clock_scheduled = False
        session.queries = []
        return session

    def test_one_fixed_level1_call_and_no_replay(self):
        session = self.session()
        payload = session.command_payload('normal_recovery', 'abc123')
        self.assertEqual(payload, level1_payload('abc123'))
        self.assertEqual(len(payload), 257)
        self.assertEqual(payload.count(b'svsOnIntervention_set 1'), 1)
        self.assertNotIn(b'svsOnIntervention_set 0', payload)
        with self.assertRaises(RuntimeError):
            session.command_payload('normal_recovery', 'def456')

    def test_return_keeps_level_and_all_head_scope_honest(self):
        session = self.session()
        report = {'phases': []}
        session.validate_reply('normal_recovery', 'abc123',
                               b'Sabc123\nRabc123_0\nEabc123\n', None, report)
        proof = report['recovery_reply_proof']
        self.assertEqual((proof['level'], proof['head_mask']), (1, 15))
        self.assertFalse(proof['physical_ink_restoration_proven'])
        with self.assertRaises(ValueError):
            session.validate_reply('normal_recovery', 'abc123',
                                   b'Sabc123\nRabc123_1\nEabc123\n', None, {'phases': []})

    def test_wait_has_no_out_until_the_exact_return(self):
        session = self.session()
        session.recovery_nonce = 'abc123'
        self.assertIsNone(session.drain_payload('normal_recovery', b'Sabc123\n'))
        self.assertIsNone(session.drain_payload('normal_recovery', b'Sabc123\nRabc123_1\n'))
        self.assertEqual(session.drain_payload('normal_recovery', b'Sabc123\nRabc123_0\n'),
                         returned_close_payload())
        self.assertIsNone(session.drain_payload('normal_recovery', b'Sabc123\nRabc123_0\n'))


if __name__ == '__main__':
    unittest.main()
