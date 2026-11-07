"""Reject unprepared operations and out-of-RAM reads before SSH access."""
import unittest
from unittest.mock import patch
import run_service_read as runner


class RunnerChecks(unittest.TestCase):
    def test_no_arbitrary_kind_or_command_can_reach_ssh(self):
        with patch.object(runner.pexpect,'spawn',side_effect=AssertionError('SSH forbidden')):
            for kind in ('FWUPDATE','@PJL RESET','runtime_mem'):
                with self.assertRaises(ValueError):
                    runner.execute(kind,print_summary=False)

    def test_memory_limits_are_checked_before_ssh(self):
        with patch.object(runner.pexpect,'spawn',side_effect=AssertionError('SSH forbidden')):
            for span in ((0x18000000,4),(0xa0540d08,129),(0xa0540d08,0),(0xa0fffff0,32)):
                with self.assertRaises(ValueError):
                    runner.execute('runtime_mem',memory=span,print_summary=False)

    def test_exact_command_is_read_only_and_bounded(self):
        self.assertEqual(runner.safe_memory_command(0xa0540d08,128),b'osMemDump 0xa0540d08 128')


if __name__=='__main__':
    unittest.main(verbosity=2)
