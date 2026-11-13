import subprocess
import shutil
import unittest

from ram_rollback_probe import parse
from tick_guarded_native import SUPPRESSED, frame


class TickGuardChecks(unittest.TestCase):
    def run_tcl(self, commands, ticks, floor):
        payload = frame(commands, 'abc123', floor)
        script = payload.split(b'@PJL ENTER LANGUAGE=TCLWARE\r\n', 1)[1].split(b'\nexit\n', 1)[0]
        stubs = ('proc sysTickGet {} {return ' + str(ticks) + '}\n'
                 'proc osFuncCall {address count args} {\n'
                 '  puts stderr CALLED\n'
                 '  return [lindex {2 0 0 1} [lindex $args 0]]\n}\n')
        result = subprocess.run(['tclsh'], input=stubs.encode() + script + b'\n',
                                capture_output=True, check=True)
        return parse(result.stdout, 'abc123', len(commands)), result.stderr

    @unittest.skipUnless(shutil.which('tclsh'), 'system tclsh required for Tcl semantics')
    def test_pass_returns_each_result_once(self):
        values, calls = self.run_tcl(['osFuncCall 0xa00a1058 1 0',
                                     'osFuncCall 0xa00a1058 1 3'], 100, 100)
        self.assertEqual(values, [2, 1])
        self.assertEqual(calls, b'CALLED\nCALLED\n')

    @unittest.skipUnless(shutil.which('tclsh'), 'system tclsh required for Tcl semantics')
    def test_lower_ticks_suppress_all_calls(self):
        values, calls = self.run_tcl(['osFuncCall 0xa00a1058 1 0'] * 4, 99, 100)
        self.assertEqual(values, [SUPPRESSED] * 4)
        self.assertEqual(calls, b'')

    def test_fixed_sizes_cover_worst_copy_group(self):
        command = 'osFuncCall 0xa0010770 3 0xa037ffff 0xa1ffffff 0x40'
        self.assertEqual(len(frame([command] * 4, 'abcdef', 0x7ffffffe)), 513)
        self.assertEqual(len(frame(['osMemFree 0xa1ffffff'], 'abcdef', 100)), 257)

    def test_rejects_injection_and_ambiguous_tick_values(self):
        for floor in (0, -1, True, 0x7fffffff, 0x80000000):
            with self.assertRaises(ValueError):
                frame(['osMemAlloc 1024'], 'abcdef', floor)
        for command in ('osMemAlloc 1024\nexit', 'osMemFree [evil]', 'osFuncCall 0xa00a1058 1 0; exit'):
            with self.assertRaises(ValueError):
                frame([command], 'abcdef', 100)


if __name__ == '__main__':
    unittest.main()
