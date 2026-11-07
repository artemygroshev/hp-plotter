"""Reject unprepared operations and out-of-RAM reads before SSH access."""
import unittest
import datetime
import json
from pathlib import Path
import tempfile
import subprocess
import ast
import base64
import zlib
import sys
from unittest.mock import patch
import run_service_read as runner


class RunnerChecks(unittest.TestCase):
    def test_no_arbitrary_kind_or_command_can_reach_ssh(self):
        with patch.object(runner,'ssh_execute',side_effect=AssertionError('SSH forbidden')):
            for kind in ('FWUPDATE','@PJL RESET','runtime_mem'):
                with self.assertRaises(ValueError):
                    runner.execute(kind,print_summary=False)

    def test_memory_limits_are_checked_before_ssh(self):
        with patch.object(runner,'ssh_execute',side_effect=AssertionError('SSH forbidden')):
            for span in ((0x18000000,4),(0xa0540d08,129),(0xa0540d08,0),(0xa0fffff0,32)):
                with self.assertRaises(ValueError):
                    runner.execute('runtime_mem',memory=span,print_summary=False)

    def test_exact_command_is_read_only_and_bounded(self):
        self.assertEqual(runner.safe_memory_command(0xa0540d08,128),b'osMemDump 0xa0540d08 128')

    def test_local_executor_uses_no_ssh_and_clears_guard_only_after_proven_cleanup(self):
        from local_config import DEFAULTS
        class Child:
            returncode=0
            def communicate(self,timeout):
                report={'cleanup':{'verified':True},'transport':{'cleanup_verified':True,
                    'write_completed':True,'small_stopped_after_end_and_two_quiet_phases':True}}
                return 'BTT_RESULT:'+json.dumps(report),''
        with tempfile.TemporaryDirectory() as folder:
            config=dict(DEFAULTS,executor='local',capture_root=folder)
            deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).isoformat()
            with patch.object(runner,'configuration',return_value=config),\
                 patch.object(runner.subprocess,'Popen',return_value=Child()) as spawn,\
                 patch.object(runner,'ssh_execute',side_effect=AssertionError('no SSH')):
                path,report,_=runner.execute('telemetry_serial',deadline_utc=deadline,print_summary=False)
                self.assertTrue(path.is_file())
                self.assertFalse((Path(folder)/'transaction-unverified.json').exists())
                source=spawn.call_args.args[0][-1]
                encoded=next(n.args[0].value for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='b64decode')
                source=zlib.decompress(base64.b64decode(encoded)).decode()
                self.assertIn("with locking['usb_lock']",source)
                self.assertIn('with guard.DeviceGuard(',source)
                self.assertNotIn(folder,source)
                self.assertNotIn('RESET',source.split("r=trace['run']",1)[1])

    def test_compressed_program_crosses_old_argument_limit_without_altering_code(self):
        source="print('offline verified')\n#"+'x'*200000
        packed=runner.packed_program(source)
        self.assertLess(len(packed),110000)
        proc=subprocess.run([sys.executable,'-c',packed],capture_output=True,text=True,check=True)
        self.assertEqual(proc.stdout,'offline verified\n')

    def test_insufficient_cleanup_time_rejected_before_connecting(self):
        deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=10)).isoformat()
        with patch.object(runner,'configuration',side_effect=AssertionError('too late')),self.assertRaises(ValueError):
            runner.execute('telemetry_serial',deadline_utc=deadline)

    def test_status_must_not_disguise_bad_nonce_as_missing_field(self):
        from designjet_readonly import Client
        client=object.__new__(Client)
        client.value=lambda kind:(_ for _ in ()).throw(ValueError('nonce mismatch'))
        with self.assertRaises(ValueError):client.status(('telemetry_head_3',))

    def test_arriving_print_job_yields_after_proven_hardware_cleanup(self):
        import designjet_readonly as client_module
        client=object.__new__(client_module.Client)
        client.cutoff=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)
        client.state={'queries':[]};client.checkpoint=lambda:None
        report={'cleanup':{'verified':False,'usb_restored':True},
            'transport':{'cleanup_verified':True,'write_completed':True,
                         'small_stopped_after_end_and_two_quiet_phases':True},
            'preflight':{'machine_id':client_module.MACHINE_ID,'observed_utc':'offline'},
            'postflight':{'cups':{'unfinished_job_ids':[17]}}}
        with patch.object(client_module,'execute',return_value=(Path('/offline/report'),report,{})):
            with self.assertRaises(client_module.PrintPriority):client.query('telemetry_part')
        self.assertEqual(len(client.state['queries']),1)

    def test_queued_job_refusal_has_no_usb_result_to_decode(self):
        import designjet_readonly as client_module
        client=object.__new__(client_module.Client)
        client.cutoff=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)
        report={'yield_to_print':True,'no_usb_started':True,'error':'print pending'}
        with patch.object(client_module,'execute',return_value=(Path('/offline/report'),report,{})):
            with self.assertRaises(client_module.PrintPriority):client.query('telemetry_part')


if __name__=='__main__':
    unittest.main(verbosity=2)
