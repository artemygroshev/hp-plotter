"""Portable configuration fails closed; these tests never connect to SSH."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from local_config import configuration,private_password,DEFAULTS


class ConfigChecks(unittest.TestCase):
    def test_missing_configuration_cannot_start_hardware_work(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'HP_PLOTTER_CONFIG':folder+'/missing.json'}):
            with self.assertRaises(RuntimeError):configuration()
            self.assertEqual(configuration(False)['printer_serial'],'UNCONFIGURED')

    def test_option_injection_is_rejected_before_ssh(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'hosts').write_text('')
            cfg=dict(DEFAULTS,machine_id='1'*32,printer_serial='TEST-ONLY',known_hosts=str(path/'hosts'),ssh_target='-oProxyCommand=anything')
            (path/'config.json').write_text(json.dumps(cfg))
            with patch.dict(os.environ,{'HP_PLOTTER_CONFIG':str(path/'config.json')}),self.assertRaises(ValueError):configuration()

    def test_password_file_permissions_are_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'private';path.write_text('unit-test-value\n');path.chmod(0o644)
            with self.assertRaises(ValueError):private_password({'password_file':str(path)})
            path.chmod(0o600)
            self.assertEqual(private_password({'password_file':str(path)}),'unit-test-value')

    def test_local_executor_does_not_require_ssh_files_or_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'config.json'
            cfg=dict(DEFAULTS,executor='local',machine_id='1'*32,printer_serial='TEST-ONLY',
                     known_hosts='/missing/hosts',capture_root=folder)
            path.write_text(json.dumps(cfg))
            with patch.dict(os.environ,{'HP_PLOTTER_CONFIG':str(path)}):
                self.assertEqual(configuration()['executor'],'local')
