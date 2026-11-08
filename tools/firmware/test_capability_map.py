"""Offline evidence checks; no printer or firmware image is distributed."""
import os
from pathlib import Path
import unittest
import capability_map


class CapabilityEvidence(unittest.TestCase):
    def test_wrong_or_other_firmware_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'pinned official'):
            capability_map.extract(b'not a firmware image')

    def test_exact_image_and_generated_public_catalogue(self):
        folder = os.environ.get('HP_PLOTTER_FIXTURES')
        if not folder:
            self.skipTest('external official A.04.02 image not supplied')
        image = Path(folder)/'engine-A0402-main.bin'
        if not image.is_file():
            self.skipTest('external official A.04.02 main image not supplied')
        data = image.read_bytes()
        report = capability_map.extract(data)
        self.assertEqual(report['command_count'], 403)
        commands = {row['name']: row for row in
                    report['commands_matching_this_registration_pattern']}
        self.assertEqual(commands['fpSimulateKey']['review'],
                         'static_event_injection_not_enabled')
        self.assertEqual(commands['fpGetStatus']['review'],
                         'static_two_result_status_not_error_text')
        self.assertEqual(report['known_head_case']['native_device_index'], 0)
        self.assertEqual(report['known_head_case']['derived_code'], '0033')
        self.assertFalse(report['system_error_log_candidate']['native_record_function_invocation_implemented'])
        self.assertEqual(report['system_error_log_candidate']['ring_bytes'],201)
        self.assertTrue(report['head_history_ram_reader']['native_index_getter_may_write_on_invalid_index'])
        self.assertFalse(report['head_history_ram_reader']['native_functions_called_by_reader'])
        import json
        saved = Path(__file__).resolve().parents[2]/'docs/a04-capabilities.json'
        self.assertEqual(report, json.loads(saved.read_text()))
        altered = bytearray(data)
        altered[0x100] ^= 1
        with self.assertRaisesRegex(ValueError, 'pinned official'):
            capability_map.extract(altered)


if __name__ == '__main__':
    unittest.main()
