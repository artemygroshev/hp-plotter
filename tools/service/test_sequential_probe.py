"""Verify the prepared ECHO experiment offline; no USB access."""
import ctypes
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'firmware'))
import probe_printer as probe
from test_access_tools import FakeUSB, Clock

body = b'MANUFACTURER:Hewlett-Packard;MODEL:DesignJet 500 (C7769B);'
DEVICE_ID = (len(body)+2).to_bytes(2, 'big') + body


class SequentialUSB(FakeUSB):
    def __init__(self, scenario='ok', identity=DEVICE_ID):
        super().__init__(scenario)
        self.identity = identity
        self.transfers = []

    def control_transfer(self, handle, bm, request, value, index, data, length, timeout):
        if (bm, request) == (0xa1, 0):
            ctypes.memmove(data, self.identity, len(self.identity))
            return len(self.identity)
        return super().control_transfer(handle, bm, request, value, index, data, length, timeout)

    def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
        self.transfers.append(endpoint)
        return super().bulk_transfer(handle, endpoint, data, length, count, timeout)


class SequentialChecks(unittest.TestCase):
    nonce = '0123456789abcdef'

    def run_probe(self, usb):
        return probe.transact(probe.make_query('echo', self.nonce), 6, 2,
                              lib=usb, now=Clock(), read_seconds=1,
                              prime_device_id=True, sequential_readback=True)

    def test_no_bulk_in_before_single_complete_out(self):
        usb = SequentialUSB()
        result = self.run_probe(usb)
        self.assertEqual(usb.transfers[0], 1)
        self.assertTrue(all(ep == 0x82 for ep in usb.transfers[1:]))
        self.assertEqual(len(usb.out), 1)
        self.assertFalse(result['prequery_bulk_read_performed'])
        self.assertTrue(result['cleanup_verified'])
        self.assertTrue(probe.classify_echo(result['received_text'].encode(), self.nonce, usb.out[0])['pjl_echo_frame_valid'])

    def test_persistent_sequence_claims_once_and_does_not_repeat_id(self):
        usb = SequentialUSB()
        result = probe.transact(probe.make_query('echo', self.nonce), 6, 2,
            lib=usb, now=Clock(), read_seconds=1, prime_device_id=True,
            sequential_readback=True, read_packet_mode=True, persistent_sequence=True)
        self.assertEqual(len(usb.out), 3)
        self.assertEqual(usb.out[1], probe.make_lcd_pair_query(self.nonce[:6]))
        self.assertEqual(usb.out[2], probe.make_query('echo', self.nonce[::-1]))
        self.assertEqual([p['name'] for p in result['phases']],
                         ['echo_before', 'lcd_pair', 'echo_after'])
        self.assertTrue(result['cleanup_verified'])

    def test_persistent_sequence_stops_on_first_partial_write(self):
        usb = SequentialUSB('partial_write')
        result = probe.transact(probe.make_query('echo', self.nonce), 6, 2,
            lib=usb, now=Clock(), read_seconds=1, prime_device_id=True,
            sequential_readback=True, read_packet_mode=True, persistent_sequence=True)
        self.assertEqual(len(usb.out), 1)
        self.assertFalse(result['write_completed'])
        self.assertNotIn(0x82, usb.transfers)

    def test_zero_length_drain_never_enqueues_printer_commands(self):
        usb = SequentialUSB()
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True,
            sequential_kind='drain_zlp', read_packet_mode=True)
        self.assertEqual(usb.out, [b'']*8)
        self.assertEqual(result['written_bytes'], 0)
        self.assertTrue(result['cleanup_verified'])

    def test_missing_identity_still_allows_pure_drain_without_any_out(self):
        usb = SequentialUSB(identity=b'')
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='drain_only')
        self.assertEqual(usb.out, [])
        self.assertEqual(result['write_attempts'], 0)
        self.assertTrue(all(ep == 0x82 for ep in usb.transfers))
        self.assertTrue(result['cleanup_verified'])

    def test_fixed_line_terminator_cannot_be_replaced_by_a_command(self):
        with self.assertRaises(ValueError):
            probe.transact(b'exit\n', 6, 2, lib=SequentialUSB(), now=Clock(),
                prime_device_id=True, sequential_readback=True,
                sequential_kind='terminate_line')

    def test_long_drain_issues_one_in_and_never_out(self):
        usb = SequentialUSB(identity=b'')
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='long_drain')
        self.assertEqual(usb.transfers, [0x82])
        self.assertEqual(usb.out, [])
        self.assertEqual(result['reverse_timeout_ms'], 30000)
        self.assertTrue(result['cleanup_verified'])

    def test_control_status_errors_do_not_turn_into_ready_or_bulk_out(self):
        class StatusUSB(SequentialUSB):
            def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
                if bm == 0x80 and req == 0:
                    ctypes.memmove(data, bytes(2), 2)
                    return 2
                if bm == 0xa1 and req == 1:
                    return -9 if index == 0 else -1
                return super().control_transfer(handle, bm, req, value, index, data, length, timeout)
        usb = StatusUSB(identity=b'')
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='status_only')
        self.assertEqual(usb.transfers, [])
        self.assertEqual([r['rc'] for r in result['status_requests']], [2, -9, -1])
        self.assertNotIn('ready', result)
        self.assertTrue(result['cleanup_verified'])

    def class_reset_probe(self, reset_results, identity=b''):
        class ResetUSB(SequentialUSB):
            def __init__(self):
                super().__init__(identity=identity)
                self.resets = []

            def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
                if bm in (0x23, 0x21) and req == 2:
                    self.resets.append((bm, req, value, index, data, length, timeout))
                    return reset_results[len(self.resets)-1]
                return super().control_transfer(handle, bm, req, value, index, data, length, timeout)

        usb = ResetUSB()
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='class_reset')
        self.assertEqual(usb.transfers, [])
        self.assertEqual(usb.out, [])
        self.assertTrue(result['cleanup_verified'])
        for request in usb.resets:
            self.assertEqual(request[1:], (2, 0, 0, None, 0, 2000))
        return usb, result

    def test_class_reset_success_is_one_request_and_does_not_imply_hp_ready(self):
        usb, result = self.class_reset_probe([0])
        self.assertEqual([r[0] for r in usb.resets], [0x23])
        self.assertFalse(result['device_id_after_interface_reset']['decoded']['hp_c7769b_identified'])
        self.assertNotIn('ready', result)

    def test_class_reset_explicit_stall_allows_interface_recipient_fallback(self):
        usb, result = self.class_reset_probe([-9, 0], DEVICE_ID)
        self.assertEqual([r[0] for r in usb.resets], [0x23, 0x21])
        self.assertTrue(result['device_id_after_interface_reset']['decoded']['hp_c7769b_identified'])

    def test_class_reset_timeout_is_never_replayed(self):
        usb, result = self.class_reset_probe([-7])
        self.assertEqual(len(usb.resets), 1)
        self.assertEqual(result['usb_interface_reset_requests'][0]['rc'], -7)

    def test_class_reset_two_stalls_stop_without_bulk_transfer(self):
        usb, result = self.class_reset_probe([-9, -9])
        self.assertEqual(len(usb.resets), 2)
        self.assertEqual(result['usb_interface_reset_requests'][-1]['rc'], -9)

    def test_id_cycle_is_bounded_to_one_mode_cycle_and_no_data_out(self):
        class CycleUSB(SequentialUSB):
            def __init__(self):
                super().__init__()
                self.id_available = False
                self.id_calls = 0

            def set_interface_alt_setting(self, handle, interface, value):
                rc = super().set_interface_alt_setting(handle, interface, value)
                if value == 1:
                    self.id_available = True
                return rc

            def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
                if (bm, req) == (0xa1, 0):
                    self.id_calls += 1
                    raw = DEVICE_ID if self.id_available else b''
                    self.id_available = False
                    ctypes.memmove(data, raw, len(raw))
                    return len(raw)
                return super().control_transfer(handle, bm, req, value, index, data, length, timeout)

        usb = CycleUSB()
        result = probe.transact(b'', 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='id_cycle')
        self.assertEqual(usb.id_calls, 3)
        self.assertEqual([r['rc'] for r in result['interface_cycle_ids']], [0, len(DEVICE_ID)])
        self.assertEqual(usb.transfers, [])
        self.assertTrue(result['cleanup_verified'])

    def test_missing_identity_prevents_out(self):
        usb = SequentialUSB(identity=b'')
        result = self.run_probe(usb)
        self.assertEqual(usb.transfers, [])
        self.assertIn('identity not confirmed', result['error'])
        self.assertTrue(result['cleanup_verified'])

    def test_only_zero_byte_identity_read_is_retried_once(self):
        class AlternatingIDUSB(SequentialUSB):
            def __init__(self):
                super().__init__()
                self.id_calls = 0
            def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
                if (bm, req) == (0xa1, 0):
                    self.id_calls += 1
                    if self.id_calls == 1:
                        return 0
                return super().control_transfer(handle, bm, req, value, index, data, length, timeout)
        usb = AlternatingIDUSB()
        result = self.run_probe(usb)
        self.assertEqual(usb.id_calls, 2)
        self.assertEqual([r['rc'] for r in result['device_id_attempts_before_query']], [0, len(DEVICE_ID)])
        self.assertEqual(len(usb.out), 1)
        self.assertTrue(result['cleanup_verified'])

    def test_framed_echo_is_exact_packet_with_closing_line_ending(self):
        usb = SequentialUSB()
        payload = probe.make_echo_framed_query(self.nonce)
        result = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='echo_framed',
            read_packet_mode=True, forward_gap_seconds=0.25)
        self.assertEqual(len(payload), 64)
        self.assertTrue(payload.endswith(probe.UEL+b'\r\n'))
        self.assertEqual(usb.out, [payload])
        self.assertTrue(result['cleanup_verified'])
        with self.assertRaises(ValueError):
            probe.transact(payload.replace(b'ECHO', b'JUNK'), 6, 2, lib=SequentialUSB(),
                prime_device_id=True, sequential_readback=True, sequential_kind='echo_framed')

    def test_identity_error_is_not_retried(self):
        class FailedIDUSB(SequentialUSB):
            def control_transfer(self, handle, bm, req, value, index, data, length, timeout):
                if (bm, req) == (0xa1, 0):
                    return -7
                return super().control_transfer(handle, bm, req, value, index, data, length, timeout)
        usb = FailedIDUSB()
        result = self.run_probe(usb)
        self.assertEqual(len(result['device_id_attempts_before_query']), 1)
        self.assertEqual(usb.out, [])

    def test_echo_pair_keeps_one_session_and_sends_exactly_two_queries(self):
        usb = SequentialUSB()
        payload = probe.make_echo_framed_query(self.nonce)
        result = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='echo_pair',
            read_packet_mode=True, forward_gap_seconds=0.25)
        self.assertEqual(usb.out, [payload, probe.make_echo_framed_query(self.nonce[::-1])])
        self.assertEqual(len(result['device_id_attempts_before_query']), 1)
        self.assertEqual(usb.released, 1)
        self.assertTrue(result['cleanup_verified'])

    def test_comment_drain_requests_no_new_output_and_stops_when_quiet(self):
        usb = SequentialUSB()
        payload = probe.make_drain_comment()
        result = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='drain_comment',
            read_packet_mode=True, forward_gap_seconds=0.25)
        self.assertEqual(len(payload), 64)
        self.assertNotIn(b'ECHO', payload)
        self.assertEqual(usb.out, [payload]*3)
        self.assertTrue(result['drain_stopped_after_two_quiet_phases'])
        self.assertTrue(result['cleanup_verified'])

    def test_known_pattern_requires_exact_length_content_and_unique_markers(self):
        nonce = '0123ab'
        raw = b'B0123ab\n'+b' '*1018+b'0123ab\nE0123ab\n'
        self.assertTrue(probe.validate_pattern(raw, nonce)['exact_body_received'])
        for damaged in (raw[:100]+raw[101:], raw[:100]+b'X'+raw[100:],
                        raw+raw, probe.make_pattern_query(nonce), raw[:-1]):
            self.assertFalse(probe.validate_pattern(damaged, nonce)['exact_body_received'])
        usb = SequentialUSB()
        payload = probe.make_pattern_query(nonce)
        result = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
            prime_device_id=True, sequential_readback=True, sequential_kind='pattern_read',
            read_packet_mode=True, forward_gap_seconds=0.25)
        self.assertEqual(len(payload), 128)
        self.assertTrue(payload.endswith(probe.UEL+b'\r\n'))
        self.assertEqual(usb.out, [payload]+[probe.make_drain_comment()]*8)
        self.assertTrue(result['cleanup_verified'])

    def test_short_pattern_detects_a_duplicate_whole_packet(self):
        raw = b'B0123ab\n'+b' '*58+b'0123ab\nE0123ab\n'
        self.assertTrue(probe.validate_pattern(raw, '0123ab', 64)['exact_body_received'])
        self.assertFalse(probe.validate_pattern(raw[:8]+raw[8:72]+raw[8:], '0123ab', 64)['exact_body_received'])
        usb = SequentialUSB()
        result = probe.transact(probe.make_pattern_query('0123ab', 64), 6, 2,
            lib=usb, now=Clock(), read_seconds=1, prime_device_id=True,
            sequential_readback=True, sequential_kind='pattern_short', read_packet_mode=True,
            forward_gap_seconds=0.25)
        self.assertEqual(len(usb.out), 9)
        self.assertTrue(result['cleanup_verified'])

    def test_small_reads_are_fixed_and_require_fresh_complete_markers(self):
        nonce = '0123ab'
        raw = b'B0123ab\nA.04.02\nE0123ab\n'
        result = probe.extract_small_read(raw, nonce)
        self.assertTrue(result['framing_verified'])
        for bad in (raw[:-1], raw+raw, probe.make_small_read_query('fw_info', nonce),
                    raw.replace(b'A.04.02', probe.UEL)):
            self.assertFalse(probe.extract_small_read(bad, nonce)['framing_verified'])
        for kind in ('fw_info', 'rom_probe', 'rom_flush'):
            payload = probe.make_small_read_query(kind, nonce)
            self.assertEqual(len(payload), 128)
            usb = SequentialUSB()
            result = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
                prime_device_id=True, sequential_readback=True, sequential_kind=kind,
                read_packet_mode=True, forward_gap_seconds=0.25)
            self.assertEqual(len(usb.out), 9)
            self.assertTrue(result['cleanup_verified'])
            with self.assertRaises(ValueError):
                probe.transact(payload.replace(probe.SMALL_READ_COMMANDS[kind], b'exit'), 6, 2,
                    lib=SequentialUSB(), prime_device_id=True, sequential_readback=True,
                    sequential_kind=kind)

    def test_short_primary_out_profile_preserves_script_and_is_explicit(self):
        nonce='0123ab'
        original=probe.make_small_read_query('rom_flush',nonce)
        short=probe.make_small_read_query('rom_flush',nonce,129)
        self.assertEqual(len(short),129)
        self.assertEqual(short.replace(b'# \n',b'#\n'),original)
        with self.assertRaises(ValueError):
            probe.transact(short,6,2,lib=SequentialUSB(),prime_device_id=True,
                sequential_readback=True,sequential_kind='rom_flush')
        usb=SequentialUSB()
        result=probe.transact(short,6,2,lib=usb,now=Clock(),read_seconds=1,
            prime_device_id=True,sequential_readback=True,sequential_kind='rom_flush',
            small_query_bytes=129,read_packet_mode=True,finish_on_short=True)
        self.assertEqual(len(usb.out[0]),129)
        self.assertTrue(all(len(p)==64 for p in usb.out[1:]))
        self.assertTrue(result['cleanup_verified'])

    def test_short_out_tick_changes_only_the_comment_packet_length(self):
        usb = SequentialUSB()
        result = probe.transact(probe.make_pattern_query('0123ab'), 6, 2,
            lib=usb, now=Clock(), read_seconds=1, prime_device_id=True,
            sequential_readback=True, sequential_kind='pattern_63tick', read_packet_mode=True,
            forward_gap_seconds=0.25)
        self.assertEqual([len(p) for p in usb.out], [128]+[63]*8)
        self.assertTrue(all(p.endswith(probe.UEL+b'\r\n') for p in usb.out))
        self.assertTrue(result['cleanup_verified'])

    def test_short_packet_ends_small_read_phase_without_an_extra_pending_in(self):
        usb = SequentialUSB()
        result = probe.transact(probe.make_small_read_query('fw_info','0123ab'),6,2,
            lib=usb,now=Clock(),read_seconds=1,prime_device_id=True,
            sequential_readback=True,sequential_kind='fw_info',read_packet_mode=True,
            forward_gap_seconds=0.25,finish_on_short=True)
        self.assertEqual(usb.transfers[:3],[1,0x82,1])
        self.assertTrue(result['short_packet_boundaries'])
        self.assertTrue(result['cleanup_verified'])

    def test_native_lcd_block_stops_at_1024_without_a_seventeenth_in(self):
        class BlockUSB(SequentialUSB):
            def bulk_transfer(self, handle, endpoint, data, length, count, timeout):
                if endpoint==0x82 and len(self.out)==1:
                    self.transfers.append(endpoint)
                    ctypes.memmove(data,b'A'*64,64)
                    count._obj.value=64
                    return 0
                return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        ticks=[0.0]
        def tiny_clock():
            ticks[0]+=0.01
            return ticks[0]
        usb=BlockUSB()
        result=probe.transact(probe.make_small_read_query('lcd_direct','0123ab'),6,2,
            lib=usb,now=tiny_clock,read_seconds=1,prime_device_id=True,
            sequential_readback=True,sequential_kind='lcd_direct',read_packet_mode=True,
            forward_gap_seconds=0.25,finish_on_short=True)
        self.assertEqual(result['phases'][0]['received_bytes'],1024)
        self.assertEqual(usb.transfers[:18],[1]+[0x82]*16+[1])
        self.assertTrue(result['cleanup_verified'])

    def test_wrong_identity_prevents_out(self):
        body = b'MANUFACTURER:Hewlett-Packard;MODEL:Another printer;'
        usb = SequentialUSB(identity=(len(body)+2).to_bytes(2, 'big')+body)
        result = self.run_probe(usb)
        self.assertEqual(usb.out, [])
        self.assertIn('identity not confirmed', result['error'])

    def test_partial_write_is_not_replayed_and_has_no_following_in(self):
        usb = SequentialUSB('partial_write')
        result = self.run_probe(usb)
        self.assertEqual(usb.transfers, [1])
        self.assertEqual(result['write_attempts'], 1)
        self.assertFalse(result['write_completed'])
        self.assertTrue(result['cleanup_verified'])

    def test_settings_payload_rejected_before_usb(self):
        usb = SequentialUSB()
        with self.assertRaises(ValueError):
            probe.transact(probe.UEL+b'@PJL RESET\r\n'+probe.UEL, 6, 2,
                           lib=usb, prime_device_id=True, sequential_readback=True)
        self.assertEqual(usb.out, [])

    def test_concurrent_in_is_rejected(self):
        with self.assertRaises(ValueError):
            probe.transact(probe.make_query('echo', self.nonce), 6, 2,
                           lib=SequentialUSB(), prime_device_id=True,
                           sequential_readback=True, concurrent_read=True)

    def test_only_fixed_lcd_script_is_accepted(self):
        usb = SequentialUSB()
        payload = probe.make_lcd_query(self.nonce)
        report = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
                                prime_device_id=True, sequential_readback=True,
                                sequential_kind='lcd')
        self.assertLessEqual(len(payload), 128)
        self.assertEqual(usb.out, [payload])
        self.assertEqual(usb.transfers[0], 1)
        self.assertTrue(report['cleanup_verified'])

    def test_lcd_script_with_configuration_command_is_rejected(self):
        usb = SequentialUSB()
        payload = probe.make_lcd_query(self.nonce).replace(b'fpDumpDisplay BMP', b'sysODBSet X 1')
        with self.assertRaises(ValueError):
            probe.transact(payload, 6, 2, lib=usb, prime_device_id=True,
                           sequential_readback=True, sequential_kind='lcd')
        self.assertEqual(usb.out, [])

    def test_tcl_ping_is_one_full_packet_with_no_other_commands(self):
        usb = SequentialUSB()
        payload = probe.make_tcl_ping_query('0123ab')
        report = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
                                prime_device_id=True, sequential_readback=True,
                                sequential_kind='tcl_ping')
        self.assertEqual(len(payload), 64)
        self.assertEqual(usb.out, [payload])
        self.assertTrue(report['cleanup_verified'])

    def test_single_lcd_is_exactly_one_packet(self):
        usb = SequentialUSB()
        payload = probe.make_lcd_single_query()
        report = probe.transact(payload, 6, 2, lib=usb, now=Clock(), read_seconds=1,
                                prime_device_id=True, sequential_readback=True,
                                sequential_kind='lcd_single')
        self.assertEqual(len(payload), 64)
        self.assertEqual(usb.out, [payload])
        self.assertTrue(report['cleanup_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
