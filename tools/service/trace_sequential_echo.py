"""One trace-backed, short PJL ECHO or LCD read with no pre-query bulk IN.

No image/PDL, persistent settings, flash, or arbitrary caller-supplied commands.
Explicit resumed-repair kinds may recover the recorded USB interface.
Panel state may be unknown; this never treats CUPS idle as physical Ready.
One write attempt only. An incomplete write prevents reverse reads/replay.
"""
import base64
import datetime
import os
from pathlib import Path
import secrets
import re
import select
import subprocess
import threading
import time


def run(support, probe, address_of, kind='echo', finish_on_short=False, deadline_utc=None):
    is_small = kind in probe.get('SMALL_READ_COMMANDS', {})
    if not is_small and kind not in ('echo', 'echo_framed', 'echo_pair', 'drain_comment', 'pattern_read', 'pattern_short', 'pattern_63tick', 'lcd', 'tcl_ping', 'lcd_single', 'tcl_flush', 'lcd_pair', 'persistent', 'drain_zlp', 'drain_only', 'status_only', 'terminate_line', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle'):
        raise ValueError('only fixed ECHO, Tcl marker and LCD read queries are implemented')
    if deadline_utc is None:
        raise RuntimeError('explicit authorized deadline required')
    cutoff = datetime.datetime.fromisoformat(deadline_utc)
    if cutoff.tzinfo is None:
        raise ValueError('diagnostic cutoff must include a timezone')
    if datetime.datetime.now(datetime.timezone.utc) >= cutoff:
        raise RuntimeError('autonomous diagnostic deadline: do not start a probe')
    before = support['snapshot'](class_read=False)
    cups = before['cups']
    if (cups['unfinished_job_ids'] != [] or cups['queue_command']['rc'] != 0
            or cups['queue_command']['out'].strip() or cups['usb_backend_pids']
            or cups['attributes'].get('printer-state', {}).get('raw_value') != 'idle'
            or before['usb_handles']['open_handles']
            or not before['usb_handles']['inspection_complete']):
        raise RuntimeError('queue or interface ownership not clear')
    adapters = before['adapters']
    if (len(adapters) != 1 or adapters[0]['descriptor_sha256'] != support['ADAPTER_DESCRIPTOR_SHA256']
            or adapters[0]['alternate'] != 1
            or adapters[0]['driver'] != '/sys/bus/usb/drivers/usblp'):
        raise RuntimeError('recorded bound adapter changed')
    adapter = adapters[0]
    bus, dev = int(adapter['busnum']), int(adapter['devnum'])
    nonce = secrets.token_hex(3 if is_small or kind in ('tcl_ping', 'tcl_flush', 'lcd_pair', 'pattern_read', 'pattern_short', 'pattern_63tick') else 8)
    if kind == 'terminate_line':
        payload = b'\n'
    elif kind in ('drain_zlp', 'drain_only', 'status_only', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle'):
        payload = b''
    elif kind in ('echo', 'persistent'):
        payload = probe['make_query']('echo', nonce)
    elif kind in ('echo_framed', 'echo_pair'):
        payload = probe['make_echo_framed_query'](nonce)
    elif kind == 'drain_comment':
        payload = probe['make_drain_comment']()
    elif kind in ('pattern_read', 'pattern_short', 'pattern_63tick'):
        payload = probe['make_pattern_query'](nonce, 64 if kind == 'pattern_short' else 1024)
    elif is_small:
        payload = probe['make_small_read_query'](kind, nonce)
    elif kind == 'lcd':
        payload = probe['make_lcd_query'](nonce)
    elif kind == 'lcd_pair':
        payload = probe['make_lcd_pair_query'](nonce)
    elif kind == 'tcl_flush':
        payload = probe['make_tcl_flush_query'](nonce)
    elif kind == 'tcl_ping':
        payload = probe['make_tcl_ping_query'](nonce)
    else:
        payload = probe['make_lcd_single_query']()
    if (kind == 'echo' and len(payload) != 56) or len(payload) > 128:
        raise RuntimeError('short ECHO template changed')
    report = {'preflight': before, 'panel_observation': None,
              'panel_observation_reason': 'current front panel not observed; no Ready inference',
              'kind': 'one sequential '+kind+' query, no pre-query bulk IN',
              'nonce': nonce, 'payload_hex': payload.hex(), 'print_content_sent': False,
              'usbmon_loaded_before': Path('/sys/module/usbmon').exists(), 'cleanup': {}}
    stop, ready = threading.Event(), threading.Event()
    trace, errors = bytearray(), []
    loaded, reader = False, None

    def command(args):
        p = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return {'rc': p.returncode, 'out': p.stdout[-1000:], 'err': p.stderr[-1000:]}

    def collect():
        fd = None
        try:
            fd = os.open('/sys/kernel/debug/usb/usbmon/%du' % bus, os.O_RDONLY | os.O_NONBLOCK)
            ready.set()
            end = time.monotonic() + 35
            while not stop.is_set() and time.monotonic() < end and len(trace) < 262144:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        data = os.read(fd, min(4096, 262144-len(trace)))
                    except BlockingIOError:
                        continue
                    if not data:
                        break
                    trace.extend(data)
            if len(trace) >= 262144:
                errors.append('trace byte limit reached')
        except Exception as error:
            errors.append(str(error))
            ready.set()
        finally:
            if fd is not None:
                os.close(fd)

    try:
        if not report['usbmon_loaded_before']:
            report['module_load'] = command(['modprobe', 'usbmon'])
            loaded = Path('/sys/module/usbmon').exists()
            if report['module_load']['rc'] or not loaded:
                raise RuntimeError('usbmon not available')
        reader = threading.Thread(target=collect, name='one-sequential-echo-usbmon')
        reader.start()
        if not ready.wait(2) or errors:
            raise RuntimeError('trace not ready: ' + repr(errors))
        transport = probe['transact'](payload, bus, dev, read_seconds=1 if is_small or kind in ('drain_comment', 'pattern_read', 'pattern_short', 'pattern_63tick') else (15 if kind in ('drain_only', 'terminate_line') else (2 if kind == 'drain_zlp' else (4 if kind == 'echo' else (6 if kind == 'persistent' else (15 if kind == 'lcd_pair' else 8))))),
                                      prime_device_id=True, sequential_readback=True,
                                      sequential_kind='echo' if kind == 'persistent' else kind,
                                      forward_gap_seconds=1.0 if kind in ('lcd_single', 'tcl_flush', 'lcd_pair') else (0.25 if is_small or kind in ('echo_framed', 'echo_pair', 'drain_comment', 'pattern_read', 'pattern_short', 'pattern_63tick') else 0.005),
                                      read_packet_mode=is_small or kind in ('tcl_flush', 'lcd_pair', 'persistent', 'drain_zlp', 'terminate_line', 'echo_framed', 'echo_pair', 'drain_comment', 'pattern_read', 'pattern_short', 'pattern_63tick'),
                                      persistent_sequence=kind == 'persistent', finish_on_short=finish_on_short)
        report['transport'] = transport
        raw = base64.b64decode(transport['received_base64'])
        if kind in ('drain_zlp', 'drain_only', 'status_only', 'terminate_line', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle', 'drain_comment'):
            report['commands_enqueued'] = 0
            report['fresh_lcd_received'] = None
            if kind == 'drain_comment':
                report['comment_packets_sent'] = transport['write_attempts']
                report['commands_enqueued'] = transport['write_attempts']
                report['new_response_requested'] = False
        elif is_small:
            report['small_read_validation'] = probe['extract_small_read'](raw, nonce)
        elif kind in ('pattern_read', 'pattern_short', 'pattern_63tick'):
            report['pattern_validation'] = probe['validate_pattern'](raw, nonce, 64 if kind == 'pattern_short' else 1024)
        elif kind in ('echo', 'echo_framed', 'echo_pair', 'persistent'):
            report['echo_validation'] = probe['classify_echo'](raw, nonce, payload)
            report['fresh_echo_received'] = (transport['write_completed']
                and transport['cleanup_verified']
                and report['echo_validation']['pjl_echo_frame_valid'])
            if kind == 'echo_pair':
                report['echo_pair_validation'] = [probe['classify_echo'](raw, n,
                    probe['make_echo_framed_query'](n)) for n in (nonce, nonce[::-1])]
        elif kind in ('tcl_ping', 'tcl_flush'):
            report['fresh_tcl_reply'] = bool(re.search(
                rb'(?:\A|[\r\n])'+nonce.encode()+rb'\r?\n', raw)) and probe['UEL'] not in raw
        elif kind == 'lcd_single':
            report['lcd_markers_verified'] = None
            report['fresh_lcd_received'] = None
            report['lcd_decode_status'] = 'pending geometric validation; no in-band nonce in this fixed one-packet script'
        else:
            begin = re.search(rb'(?:\A|[\r\n])B'+nonce.encode()+rb'\r?\n', raw)
            end = re.search(rb'(?:\A|[\r\n])(E'+nonce.encode()+rb')\r?\n', raw)
            report['lcd_markers_verified'] = bool(begin and end and begin.end() < end.start())
            report['fresh_lcd_received'] = None
            report['lcd_decode_status'] = 'pending validation on PC20'
            if report['lcd_markers_verified']:
                body = raw[begin.end():end.start(1)]
                report['lcd_body_base64'] = base64.b64encode(body).decode('ascii')
                report['lcd_body_bytes'] = len(body)
                # Image decoding on PC20 is required before accepting the frame.
    except Exception as error:
        report['error'] = str(error)
    finally:
        time.sleep(0.1)
        stop.set()
        if reader is not None:
            reader.join(2)
        report['cleanup']['reader_closed'] = reader is None or not reader.is_alive()
        lines = []
        for line in trace.decode('ascii', 'backslashreplace').splitlines():
            address = address_of(line)
            if address and address[2:4] == (bus, dev):
                lines.append(line)
        report['trace'] = '\n'.join(lines)
        report['trace_reader_errors'] = errors
        if loaded:
            report['module_unload'] = command(['modprobe', '-r', 'usbmon'])
        report['cleanup']['usbmon_loaded_after'] = Path('/sys/module/usbmon').exists()
        after = support['snapshot'](class_read=False)
        report['postflight'] = after
        same = [x for x in after['adapters'] if x['path'] == adapter['path']]
        report['cleanup']['verified'] = (len(same) == 1
            and all(same[0][key] == adapter[key] for key in
                    ('alternate', 'driver', 'descriptor_sha256', 'busnum', 'devnum'))
            and report['cleanup']['reader_closed']
            and report['cleanup']['usbmon_loaded_after'] == report['usbmon_loaded_before']
            and after['cups']['unfinished_job_ids'] == []
            and after['usb_handles']['inspection_complete']
            and not after['usb_handles']['open_handles'])
    return report
