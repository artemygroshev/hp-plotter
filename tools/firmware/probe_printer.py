"""Bounded PJL readback probe for the identified BTT and USB-parallel bridge.

Defaults to an offline preview. --send requires an observed idle panel state.
Ready or a stationary Replace ink cartridges warning permits these read queries;
neither permits a print or settings change through this tool.
No print data, firmware, persistent configuration or arbitrary script input.
The resumed repair phase adds explicitly selected, targeted USB interface recovery.
The bridge's temporary alternate setting is restored and read back before release.
"""
import argparse
import base64
import ctypes as C
import ctypes.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
from status_snapshot import ADAPTER_DESCRIPTOR_SHA256, MACHINE_ID, parse_device_id
from status_snapshot import adapter_open_handles, adapters
import hashlib

UEL = b'\x1b%-12345X'


def make_query(kind, nonce):
    if not re.fullmatch(r'[A-Za-z0-9]{8,64}', nonce):
        raise ValueError('nonce must be 8..64 alphanumeric characters')
    command = ('@PJL ECHO BTT_' + nonce if kind == 'echo' else '@PJL INFO ID')
    if kind not in ('echo', 'id'):
        raise ValueError('only ECHO and INFO ID are implemented')
    return UEL + b'@PJL\r\n' + command.encode('ascii') + b'\r\n' + UEL


def make_lcd_query(nonce):
    """Fixed read-only LCD script; kept below the bridge's observed 128B FIFO."""
    if not re.fullmatch(r'[a-f0-9]{16}', nonce):
        raise ValueError('LCD nonce must be exactly 16 lowercase hex characters')
    script = ('puts B'+nonce+'\nfpDumpDisplay BMP\nputs "\\nE'+nonce+'"\nexit 0\n').encode('ascii')
    payload = UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script + UEL
    if len(payload) > 128:
        raise ValueError('LCD query exceeds the short-request bound')
    return payload


def make_echo_framed_query(nonce):
    """One 64-byte PJL read query with CRLF after the closing UEL."""
    payload = make_query('echo', nonce)[:-len(UEL)] + b'\r\n'*3 + UEL + b'\r\n'
    if len(payload) != 64:
        raise ValueError('framed ECHO requires the 16-hex nonce and exactly 64 bytes')
    return payload


def make_drain_comment(length=64):
    """A whole-packet PJL COMMENT: no request for additional printer output."""
    if length not in (63, 64):
        raise ValueError('only adjacent whole/short USB packet bounds are implemented')
    prefix = UEL + b'@PJL\r\n@PJL COMMENT BTT_READ_DRAIN'
    tail = b'\r\n' + UEL + b'\r\n'
    return prefix + b' '*(length-len(prefix)-len(tail)) + tail


def make_pattern_query(nonce, width=1024):
    """Known 1041-byte output, generated in RAM by Tcl; no printer settings."""
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('pattern nonce must be six hex characters')
    if width not in (64, 1024):
        raise ValueError('only two bounded output sizes are implemented')
    script = ('puts B'+nonce+'\nputs [format %'+str(width)+'s '+nonce+']\nputs E'+nonce+'\nexit\n').encode('ascii')
    prefix = UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail = b'\n'+UEL+b'\r\n'
    return prefix+b'#'+b' '*(128-len(prefix)-1-len(tail))+tail


def validate_pattern(raw, nonce, width=1024):
    begin = b'B'+nonce.encode()+b'\n'
    end = b'E'+nonce.encode()+b'\n'
    starts = [m.end() for m in re.finditer(rb'(?:\A|\n)'+re.escape(begin), raw)]
    ends = [m.start() for m in re.finditer(re.escape(end), raw)]
    expected = b' '*(width-len(nonce))+nonce.encode()+b'\n'
    return {'begin_markers': len(starts), 'end_markers': len(ends),
            'expected_body_bytes': len(expected),
            'exact_body_received': (len(starts) == len(ends) == 1
                and raw[starts[0]:ends[0]] == expected)}


SMALL_READ_COMMANDS = {
    'fw_info': b'puts [sysGetFwRevision]',
    'rom_probe': b'osMemDump 0xa017d468 16',
    'rom_flush': b'flush stdout\nafter 99\nosMemDump 0xa017d468 96',
    # A04 getter code (96 bytes) matched the pinned image in live memory.
    # This exact function only returns display 0; never accept arbitrary calls.
    'lcd_pointer': b'puts [osFuncCall 0xa017d468 1 0]',
    'lcd_pointer_tagged': b'puts "P@NONCE@ [osFuncCall 0xa017d468 1 0]"',
    'telemetry_serial': b'puts R@NONCE@_[sysODBGet DEV-SERIAL-NUMBER s]',
    'telemetry_error': b'puts R@NONCE@_[sysODBGet ERROR-STATE u]',
    'fw_info_tagged': b'puts F@NONCE@_[sysGetFwRevision]',
    'telemetry_part': b'puts R@NONCE@_[sysODBGet DEV-PART-NUMBER s]',
    'telemetry_model': b'puts R@NONCE@_[sysODBGet DEV-PRODUCT-NAME s]',
    'telemetry_ram': b'puts R@NONCE@_[sysODBGet DRAM-INSTALLED u]',
    'telemetry_media': b'puts R@NONCE@_[sysODBGet FP-MEDIA-NAME s]',
    'telemetry_ink_out': b'puts R@NONCE@_[sysODBGet IO-STATUS-INK-OUT b]',
    'telemetry_head_0': b'puts R@NONCE@_[sysODBGet PH-USER-STATUS-0 u]',
    'telemetry_color_0': b'puts R@NONCE@_[sysODBGet IDSSET-COLOR-0 u]',
    'telemetry_cartridge_0': b'puts R@NONCE@_[sysODBGet CRTGE-STATUS-0 u]',
    'telemetry_level_0': b'puts R@NONCE@_[sysODBGet CRTGE-LEVEL-0 u]',
    'telemetry_head_1': b'puts R@NONCE@_[sysODBGet PH-USER-STATUS-1 u]',
    'telemetry_color_1': b'puts R@NONCE@_[sysODBGet IDSSET-COLOR-1 u]',
    'telemetry_cartridge_1': b'puts R@NONCE@_[sysODBGet CRTGE-STATUS-1 u]',
    'telemetry_level_1': b'puts R@NONCE@_[sysODBGet CRTGE-LEVEL-1 u]',
    'telemetry_head_2': b'puts R@NONCE@_[sysODBGet PH-USER-STATUS-2 u]',
    'telemetry_color_2': b'puts R@NONCE@_[sysODBGet IDSSET-COLOR-2 u]',
    'telemetry_cartridge_2': b'puts R@NONCE@_[sysODBGet CRTGE-STATUS-2 u]',
    'telemetry_level_2': b'puts R@NONCE@_[sysODBGet CRTGE-LEVEL-2 u]',
    'telemetry_head_3': b'puts R@NONCE@_[sysODBGet PH-USER-STATUS-3 u]',
    'telemetry_color_3': b'puts R@NONCE@_[sysODBGet IDSSET-COLOR-3 u]',
    'telemetry_cartridge_3': b'puts R@NONCE@_[sysODBGet CRTGE-STATUS-3 u]',
    'telemetry_level_3': b'puts R@NONCE@_[sysODBGet CRTGE-LEVEL-3 u]',
    # Existing A04 ODB fields, independently of the simplified user status.
    'telemetry_head_native_0': b'puts R@NONCE@_[sysODBGet PH-STATUS-0 u]',
    'telemetry_head_model_0': b'puts R@NONCE@_[sysODBGet PH-MODEL-0 u]',
    'telemetry_head_native_1': b'puts R@NONCE@_[sysODBGet PH-STATUS-1 u]',
    'telemetry_head_model_1': b'puts R@NONCE@_[sysODBGet PH-MODEL-1 u]',
    'telemetry_head_native_2': b'puts R@NONCE@_[sysODBGet PH-STATUS-2 u]',
    'telemetry_head_model_2': b'puts R@NONCE@_[sysODBGet PH-MODEL-2 u]',
    'telemetry_head_native_3': b'puts R@NONCE@_[sysODBGet PH-STATUS-3 u]',
    'telemetry_head_model_3': b'puts R@NONCE@_[sysODBGet PH-MODEL-3 u]',
    'lcd_direct': b'fpDumpDisplay BMP',
}


def make_small_read_query(kind, nonce):
    if kind not in SMALL_READ_COMMANDS or not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('only fixed, short read-only service queries are implemented')
    command = SMALL_READ_COMMANDS[kind].replace(b'@NONCE@', nonce.encode())
    script = b'puts B'+nonce.encode()+b'\n'+command+b'\nputs E'+nonce.encode()+b'\nexit\n'
    prefix = UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail = b'\n'+UEL+b'\r\n'
    if len(prefix)+len(tail)+1 > 128:
        raise ValueError('fixed query exceeds two packets')
    return prefix+b'#'+b' '*(128-len(prefix)-1-len(tail))+tail


def extract_small_read(raw, nonce):
    starts = [m.end() for m in re.finditer(rb'(?:\A|\n)B'+nonce.encode()+rb'\n', raw)]
    ends = [m.start() for m in re.finditer(rb'(?:\A|\n)E'+nonce.encode()+rb'\n', raw)]
    body = raw[starts[0]:ends[0]+1] if len(starts) == len(ends) == 1 and ends[0] >= starts[0]-1 else b''
    valid = len(starts) == len(ends) == 1 and 0 < len(body) < 4096 and UEL not in body and b'@PJL' not in body
    return {'framing_verified': valid, 'body_base64': base64.b64encode(body).decode() if valid else '',
            'begin_markers': len(starts), 'end_markers': len(ends)}


def make_tcl_ping_query(nonce):
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('Tcl ping nonce must be exactly 6 lowercase hex characters')
    payload = (UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n'
               + ('puts '+nonce+'\nexit\n').encode('ascii') + UEL)
    if len(payload) != 64:
        raise ValueError('Tcl ping must occupy exactly one full USB packet')
    return payload


def make_lcd_single_query():
    # PJL permits LF line termination. UEL supplies the input end-of-job;
    # the observed Tcl runtime handles input EOF and closes its FILE/channel.
    payload = UEL + b'@PJL ENTER LANGUAGE=TCLWARE\nfpDumpDisplay BMP\n' + UEL
    if len(payload) != 64:
        raise ValueError('single LCD query must occupy one full USB packet')
    return payload


def make_tcl_flush_query(nonce):
    """Read-only marker, explicit Tcl flush and exit; full two-packet request."""
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('Tcl flush nonce must be six hex characters')
    prefix = UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n'
    script = ('puts '+nonce+'\nflush stdout\nexit\n').encode('ascii')
    # Pad before UEL with whitespace only. No arbitrary script input.
    payload = prefix + script
    payload += b' ' * (128 - len(payload) - len(UEL)) + UEL
    if len(payload) != 128:
        raise ValueError('fixed full-packet bound changed')
    return payload


def make_lcd_pair_query(nonce):
    """Two read-only frames in one script to expose buffering, no reconnect."""
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('LCD pair nonce must be six hex characters')
    script = ('puts B'+nonce+'\nfpDumpDisplay BMP\nfpDumpDisplay BMP\n'
              'puts E'+nonce+'\nflush stdout\nexit\n').encode('ascii')
    payload = UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
    payload += b' ' * (128 - len(payload) - len(UEL)) + UEL
    if len(payload) != 128:
        raise ValueError('LCD pair full-packet bound changed')
    return payload


def classify_echo(raw, nonce, payload):
    marker = b'@PJL ECHO BTT_' + nonce.encode('ascii')
    framed = re.search(rb'(?:\A|[\r\n\f])' + re.escape(marker) + rb'\r?\n\f', raw)
    loopback = payload in raw or UEL in raw
    return {'pjl_echo_frame_valid': bool(framed) and not loopback,
            'echo_marker_seen': marker in raw,
            'input_loopback_suspected': loopback,
            'printer_identity_verified': False}


def validate_descriptors(data):
    endpoints = set(); selected = False; found = False; offset = 0
    while offset < len(data):
        if offset+2 > len(data): raise ValueError('truncated USB descriptor')
        length, kind = data[offset:offset+2]
        if length < 2 or offset+length > len(data):
            raise ValueError('invalid USB descriptor length')
        part = data[offset:offset+length]
        if kind == 4:
            if length < 9: raise ValueError('truncated interface descriptor')
            selected = part[2:4] == bytes([0, 1])
            if selected:
                if part[5:8] != bytes([7, 1, 2]):
                    raise ValueError('unexpected alt1 printer protocol')
                found = True
        elif kind == 5 and selected:
            if length < 7: raise ValueError('truncated endpoint descriptor')
            if part[3] & 3 == 2: endpoints.add(part[2])
        offset += length
    if not found or not {0x01, 0x82}.issubset(endpoints):
        raise ValueError('recorded bidirectional bulk endpoints not present')


def discover():
    if Path('/etc/machine-id').read_text().strip() != MACHINE_ID:
        raise RuntimeError('this probe targets the recorded BTT, not this machine')
    q = subprocess.run(['lpstat', '-W', 'not-completed', '-o', 'HP-DesignJet-500'],
                       capture_output=True, text=True, timeout=5)
    if q.returncode or q.stdout.strip():
        raise RuntimeError('CUPS queue is nonempty or cannot be checked')
    devices = []
    for p in Path('/sys/bus/usb/devices').glob('*'):
        try:
            if ((p/'idVendor').read_text().strip(), (p/'idProduct').read_text().strip()) == ('1a86', '7584'):
                devices.append(p)
        except (FileNotFoundError, NotADirectoryError):
            continue
    if (len(devices) != 1 or hashlib.sha256((devices[0]/'descriptors').read_bytes()).hexdigest()
            != ADAPTER_DESCRIPTOR_SHA256):
        raise RuntimeError('recorded adapter descriptor not uniquely identified')
    if (devices[0]/'bConfigurationValue').read_text().strip() != '1':
        raise RuntimeError('unexpected adapter configuration')
    validate_descriptors((devices[0]/'descriptors').read_bytes())
    owners = adapter_open_handles(adapters())
    if owners['open_handles'] or not owners['inspection_complete']:
        raise RuntimeError('USB/printer device already open, or ownership inspection incomplete')
    return int((devices[0]/'busnum').read_text()), int((devices[0]/'devnum').read_text())


def observe_host_alt(bus, address):
    found = []
    for p in Path('/sys/bus/usb/devices').glob('*'):
        try:
            if (int((p/'busnum').read_text()), int((p/'devnum').read_text())) == (bus, address):
                found.append(int((p.parent/(p.name+':1.0')/'bAlternateSetting').read_text(), 16))
        except (FileNotFoundError, NotADirectoryError):
            continue
    if len(found) != 1: raise RuntimeError('host alternate setting not uniquely identified')
    return found[0]


def transact(payload, bus, address, lib=None, now=None, alt_observer=None,
             concurrent_read=False, read_seconds=4, prime_device_id=False,
             sequential_readback=False, sequential_kind='echo', forward_gap_seconds=0.005, read_packet_mode=False, persistent_sequence=False, finish_on_short=False):
    if not 1 <= read_seconds <= 15:
        raise ValueError('read_seconds must be within 1..15')
    if forward_gap_seconds not in (0.005, 0.25, 1.0):
        raise ValueError('forward/reverse gap is outside the three bounded experiments')
    if finish_on_short and not (sequential_readback and read_packet_mode and sequential_kind in SMALL_READ_COMMANDS):
        raise ValueError('short packet boundaries require a fixed small read and packet mode')
    if sequential_readback:
        echo_pattern = (re.escape(UEL) + rb'@PJL\r\n@PJL ECHO BTT_[A-Za-z0-9]{8,16}\r\n'
                        + re.escape(UEL))
        valid_payload = False
        if sequential_kind == 'echo':
            valid_payload = bool(re.fullmatch(echo_pattern, payload))
        elif sequential_kind in ('echo_framed', 'echo_pair'):
            marker = re.search(rb'BTT_([a-f0-9]{16})', payload)
            if marker:
                valid_payload = payload == make_echo_framed_query(marker[1].decode('ascii'))
        elif sequential_kind == 'lcd':
            marker = re.search(rb'\nputs B([a-f0-9]{16})\n', payload)
            # The script immediately follows CRLF; accept that exact boundary.
            if marker is None:
                marker = re.search(rb'\r\nputs B([a-f0-9]{16})\n', payload)
            if marker:
                valid_payload = payload == make_lcd_query(marker[1].decode('ascii'))
        elif sequential_kind == 'tcl_ping':
            marker = re.search(rb'\r\nputs ([a-f0-9]{6})\n', payload)
            if marker:
                valid_payload = payload == make_tcl_ping_query(marker[1].decode('ascii'))
        elif sequential_kind == 'lcd_single':
            valid_payload = payload == make_lcd_single_query()
        elif sequential_kind == 'terminate_line':
            valid_payload = payload == b'\n'
        elif sequential_kind == 'drain_comment':
            valid_payload = payload == make_drain_comment()
        elif sequential_kind in ('pattern_read', 'pattern_short', 'pattern_63tick'):
            marker = re.search(rb'puts B([a-f0-9]{6})\n', payload)
            if marker:
                valid_payload = payload == make_pattern_query(marker[1].decode('ascii'), 64 if sequential_kind == 'pattern_short' else 1024)
        elif sequential_kind in SMALL_READ_COMMANDS:
            marker = re.search(rb'puts B([a-f0-9]{6})\n', payload)
            if marker:
                valid_payload = payload == make_small_read_query(sequential_kind, marker[1].decode('ascii'))
        elif sequential_kind in ('drain_only', 'drain_zlp', 'status_only', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle'):
            valid_payload = payload == b''
        elif sequential_kind == 'lcd_pair':
            marker = re.search(rb'\r\nputs B([a-f0-9]{6})\n', payload)
            if marker:
                valid_payload = payload == make_lcd_pair_query(marker[1].decode('ascii'))
        elif sequential_kind == 'tcl_flush':
            marker = re.search(rb'\r\nputs ([a-f0-9]{6})\n', payload)
            if marker:
                valid_payload = payload == make_tcl_flush_query(marker[1].decode('ascii'))
        if not prime_device_id or concurrent_read or not valid_payload:
            raise ValueError('sequential experiment requires a fixed short read query, fresh ID, no concurrent IN')
    if persistent_sequence:
        if not (sequential_readback and sequential_kind == 'echo' and read_packet_mode):
            raise ValueError('persistent sequence requires validated sequential ECHO and packet reads')
        initial_nonce = re.search(rb'BTT_([a-f0-9]{16})', payload)
        if not initial_nonce:
            raise ValueError('persistent sequence nonce missing')
        initial_nonce = initial_nonce[1].decode('ascii')
        sequence = [('echo_before', payload),
                    ('lcd_pair', make_lcd_pair_query(initial_nonce[:6])),
                    ('echo_after', make_query('echo', initial_nonce[::-1]))]
    elif sequential_kind == 'echo_pair':
        nonce = re.search(rb'BTT_([a-f0-9]{16})', payload)[1].decode('ascii')
        sequence = [('echo_first', payload), ('echo_second', make_echo_framed_query(nonce[::-1]))]
    elif sequential_kind == 'drain_comment':
        sequence = [('comment_tick_'+str(i+1), payload) for i in range(8)]
    elif sequential_kind in ('pattern_read', 'pattern_short', 'pattern_63tick'):
        pattern_nonce = re.search(rb'puts B([a-f0-9]{6})\n', payload)[1].decode('ascii')
        pattern_width = 64 if sequential_kind == 'pattern_short' else 1024
        sequence = [('known_pattern', payload)]+[('comment_tick_'+str(i+1), make_drain_comment(63 if sequential_kind == 'pattern_63tick' else 64)) for i in range(8)]
    elif sequential_kind in SMALL_READ_COMMANDS:
        small_nonce = re.search(rb'puts B([a-f0-9]{6})\n', payload)[1].decode('ascii')
        sequence = [(sequential_kind, payload)]+[('comment_tick_'+str(i+1), make_drain_comment()) for i in range(8)]
    elif sequential_kind in ('drain_only', 'status_only', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle'):
        sequence = []
    elif sequential_kind == 'drain_zlp':
        sequence = [('zero_length_transport_'+str(i), b'') for i in range(8)]
    else:
        sequence = [(sequential_kind, payload)]
    if lib is None:
        lib = C.CDLL(ctypes.util.find_library('usb-1.0'))
        if alt_observer is None: alt_observer = lambda: observe_host_alt(bus, address)
    if now is None: now = time.monotonic
    def fn(name, args, result):
        f = getattr(lib, name); f.argtypes = args; f.restype = result
        return f
    ptr, integer = C.c_void_p, C.c_int
    init = fn('libusb_init', [C.POINTER(ptr)], integer)
    leave = fn('libusb_exit', [ptr], None)
    op = fn('libusb_open_device_with_vid_pid', [ptr, C.c_uint16, C.c_uint16], ptr)
    close = fn('libusb_close', [ptr], None)
    device = fn('libusb_get_device', [ptr], ptr)
    get_bus = fn('libusb_get_bus_number', [ptr], C.c_uint8)
    get_address = fn('libusb_get_device_address', [ptr], C.c_uint8)
    auto = fn('libusb_set_auto_detach_kernel_driver', [ptr, integer], integer)
    active = fn('libusb_kernel_driver_active', [ptr, integer], integer)
    claim = fn('libusb_claim_interface', [ptr, integer], integer)
    release = fn('libusb_release_interface', [ptr, integer], integer)
    alternate = fn('libusb_set_interface_alt_setting', [ptr, integer, integer], integer)
    control = fn('libusb_control_transfer', [ptr, C.c_uint8, C.c_uint8, C.c_uint16,
                  C.c_uint16, ptr, C.c_uint16, C.c_uint], integer)
    bulk = fn('libusb_bulk_transfer', [ptr, C.c_ubyte, ptr, integer,
                                      C.POINTER(integer), C.c_uint], integer)
    ctx = ptr(); handle = None; claimed = False; previous = None; alt_attempted = False
    kernel_before = None
    reader = None; response = bytearray(); reader_result = {}
    result = {'write_attempts': 0, 'written_bytes': 0, 'write_completed': False,
              'received_base64': '', 'prequery_received_base64': '',
              'cleanup': {}, 'cleanup_verified': False}
    def read_alt():
        current = C.c_ubyte()
        rc = control(handle, 0x81, 10, 0, 0, C.byref(current), 1, 1000)
        if rc != 1: raise RuntimeError(('GET_INTERFACE', rc))
        host = alt_observer() if alt_observer is not None else None
        report = {'device_get_interface': current.value, 'host_sysfs': host}
        # This recorded bridge returns 0 even after a successful SETINTERFACE.
        # Linux's independently observed setting controls host endpoint access;
        # neither observation alone proves the parallel negotiation succeeded.
        if host is not None and host != current.value:
            report['device_host_disagreement'] = True
        return (host if host is not None else current.value), report
    def read_response():
        # long_drain is one explicitly bounded 30s IN, with no outgoing data.
        # Other modes use the shorter loop deadline and cancellable reads.
        rxbuf = C.create_string_buffer(16384 if sequential_kind == 'long_drain' else (512 if sequential_kind in ('drain_only', 'terminate_line') else (64 if read_packet_mode else 16384)))
        result['reverse_request_bytes'] = len(rxbuf)
        result['reverse_timeout_ms'] = 30000 if sequential_kind == 'long_drain' else (5000 if sequential_kind in ('drain_only', 'terminate_line') else (1000 if read_packet_mode else 200))
        deadline = now() + read_seconds
        phase_start = len(response)
        try:
            while now() < deadline and len(response) < 65536:
                rxcount = integer()
                rc = bulk(handle, 0x82, rxbuf, min(len(rxbuf), 65536-len(response)),
                          C.byref(rxcount), result['reverse_timeout_ms'])
                if rxcount.value: response.extend(rxbuf.raw[:rxcount.value])
                if finish_on_short and rc == 0 and rxcount.value < len(rxbuf):
                    result.setdefault('short_packet_boundaries', []).append(len(response))
                    break
                if finish_on_short and sequential_kind == 'lcd_direct' and len(response)-phase_start >= 1024:
                    # A04's FILE writer emits 1 KiB blocks. Do not leave an
                    # additional IN pending beyond that exact block boundary.
                    result.setdefault('native_block_boundaries', []).append(len(response))
                    break
                if sequential_kind == 'long_drain':
                    reader_result['single_long_read_rc'] = rc
                    break
                if rc not in (0, -7):
                    reader_result['read_error'] = rc
                    break
        except Exception as e:
            reader_result['read_error'] = str(e)
    rc = init(C.byref(ctx))
    if rc: raise RuntimeError(('libusb_init', rc))
    try:
        handle = op(ctx, 0x1a86, 0x7584)
        if not handle: raise RuntimeError('cannot open adapter')
        dev = device(handle)
        if (get_bus(dev), get_address(dev)) != (bus, address):
            raise RuntimeError('adapter changed since sysfs identification')
        kernel_before = active(handle, 0)
        result['kernel_active_before'] = kernel_before
        if kernel_before not in (0, 1):
            raise RuntimeError(('kernel_driver_state_unknown', kernel_before))
        if kernel_before:
            rc = auto(handle, 1)
            if rc: raise RuntimeError(('auto_detach', rc))
        rc = claim(handle, 0)
        if rc: raise RuntimeError(('claim', rc))
        claimed = True
        previous, result['initial_alt_report'] = read_alt()
        result['previous_alt'] = previous
        if previous != 1:
            alt_attempted = True
            rc = alternate(handle, 0, 1)
            if rc: raise RuntimeError(('select_bidi_alt1', rc))
        selected, result['selected_alt_report'] = read_alt()
        if selected != 1:
            raise RuntimeError(('bidi_alt_not_confirmed', selected))
        if prime_device_id:
            result['device_id_attempts_before_query'] = []
            for attempt in range(2):
                ident = C.create_string_buffer(1024)
                rc = control(handle, 0xa1, 0, 0, 1, ident, len(ident), 5000)
                raw = ident.raw[:max(0, rc)]
                result['device_id_before_query'] = {'rc': rc, 'hex': raw.hex()}
                result['device_id_attempts_before_query'].append(result['device_id_before_query'])
                # Observed on this bridge: a zero-byte ID can be immediately
                # followed by the correct 158-byte reply. Retry only that
                # explicit empty control read, once, never an error or write.
                if (rc != 0 or not sequential_readback or sequential_kind in
                        ('drain_only', 'drain_zlp', 'status_only', 'terminate_line',
                         'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle')):
                    break
                time.sleep(0.005)
            if rc < 0: raise RuntimeError(('GET_DEVICE_ID_before_query', rc))
            if (sequential_readback and sequential_kind not in ('drain_only', 'status_only', 'terminate_line', 'long_drain', 'endpoint_recover', 'class_reset', 'id_cycle')
                    and not parse_device_id(raw)['hp_c7769b_identified']):
                raise RuntimeError('fresh DesignJet C7769B identity not confirmed; no OUT sent')
        if sequential_kind == 'id_cycle':
            result['interface_cycle_ids'] = []
            for label, cycle in (('same_alt_repeat', False), ('after_alt0_alt1', True)):
                if cycle:
                    alt_attempted = True
                    for setting in (0, 1):
                        cycle_rc = alternate(handle, 0, setting)
                        result.setdefault('id_cycle_alt_results', []).append({'alt': setting, 'rc': cycle_rc})
                        if cycle_rc:
                            raise RuntimeError(('id_cycle_alternate', setting, cycle_rc))
                    observed, observation = read_alt()
                    result['id_cycle_alt_report'] = observation
                    if observed != 1:
                        raise RuntimeError('id cycle host alt not confirmed')
                ident = C.create_string_buffer(1024)
                rc = control(handle, 0xa1, 0, 0, 1, ident, 1024, 5000)
                result['interface_cycle_ids'].append({'phase': label, 'rc': rc,
                    'decoded': parse_device_id(ident.raw[:max(0, rc)])})
        if sequential_kind == 'class_reset':
            result['usb_interface_reset_requests'] = []
            # USB Printer Class 1.1 and CUPS: recipient OTHER first, then
            # INTERFACE only on an explicit STALL (never replay a timeout).
            for bm in (0x23, 0x21):
                rc = control(handle, bm, 2, 0, 0, None, 0, 2000)
                result['usb_interface_reset_requests'].append({
                    'bmRequestType': bm, 'bRequest': 2, 'wValue': 0,
                    'wIndex': 0, 'wLength': 0, 'rc': rc})
                if rc != -9:
                    break
            time.sleep(0.25)
            ident = C.create_string_buffer(1024)
            rc = control(handle, 0xa1, 0, 0, 1, ident, 1024, 5000)
            result['device_id_after_interface_reset'] = {'rc': rc,
                'decoded': parse_device_id(ident.raw[:max(0, rc)])}
        if sequential_kind == 'endpoint_recover':
            result['endpoint_recovery'] = []
            for endpoint in (0x01, 0x82):
                state = C.create_string_buffer(2)
                rc = control(handle, 0x82, 0, 0, endpoint, state, 2, 1000)
                row = {'endpoint': endpoint, 'get_status_rc': rc,
                       'status_hex': state.raw[:max(0, rc)].hex(),
                       'clear_halt_sent': False}
                result['endpoint_recovery'].append(row)
                if rc == 2 and int.from_bytes(state.raw, 'little') == 1:
                    # Standard CLEAR_FEATURE(ENDPOINT_HALT), only after the
                    # device positively reports a halt. Never reset the device.
                    clear = fn('libusb_clear_halt', [ptr, C.c_ubyte], integer)
                    row['clear_halt_sent'] = True
                    row['clear_halt_rc'] = clear(handle, endpoint)
                    after = C.create_string_buffer(2)
                    row['post_status_rc'] = control(handle, 0x82, 0, 0, endpoint,
                                                    after, 2, 1000)
                    row['post_status_hex'] = after.raw[:max(0, row['post_status_rc'])].hex()
            ident = C.create_string_buffer(1024)
            rc = control(handle, 0xa1, 0, 0, 1, ident, 1024, 5000)
            result['device_id_after_endpoint_check'] = {'rc': rc,
                'decoded': parse_device_id(ident.raw[:max(0, rc)])}
        if sequential_kind == 'status_only':
            status_requests = []
            result['status_requests'] = status_requests
            for bm, request, index, length in ((0x80, 0, 0, 2),
                                                (0xa1, 1, 0, 1),
                                                (0xa1, 1, 1, 1)):
                statusbuf = C.create_string_buffer(length)
                rc = control(handle, bm, request, 0, index, statusbuf, length, 1000)
                status_requests.append({'bmRequestType': bm, 'bRequest': request,
                    'wIndex': index, 'wLength': length, 'rc': rc,
                    'actual_hex': statusbuf.raw[:max(0, rc)].hex()})
        buf = C.create_string_buffer(16384)
        stale = bytearray()
        # Bound both time and bytes. A stalled reverse endpoint aborts before OUT.
        if not sequential_readback:
            drain_until = now() + 1
            while now() < drain_until and len(stale) < 65536:
                count = integer()
                rc = bulk(handle, 0x82, buf, min(len(buf), 65536-len(stale)), C.byref(count), 100)
                if count.value:
                    stale.extend(buf.raw[:count.value])
                    result['prequery_received_base64'] = base64.b64encode(stale).decode()
                if rc == -7: break
                if rc: raise RuntimeError(('reverse_endpoint_before_query', rc))
            else:
                raise RuntimeError('reverse endpoint did not become quiet')
        result['prequery_bulk_read_performed'] = not sequential_readback
        result['discarded_stale_bytes'] = len(stale)
        if concurrent_read:
            reader = threading.Thread(target=read_response, name='bounded-printer-read')
            reader.start()
            result['concurrent_read'] = True
        if sequential_kind in ('drain_only', 'long_drain'):
            read_response()
        phases = []
        result['phases'] = phases
        quiet_comment_phases = 0
        quiet_small_phases = 0
        for phase_name, phase_payload in sequence:
            offset = len(response)
            send = C.create_string_buffer(phase_payload)
            count = integer()
            result['write_attempts'] += 1
            rc = bulk(handle, 0x01, send, len(phase_payload), C.byref(count), 1500)
            phase = {'name': phase_name, 'payload_hex': phase_payload.hex(),
                     'write_rc': rc, 'written_bytes': count.value,
                     'response_offset': offset}
            phases.append(phase)
            result['write_rc'] = rc
            result['written_bytes'] += count.value
            # Never replay a query after a partial/failed write.
            if rc or count.value != len(phase_payload):
                result['write_completed'] = False
                raise RuntimeError('query write incomplete; no automatic retry')
            result['write_completed'] = True
            if sequential_readback:
                time.sleep(forward_gap_seconds)
                result['sequential_readback'] = True
                result['forward_reverse_gap_seconds'] = forward_gap_seconds
            if not concurrent_read:
                read_response()
            phase['received_bytes'] = len(response) - offset
            if sequential_kind in SMALL_READ_COMMANDS:
                small = extract_small_read(bytes(response), small_nonce)
                result['small_read_validation'] = small
                end_seen = bool(re.search(rb'(?:\A|\n)E'+small_nonce.encode()+rb'\n', bytes(response)))
                result['small_end_nonce_received'] = end_seen
                quiet_small_phases = quiet_small_phases+1 if end_seen and phase['received_bytes'] == 0 else 0
                if quiet_small_phases == 2:
                    result['small_stopped_after_end_and_two_quiet_phases'] = True
                    break
            if sequential_kind in ('pattern_read', 'pattern_short', 'pattern_63tick') and validate_pattern(bytes(response), pattern_nonce, pattern_width)['exact_body_received']:
                result['pattern_validation'] = validate_pattern(bytes(response), pattern_nonce, pattern_width)
                break
            if sequential_kind == 'drain_comment':
                quiet_comment_phases = quiet_comment_phases+1 if phase['received_bytes'] == 0 else 0
                if quiet_comment_phases == 2:
                    result['drain_stopped_after_two_quiet_phases'] = True
                    break
            if reader_result.get('read_error'):
                break

    except Exception as e:
        result['error'] = str(e)
    finally:
        # Never restore/release/close while a bounded read still uses this handle.
        if reader is not None: reader.join()
        result.update(reader_result)
        result['received_base64'] = base64.b64encode(response).decode()
        result['received_text'] = response.decode('ascii', 'backslashreplace')
        if handle:
            if claimed:
                # Cleanup steps are independent: a failed restore must not skip release.
                if alt_attempted:
                    try: result['cleanup']['restore_alt_rc'] = alternate(handle, 0, previous)
                    except Exception as e: result['cleanup']['restore_error'] = str(e)
                if previous is not None:
                    try:
                        restored, result['cleanup']['alt_report'] = read_alt()
                        result['cleanup']['alt_verified'] = restored == previous
                    except Exception as e: result['cleanup']['alt_error'] = str(e)
                try: result['cleanup']['release_rc'] = release(handle, 0)
                except Exception as e: result['cleanup']['release_error'] = str(e)
            try:
                after = active(handle, 0)
                result['cleanup']['kernel_active_after'] = after
                result['cleanup']['kernel_verified'] = after == kernel_before
            except Exception as e: result['cleanup']['kernel_error'] = str(e)
            result['cleanup_verified'] = (
                (not claimed or (result['cleanup'].get('release_rc') == 0
                                 and result['cleanup'].get('alt_verified') is True))
                and result['cleanup'].get('kernel_verified') is True
                and result['cleanup'].get('restore_alt_rc', 0) == 0
                and not any(k.endswith('_error') for k in result['cleanup']))
            close(handle)
        leave(ctx)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--query', choices=('echo', 'id'), default='echo')
    p.add_argument('--send', action='store_true')
    p.add_argument('--ready-observed', action='store_true')
    p.add_argument('--panel-observed', choices=('ready', 'replace-ink-cartridges'))
    args = p.parse_args()
    nonce = secrets.token_hex(8); payload = make_query(args.query, nonce)
    report = {'query': args.query, 'nonce': nonce, 'payload_bytes': len(payload),
              'payload_base64': base64.b64encode(payload).decode(), 'sent': False}
    if args.send:
        if not (args.ready_observed or args.panel_observed):
            p.error('observe an idle Ready or Replace ink cartridges panel before --send')
        report['panel_observation'] = args.panel_observed or 'ready'
        try:
            bus, address = discover()
            report['transport'] = transact(payload, bus, address)
            report['write_attempted'] = bool(report['transport']['write_attempts'])
            report['sent'] = report['transport']['written_bytes'] > 0
            raw = base64.b64decode(report['transport']['received_base64'])
            if args.query == 'echo': report.update(classify_echo(raw, nonce, payload))
            report['transport_clean'] = (report['transport']['write_completed']
                                         and report['transport']['cleanup_verified']
                                         and not report['transport'].get('error')
                                         and not report['transport'].get('read_error'))
            report['test_accepted'] = (report['transport_clean'] and report['pjl_echo_frame_valid']
                                       if args.query == 'echo' else None)
        except Exception as e:
            report['error'] = str(e)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
