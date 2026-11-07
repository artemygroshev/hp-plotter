"""One-shot read-only snapshot for the recorded BTT/DesignJet connection.

Run on BTT over pinned SSH. No server, print data, resets, or settings writes.
Default: host/CUPS/sysfs only. --class-read adds standard USB IN requests
after empty-queue/idle/backend/identity checks, without changing alternate mode.
Spooler media/idle/reasons never become inferred physical printer state.
"""
import argparse
import ctypes as C
import ctypes.util
import datetime
import hashlib
import json
import platform
from pathlib import Path
import re
import stat
import subprocess

MACHINE_ID = '00000000000000000000000000000000'
ADAPTER_DESCRIPTOR_SHA256 = 'd5e1ee6bc5732b93ec44b7830dd57ff82b7a044cd6064809e1d642c6aae3cf1e'
URI = 'ipp://localhost:631/printers/HP-DesignJet-500'
QUEUE = 'HP-DesignJet-500'
ATTRIBUTES = (
    'printer-state', 'printer-state-reasons', 'printer-state-message',
    'queued-job-count', 'printer-make-and-model', 'marker-names',
    'marker-types', 'marker-levels', 'marker-colors', 'marker-message',
    'printer-alert', 'printer-alert-description', 'media-ready',
    'media-col-ready', 'printer-supply', 'printer-supply-description',
)


def command(args, input_text=None):
    try:
        proc = subprocess.run(args, input=input_text, capture_output=True,
                              text=True, timeout=8)
        return {'rc': proc.returncode, 'out': proc.stdout[-16000:], 'err': proc.stderr[-1000:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'rc': None, 'out': '', 'error': str(error)}


def cups_attributes(text):
    # Parse only actual returned requested attributes; preserve raw values/types.
    # Input test declarations have no " = " and cannot supply fake values.
    found = {}
    for match in re.finditer(r'^\s+([a-z][a-z0-9-]*) \(([^\n]+?)\) = (.*)$', text, re.M):
        name, kind, value = match.groups()
        if name in ATTRIBUTES:
            found[name] = {'ipp_type': kind, 'raw_value': value}
    return found


def parse_device_id(raw):
    report = {'raw_hex': raw.hex(), 'valid': False, 'hp_c7769b_identified': False}
    if len(raw) < 2:
        report['error'] = 'missing IEEE-1284 length'
        return report
    declared = int.from_bytes(raw[:2], 'big')
    report['declared_bytes'] = declared
    if declared != len(raw) or declared < 3:
        report['error'] = 'incomplete or unexpected IEEE-1284 length'
        return report
    try:
        text = raw[2:].decode('ascii')
    except UnicodeDecodeError:
        report['error'] = 'non-ASCII device ID'
        return report
    fields = {}
    for part in text.split(';'):
        if not part:
            continue
        if ':' not in part:
            report['error'] = 'malformed IEEE-1284 field'
            return report
        name, value = part.split(':', 1)
        key = name.strip().upper()
        if not key or key in fields:
            report['error'] = 'empty or duplicate IEEE-1284 field'
            return report
        fields[key] = value.strip()
    report['fields'] = fields
    manufacturer = fields.get('MANUFACTURER', fields.get('MFG', ''))
    model = fields.get('MODEL', fields.get('MDL', ''))
    report['valid'] = bool(manufacturer and model)
    report['hp_c7769b_identified'] = (
        report['valid'] and manufacturer.casefold() in ('hewlett-packard', 'hp')
        and model == 'DesignJet 500 (C7769B)'
    )
    return report


def adapters():
    result = []
    for node in Path('/sys/bus/usb/devices').glob('*'):
        try:
            if (node/'idVendor').read_text().strip() != '1a86' or (node/'idProduct').read_text().strip() != '7584':
                continue
            row = {'path': str(node.resolve()), 'sysfs_node': str(node)}
            for name in ('idVendor', 'idProduct', 'busnum', 'devnum',
                         'bConfigurationValue', 'manufacturer', 'product', 'serial',
                         'speed', 'bcdDevice', 'authorized'):
                try:
                    row[name] = (node/name).read_text().strip()
                except OSError:
                    pass  # Many bridges have no manufacturer/serial descriptor.
            row['power'] = {}
            for attribute in ('control', 'runtime_status', 'autosuspend_delay_ms',
                              'runtime_active_time', 'runtime_suspended_time', 'wakeup'):
                try:
                    row['power'][attribute] = (node/'power'/attribute).read_text().strip()
                except OSError:
                    pass
            row['descriptor_sha256'] = hashlib.sha256((node/'descriptors').read_bytes()).hexdigest()
            interface = node.parent / (node.name + ':1.0')
            row['alternate'] = int((interface/'bAlternateSetting').read_text(), 16)
            row['driver'] = str((interface/'driver').resolve()) if (interface/'driver').exists() else None
            result.append(row)
        except (FileNotFoundError, NotADirectoryError):
            continue
    return result


def backend_pids():
    found = []
    for node in Path('/proc').glob('[0-9]*'):
        try:
            first = (node/'cmdline').read_bytes().split(b'\0', 1)[0]
            if b'/cups/backend/' in first and first.endswith(b'/usb'):
                found.append(int(node.name))
        except OSError:
            continue
    return found


def adapter_open_handles(usb):
    """Only inspect fd metadata for our USB/lp devices, never file contents."""
    if not usb:
        return {'devices': [], 'open_handles': [], 'inspection_complete': True, 'errors': []}
    nodes = []
    for adapter in usb:
        nodes.append(Path('/dev/bus/usb/%03d/%03d' %
                          (int(adapter['busnum']), int(adapter['devnum']))))
        for lp in Path('/sys/class/usbmisc').glob('lp*'):
            if str(lp.resolve()).startswith(adapter['path'] + '/'):
                nodes.append(Path('/dev/usb') / lp.name)
    device_numbers, errors, owners = {}, [], []
    for node in nodes:
        try:
            meta = node.stat()
            if stat.S_ISCHR(meta.st_mode):
                device_numbers[meta.st_rdev] = str(node)
        except FileNotFoundError:
            errors.append('expected device node missing: ' + str(node))
        except OSError as error:
            errors.append(str(error))
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            for fd in (proc/'fd').iterdir():
                try:
                    meta = fd.stat()
                    if stat.S_ISCHR(meta.st_mode) and meta.st_rdev in device_numbers:
                        owners.append({'pid': int(proc.name), 'fd': fd.name,
                                       'device': device_numbers[meta.st_rdev]})
                except FileNotFoundError:
                    pass  # fd/process may close during the passive scan
        except FileNotFoundError:
            pass
        except OSError as error:
            errors.append('cannot inspect pid ' + proc.name + ': ' + str(error))
    return {'devices': [str(n) for n in nodes], 'open_handles': owners,
            'inspection_complete': not errors, 'errors': errors}


def read_class_status(adapter):
    lib = C.CDLL(ctypes.util.find_library('usb-1.0'))
    pointer, integer = C.c_void_p, C.c_int
    def bind(name, args, result):
        function = getattr(lib, name)
        function.argtypes, function.restype = args, result
        return function
    init = bind('libusb_init', [C.POINTER(pointer)], integer)
    leave = bind('libusb_exit', [pointer], None)
    op = bind('libusb_open_device_with_vid_pid', [pointer, C.c_uint16, C.c_uint16], pointer)
    close = bind('libusb_close', [pointer], None)
    device = bind('libusb_get_device', [pointer], pointer)
    bus = bind('libusb_get_bus_number', [pointer], C.c_uint8)
    address = bind('libusb_get_device_address', [pointer], C.c_uint8)
    active = bind('libusb_kernel_driver_active', [pointer, integer], integer)
    claim = bind('libusb_claim_interface', [pointer, integer], integer)
    release = bind('libusb_release_interface', [pointer, integer], integer)
    control = bind('libusb_control_transfer', [pointer, C.c_uint8, C.c_uint8,
                   C.c_uint16, C.c_uint16, pointer, C.c_uint16, C.c_uint], integer)
    report = {'bulk_out_bytes': 0, 'alt_changes': 0, 'requests': {}, 'cleanup_verified': False}
    context, handle, claimed = pointer(), None, False
    kernel_before = None
    original = adapter['alternate']
    if original not in (0, 1):
        raise RuntimeError('unsupported alternate setting')
    rc = init(C.byref(context))
    if rc:
        raise RuntimeError(('libusb_init', rc))
    try:
        handle = op(context, 0x1a86, 0x7584)
        if not handle:
            raise RuntimeError('adapter not opened')
        dev = device(handle)
        if (bus(dev), address(dev)) != (int(adapter['busnum']), int(adapter['devnum'])):
            raise RuntimeError('adapter changed')
        kernel_before = active(handle, 0)
        if kernel_before not in (0, 1):
            raise RuntimeError(('kernel ownership unknown', kernel_before))
        requests = [('GET_DEVICE_ID', 0, original, 1024, 5000)]
        if kernel_before == 0:
            rc = claim(handle, 0)
            if rc:
                raise RuntimeError(('claim', rc))
            claimed = True
            requests.append(('GET_PORT_STATUS', 1, 0, 1, 1000))
        else:
            # Linux devio.c permits this standard printer ID request while a
            # kernel driver is bound. Do not open usblp: its pending bulk IN
            # reproducibly interferes with GET_DEVICE_ID on our adapter.
            report['requests']['GET_PORT_STATUS'] = {
                'skipped': 'kernel interface retained; status requires ownership',
            }
        report['kernel_active_before'] = kernel_before
        # Printer Class 1.1: status uses interface index 0, device ID uses
        # (interface << 8)|alternate and a zero-based configuration index.
        for name, request, index, length, timeout in requests:
            buffer = C.create_string_buffer(length)
            rc = control(handle, 0xa1, request, 0, index, buffer, length, timeout)
            raw = buffer.raw[:max(0, rc)]
            row = {'bmRequestType': 0xa1, 'bRequest': request, 'wValue': 0,
                   'wIndex': index, 'wLength': length, 'rc': rc, 'raw_hex': raw.hex()}
            if name == 'GET_DEVICE_ID' and rc >= 0:
                row['decoded'] = parse_device_id(raw)
            if name == 'GET_PORT_STATUS' and rc == 1:
                row['decoded'] = {'paper_empty_signal': bool(raw[0] & 0x20),
                                  'selected_signal': bool(raw[0] & 0x10),
                                  'not_error_signal': bool(raw[0] & 0x08)}
            report['requests'][name] = row
    except Exception as error:
        report['error'] = str(error)
    finally:
        if handle:
            if claimed:
                report['release_rc'] = release(handle, 0)
            report['kernel_active_after'] = active(handle, 0)
            close(handle)
        leave(context)
        current = adapters()
        same = [x for x in current if x['path'] == adapter['path']]
        report['cleanup_verified'] = (len(same) == 1 and same[0]['alternate'] == original
                                      and same[0]['driver'] == adapter['driver']
                                      and same[0]['busnum'] == adapter['busnum']
                                      and same[0]['devnum'] == adapter['devnum']
                                      and same[0]['descriptor_sha256'] == adapter['descriptor_sha256']
                                      and (not claimed or report.get('release_rc') == 0)
                                      and kernel_before in (0, 1)
                                      and report.get('kernel_active_after') == kernel_before)
    return report


def snapshot(class_read=False):
    if Path('/etc/machine-id').read_text().strip() != MACHINE_ID:
        raise RuntimeError('this snapshot targets only the recorded BTT')
    test = ('{\nNAME "Read status attributes only"\nOPERATION Get-Printer-Attributes\n'
            'GROUP operation-attributes-tag\nATTR charset attributes-charset utf-8\n'
            'ATTR naturalLanguage attributes-natural-language en\n'
            'ATTR uri printer-uri ' + URI + '\nATTR keyword requested-attributes '
            + ','.join(ATTRIBUTES) + '\nSTATUS successful-ok\n}\n')
    raw = command(['ipptool', '-tv', '-T', '5', URI, '/dev/stdin'], test)
    queue = command(['lpstat', '-W', 'not-completed', '-o', QUEUE])
    job_test = ('{\nNAME "List unfinished jobs only"\nOPERATION Get-Jobs\n'
                'GROUP operation-attributes-tag\nATTR charset attributes-charset utf-8\n'
                'ATTR naturalLanguage attributes-natural-language en\n'
                'ATTR uri printer-uri ' + URI + '\nATTR keyword which-jobs not-completed\n'
                'ATTR keyword requested-attributes job-id,job-state,job-state-reasons\n'
                'STATUS successful-ok\n}\n')
    jobs = command(['ipptool', '-tv', '-T', '5', URI, '/dev/stdin'], job_test)
    job_ids = ([int(x) for x in re.findall(r'^\s+job-id \(integer\) = (\d+)\s*$', jobs['out'], re.M)]
               if jobs['rc'] == 0 else None)
    backends = backend_pids()
    observed = datetime.datetime.now(datetime.timezone.utc).isoformat()
    values = cups_attributes(raw['out']) if raw['rc'] == 0 else {}
    usb = adapters()
    handles = adapter_open_handles(usb)
    result = {
        'observed_utc': observed, 'machine_id': MACHINE_ID,
        'btt_boot': {'kernel_release': platform.release(),
                     'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     'uptime_seconds': float(Path('/proc/uptime').read_text().split()[0])},
        'cups': {'source': 'BTT spooler, not direct HP telemetry', 'attributes': values,
                 'raw_request': raw, 'queue_command': queue, 'unfinished_jobs_request': jobs,
                 'unfinished_job_ids': job_ids, 'usb_backend_pids': backends},
        'btt_services': command(['systemctl', 'is-active', 'cups', 'klipper', 'moonraker']),
        'adapters': usb,
        'usb_handles': handles,
        'hp_runtime': {name: {'value': None, 'reason': 'no verified HP runtime response'}
                       for name in ('lcd', 'panel_text', 'ready', 'ink_levels', 'ink_error',
                                    'printheads', 'loaded_media', 'engine_firmware', 'error_log')},
        'class_read_requested': class_read,
        'warnings': [],
    }
    hint = values.get('queued-job-count', {}).get('raw_value')
    if job_ids == [] and hint not in (None, '0'):
        result['warnings'].append('CUPS queued-job-count differs from empty Get-Jobs result; preserve both, do not infer an active job from this count')
    if class_read:
        idle = values.get('printer-state', {}).get('raw_value') == 'idle'
        if (queue['rc'] != 0 or queue['out'].strip() or backends or not idle or job_ids != []
                or handles['open_handles'] or not handles['inspection_complete']):
            result['class_read_skipped'] = 'queue/backend not idle or device ownership unknown/occupied'
        elif (len(usb) != 1 or usb[0].get('descriptor_sha256') != ADAPTER_DESCRIPTOR_SHA256
              or usb[0].get('bConfigurationValue') != '1'):
            result['class_read_skipped'] = 'recorded adapter descriptor/configuration not uniquely identified'
        else:
            result['class_read'] = read_class_status(usb[0])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--class-read', action='store_true')
    args = parser.parse_args()
    print(json.dumps(snapshot(args.class_read), ensure_ascii=False, indent=2))
