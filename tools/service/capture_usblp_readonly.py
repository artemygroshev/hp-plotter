"""Bounded read-only usblp probe with usbmon; no detach, reset or OUT data.

Requires the recorded BTT and its currently bound, idle CH340S adapter.
Only GET_PROTOCOLS, GET_DEVICE_ID, LPGETSTATUS and a three-second IN wait.
The kernel driver owns protocol selection. All own handles and optional
usbmon module are closed/restored before returning. No debugfs mounting.
"""
import array
import ctypes as C
import ctypes.util
import errno
import fcntl
import os
from pathlib import Path
import re
import select
import subprocess
import threading
import time


def address_of(line):
    parts = line.split()
    if len(parts) < 4:
        return None
    match = re.fullmatch(r'([BCIZ])([io]):(\d+):(\d+):(\d+)', parts[3])
    if not match:
        return None
    kind, direction, bus, dev, endpoint = match.groups()
    return kind, direction, int(bus), int(dev), int(endpoint)


def capture(support, class_id_requests=None, usblp_crossover=False):
    if class_id_requests is not None and tuple(class_id_requests) not in (
            ((1, 1024), (0, 1024)), ((1, 2), (0, 2)),
            ((1, 1023), (1, 1024)), ((1, 1024), (1, 1023)),
            ((1, 1024), (1, 1024))):
        raise ValueError('only the two bounded standard ID comparisons are allowed')
    if usblp_crossover and tuple(class_id_requests or ()) != ((1, 1024), (1, 1024)):
        raise ValueError('crossover requires identical class ID requests')
    before = support['snapshot'](class_read=False)  # validates machine ID first
    cups = before['cups']
    if (cups['unfinished_job_ids'] != [] or cups['queue_command']['rc'] != 0
            or cups['queue_command']['out'].strip() or cups['usb_backend_pids']
            or before['usb_handles']['open_handles']
            or not before['usb_handles']['inspection_complete']
            or cups['attributes'].get('printer-state', {}).get('raw_value') != 'idle'):
        raise RuntimeError('CUPS not verifiably idle')
    adapters = before['adapters']
    if (len(adapters) != 1
            or adapters[0].get('descriptor_sha256') != 'd5e1ee6bc5732b93ec44b7830dd57ff82b7a044cd6064809e1d642c6aae3cf1e'
            or adapters[0].get('driver') != '/sys/bus/usb/drivers/usblp'
            or adapters[0].get('alternate') != 1
            or adapters[0].get('bConfigurationValue') != '1'):
        raise RuntimeError('recorded bound bidirectional adapter not confirmed')
    adapter = adapters[0]
    candidates = [p for p in Path('/sys/class/usbmisc').glob('lp*')
                  if str(p.resolve()).startswith(adapter['path'] + '/')]
    if len(candidates) != 1:
        raise RuntimeError('associated usblp character device not unique')
    device_path = Path('/dev/usb') / candidates[0].name
    if not device_path.is_char_device():
        raise RuntimeError('missing usblp character device')
    result = {'preflight': before, 'device': str(device_path), 'requests': [],
              'trace_kind': 'usbmon HCD trace, not electrical verification',
              'usbmon_loaded_before': Path('/sys/module/usbmon').exists(),
              'bulk_out_bytes_requested_by_probe': 0, 'cleanup': {}}
    stop, ready = threading.Event(), threading.Event()
    trace, errors = bytearray(), []
    reader = None
    loaded = False
    fd = None
    bus, dev = int(adapter['busnum']), int(adapter['devnum'])

    def command(args):
        p = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return {'rc': p.returncode, 'out': p.stdout[-1000:], 'err': p.stderr[-1000:]}

    def trace_reader():
        monfd = None
        try:
            monfd = os.open('/sys/kernel/debug/usb/usbmon/%du' % bus,
                            os.O_RDONLY | os.O_NONBLOCK)
            ready.set()
            deadline = time.monotonic() + 18
            while not stop.is_set() and time.monotonic() < deadline and len(trace) < 131072:
                if select.select([monfd], [], [], 0.1)[0]:
                    try:
                        data = os.read(monfd, min(4096, 131072 - len(trace)))
                    except BlockingIOError:
                        continue
                    if not data:
                        break
                    trace.extend(data)
            if len(trace) >= 131072:
                errors.append('trace limit reached')
        except Exception as error:
            errors.append(str(error))
            ready.set()
        finally:
            if monfd is not None:
                os.close(monfd)

    def ioctl_read(name, code, buffer):
        row = {'name': name, 'code': hex(code)}
        started = time.monotonic()
        try:
            row['return_code'] = fcntl.ioctl(fd, code, buffer, True)
            row['raw_hex'] = bytes(buffer).hex()
            if name == 'GET_PROTOCOLS':
                row['current_protocol'], row['supported_mask'] = list(buffer)
            if name == 'GET_DEVICE_ID':
                declared = int.from_bytes(buffer[:2], 'big')
                row['decoded'] = support['parse_device_id'](bytes(buffer[:min(declared, len(buffer))]))
        except OSError as error:
            row.update(errno=error.errno, error=str(error))
        row['elapsed_seconds'] = round(time.monotonic() - started, 4)
        result['requests'].append(row)

    try:
        if not result['usbmon_loaded_before']:
            result['module_load'] = command(['modprobe', 'usbmon'])
            loaded = Path('/sys/module/usbmon').exists()
            if result['module_load']['rc'] or not loaded:
                raise RuntimeError('usbmon not available')
        reader = threading.Thread(target=trace_reader, name='bounded-usblp-readonly')
        reader.start()
        if not ready.wait(2) or errors:
            raise RuntimeError('usbmon reader not ready: ' + repr(errors))
        if class_id_requests is not None:
            # devio.c explicitly permits printer GET_DEVICE_ID without claiming
            # an interface, including when usblp is bound. No detach/alt change.
            result['mode'] = 'class-ID-IN-with-kernel-driver-retained'
            lib = C.CDLL(ctypes.util.find_library('usb-1.0'))
            def bind(name, args, returns):
                f = getattr(lib, name)
                f.argtypes, f.restype = args, returns
                return f
            ptr = C.c_void_p
            init = bind('libusb_init', [C.POINTER(ptr)], C.c_int)
            leave = bind('libusb_exit', [ptr], None)
            op = bind('libusb_open_device_with_vid_pid', [ptr, C.c_uint16, C.c_uint16], ptr)
            close = bind('libusb_close', [ptr], None)
            dev_of = bind('libusb_get_device', [ptr], ptr)
            get_bus = bind('libusb_get_bus_number', [ptr], C.c_uint8)
            get_addr = bind('libusb_get_device_address', [ptr], C.c_uint8)
            control = bind('libusb_control_transfer', [ptr, C.c_uint8, C.c_uint8,
                           C.c_uint16, C.c_uint16, ptr, C.c_uint16, C.c_uint], C.c_int)
            context, handle = ptr(), None
            rc = init(C.byref(context))
            if rc:
                raise RuntimeError(('libusb_init', rc))
            try:
                handle = op(context, 0x1a86, 0x7584)
                if not handle or (get_bus(dev_of(handle)), get_addr(dev_of(handle))) != (bus, dev):
                    raise RuntimeError('bridge changed before control request')
                if usblp_crossover:
                    fd = os.open(str(device_path), os.O_RDONLY | os.O_NONBLOCK)
                for index, size in class_id_requests:
                    buffer = C.create_string_buffer(size)
                    rc = control(handle, 0xa1, 0, 0, index, buffer, size, 1500)
                    raw = buffer.raw[:max(0, rc)]
                    result['requests'].append({'name': 'GET_DEVICE_ID',
                        'bmRequestType': 0xa1, 'bRequest': 0, 'wValue': 0,
                        'wIndex': index, 'wLength': size, 'actual_bytes_or_error': rc,
                        'usblp_reader_open': fd is not None,
                        'raw_hex': raw.hex(), 'decoded': support['parse_device_id'](raw)})
                    if usblp_crossover and fd is not None:
                        os.close(fd)
                        fd = None
            finally:
                if handle:
                    close(handle)
                leave(context)
        else:
            # O_RDONLY prevents print data writes. Driver opens a bulk IN URB.
            fd = os.open(str(device_path), os.O_RDONLY | os.O_NONBLOCK)
            ioctl_read('GET_PROTOCOLS', (2 << 30) | (8 << 16) | (ord('P') << 8) | 2,
                       array.array('i', [0, 0]))
            ioctl_read('GET_DEVICE_ID', (2 << 30) | (1024 << 16) | (ord('P') << 8) | 1,
                       bytearray(1024))
            ioctl_read('LPGETSTATUS', 0x060b, array.array('i', [0]))
            end = time.monotonic() + 3
            chunks = bytearray()
            while time.monotonic() < end and len(chunks) < 8192:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                if not select.select([fd], [], [], min(0.2, remaining))[0]:
                    continue
                try:
                    chunk = os.read(fd, min(1024, 8192-len(chunks)))
                except OSError as error:
                    if error.errno == errno.EAGAIN:
                        continue
                    result['bulk_in_error'] = {'errno': error.errno, 'error': str(error)}
                    break
                if not chunk:
                    break
                chunks.extend(chunk)
            result['bulk_in_bytes'] = len(chunks)
            result['bulk_in_hex'] = chunks.hex()
    except Exception as error:
        result['error'] = str(error)
    finally:
        if fd is not None:
            os.close(fd)  # kernel cancels only this open's pending URBs
        result['cleanup']['device_closed'] = True
        time.sleep(0.1)  # include cancellation completion in HCD trace
        stop.set()
        if reader is not None:
            reader.join(2)
        result['cleanup']['reader_closed'] = reader is None or not reader.is_alive()
        lines = []
        for line in trace.decode('ascii', 'backslashreplace').splitlines():
            parsed = address_of(line)
            if parsed and parsed[2:4] == (bus, dev):
                lines.append(line)
        result['trace'] = '\n'.join(lines)
        result['trace_reader_errors'] = errors
        result['observed_bulk_out_submissions'] = sum(
            line.split()[2] == 'S' and address_of(line)[:2] == ('B', 'o') for line in lines)
        if loaded:
            result['module_unload'] = command(['modprobe', '-r', 'usbmon'])
        result['cleanup']['usbmon_loaded_after'] = Path('/sys/module/usbmon').exists()
        after = support['snapshot'](class_read=False)
        result['postflight'] = after
        same = [x for x in after['adapters'] if x['path'] == adapter['path']]
        result['cleanup']['verified'] = (
            len(same) == 1 and same[0]['alternate'] == adapter['alternate']
            and same[0]['driver'] == adapter['driver']
            and same[0]['descriptor_sha256'] == adapter['descriptor_sha256']
            and result['cleanup']['reader_closed']
            and result['cleanup']['usbmon_loaded_after'] == result['usbmon_loaded_before']
            and after['cups']['unfinished_job_ids'] == []
            and not after['cups']['usb_backend_pids'])
    return result
