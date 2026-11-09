"""One reviewed A.04.02 panel key with a fresh, expected LCD and read-back.

This operator tool does not implement automatic cleaning. Each invocation sends
at most one key, without retry. No PAPER, CANCEL, ALL or key combinations exist.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from access_lock import usb_lock
from batch_read import USBTrace, check_queue, check_active, restored, BatchClient
from batch_usb import ReadSession
from device_guard import DeviceGuard, guard_path
from framebuffer_memory import extract_tagged_value
from local_config import configuration, capture_directory
from storage import atomic_json
from trace_sequential_echo import idle_adapter
import status_snapshot as support
import probe_printer as probe

KEYS = ('ENTER', 'BACK', 'UP', 'DOWN', 'TOP')
PROOFS = (
    ('tcl_key_wrapper', 0xa025ef14, 108, 'd08a8716a4340a132b71fde790f751e04f5b383d1b9a0a4755bf2cae2f873720'),
    ('key_name_parser', 0xa027c1f0, 136, '4a6d6efcd2a55e4d58c9d35ea117fbdbe06e6504459570856fe4afaa7adb1525'),
    ('native_key_dispatch', 0xa027c370, 74, '4ce973e56e7dbc118c5a0988e8cbd4b9f595bae0812b8da6a63271f646c22d10'),
    ('callback_dispatch', 0xa017d19c, 30, 'fde679a7de272d5f99ab7ba2a26b5f99c7ac43ee5a3f2397fae0c9b2fe9e9534'),
    ('key_tables', 0xa027cb00, 56, '3bf8535194a8724c5e1e494c88fc7d23cd125f71cea60b7e1eeec2274a82502e'),
)


def require_compatible_session():
    if not {'command_payload','validate_reply'}.issubset(ReadSession.query.__code__.co_names):
        raise RuntimeError('panel keys require matching batch_usb.py payload/validation interfaces')


def parse_key_reply(raw, nonce, key):
    if key not in KEYS:
        raise ValueError('unknown key')
    prefix = ('Simulating: '+key+'\n').encode('ascii')
    present = raw.startswith(prefix)
    value = extract_tagged_value(raw[len(prefix):] if present else raw, nonce, 'R', '_')
    if value != '0':
        raise ValueError('key result is not success')
    return {'value': value, 'native_prefix_present': present,
            'original_reply_preserved': True, 'fresh_result_and_end_verified': True}


def key_payload(key, nonce):
    if key not in KEYS or not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('require one fixed key and a six-hex nonce')
    script = ('puts R'+nonce+'_[fpSimulateKey '+key+']\nputs E'+nonce+'\nexit\n').encode('ascii')
    prefix = probe.UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script
    tail = b'\n'+probe.UEL+b'\r\n'
    padding = 129-len(prefix)-len(tail)
    if padding < 1:
        raise ValueError('key frame exceeds reviewed size')
    return prefix+b'#'+b' '*(padding-1)+tail


class KeySession(ReadSession):
    def __init__(self, *args, key, **kwargs):
        if key not in KEYS:
            raise ValueError('unknown key')
        self.key = key
        super().__init__(*args, **kwargs)

    def read_identity(self):
        # Retry only the bridge's empty class-ID result. Never replay a Tcl
        # query/key, and never retry a different model or a negative USB error.
        for delay in (0, .1, .3, .8):
            if delay:
                self.sleep(delay)
            try:
                return super().read_identity()
            except RuntimeError:
                last = self.controls[-1] if self.controls else {}
                if delay == .8 or last.get('operation') != 'GET_DEVICE_ID' or last.get('rc') != 0:
                    raise

    def command_payload(self, kind, nonce, memory=None):
        if kind == 'panel_key':
            if memory is not None:
                raise ValueError('key has no memory arguments')
            return key_payload(self.key, nonce)
        return super().command_payload(kind, nonce, memory)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind == 'panel_key':
            report['key_reply_proof'] = parse_key_reply(raw, nonce, self.key)
        else:
            super().validate_reply(kind, nonce, raw, memory, report)


class KeyClient(BatchClient):
    def value(self, kind, tag='R', separator='_'):
        if kind != 'panel_key':
            return super().value(kind, tag, separator)
        report = self.query(kind)
        transport = report['transport']
        proof = parse_key_reply(base64.b64decode(transport['received_base64']),
                                report['nonce'], self.session.key)
        return proof['value']


def verified_key(client, key, expected_lcd_sha256, checkpoint):
    """No callback state or input event is modified before every check passes."""
    if key not in KEYS or not re.fullmatch(r'[a-f0-9]{64}', expected_lcd_sha256):
        raise ValueError('a fixed key and an expected complete LCD hash are required')
    client.identify()
    for name, address, length, digest in PROOFS:
        data = b''.join(client.memory(address+offset, min(128, length-offset))
                        for offset in range(0, length, 128))
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('live panel code differs: '+name)
    callback, = struct.unpack('>I', client.memory(0xa03a74b8, 4))
    if not 0xa0001000 <= callback < 0xa0380000 or callback % 2:
        raise RuntimeError('panel callback is absent or outside reviewed engine code')
    descriptor, header, pointer = client.locate()
    before = client.capture('before', descriptor, header, pointer)
    actual = hashlib.sha256(before).hexdigest()
    if actual != expected_lcd_sha256:
        raise RuntimeError('LCD changed; inspect the new capture before choosing a key')
    if client.value('telemetry_diag_busy') != '0':
        raise RuntimeError('HP busy; no panel key sent')
    checkpoint('key_attempt_started')
    rc = client.value('panel_key')
    if rc != '0':
        raise RuntimeError('panel key rejected or ambiguous; no retry')
    checkpoint('key_acknowledged')
    # Re-locate: a key can replace the bitmap object. Capture does not claim
    # that one screen contains all blinking phases or is an atomic snapshot.
    descriptor, header, pointer = client.locate()
    after = client.capture('after', descriptor, header, pointer)
    checkpoint('readback_complete')
    return {'key': key, 'result': rc, 'before_sha256': actual,
            'after_sha256': hashlib.sha256(after).hexdigest(),
            'screen_changed': after != before, 'keys_sent': 1,
            'cleaning_started': False, 'cleaning_started_requires_screen_review': True}


def control(cutoff, key, expected_lcd_sha256):
    require_compatible_session()
    if key not in KEYS or not re.fullmatch(r'[a-f0-9]{64}', expected_lcd_sha256):
        raise ValueError('require one fixed key and the expected LCD hash')
    if cutoff.tzinfo is None or not 300 <= (cutoff-dt.datetime.now(dt.timezone.utc)).total_seconds() <= 1200:
        raise ValueError('allow a bounded 300..1200 second operation window')
    config = configuration()
    if (os.geteuid() != 0 or config['executor'] != 'local'
            or config['idle_driver'] != 'none' or config['small_query_bytes'] != 129):
        raise RuntimeError('panel control requires the pinned local root none/alt0/129 profile')
    for name, value in (('MACHINE_ID', config['machine_id']),
                       ('ADAPTER_DESCRIPTOR_SHA256', config['adapter_descriptor_sha256']),
                       ('QUEUE', config['queue']), ('URI', 'ipp://localhost:631/printers/'+config['queue']),
                       ('IDLE_DRIVER', None), ('IDLE_ALTERNATE', 0)):
        setattr(support, name, value)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = capture_directory(config)/('panel-key-'+stamp+'.json')
    report = {'key': key, 'expected_lcd_sha256': expected_lcd_sha256,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'identity_policy': 'fresh_class_ID_each_query_empty_ID_only_bounded_retry',
              'print_jobs_created': False, 'automatic_retry': False, 'complete': False}
    session = trace = client = None
    error = None
    with usb_lock(config['lock_file']):
        before = support.snapshot(class_read=False)
        check_queue(before)
        adapter = idle_adapter(before['adapters'], support.__dict__)
        with DeviceGuard(str(guard_path(config)), 'panel-key:'+key) as lease:
            was_loaded = Path('/sys/module/usbmon').exists()
            try:
                report['preflight'] = before
                trace = USBTrace(int(adapter['busnum']), int(adapter['devnum']), cutoff)
                trace.start()
                # Initial-ID-only passed FW but stalled on serial on 2026-11-09.
                # Keep per-query class ID, with bounded empty-ID-only retries.
                session = KeySession(int(adapter['busnum']), int(adapter['devnum']), cutoff,
                                     key=key, refresh_id_each_query=True, comment_bytes=63)
                def prior():
                    if trace.errors:
                        raise RuntimeError('USB trace stopped')
                    check_active(support.snapshot(class_read=False), before, os.getpid())
                def checkpoint(phase):
                    report['phase'] = phase
                    atomic_json(target, report)
                with session:
                    client = KeyClient(cutoff, 'panel-key', 1, session, prior)
                    report['result'] = verified_key(client, key, expected_lcd_sha256, checkpoint)
                    report['complete'] = True
            except BaseException as caught:
                error = caught
                report['error'] = str(caught)
            finally:
                if session:
                    session.close()
                trace_result = (trace.close() if trace else {'reader_closed': True,
                    'module_loaded_before': was_loaded, 'module_loaded_after': Path('/sys/module/usbmon').exists(), 'errors': []})
                after = support.snapshot(class_read=False)
                clean = restored(before, after, session, trace_result)
                # Once an input event may have been injected, only a complete
                # post-action capture permits automatic guard removal.
                attempted = report.get('phase') in ('key_attempt_started', 'key_acknowledged', 'readback_complete')
                if clean and (session is None or session.stream_closed) and (not attempted or report['complete']):
                    lease.clear()
                report.update(postflight=after, trace=trace_result, hardware_cleanup_verified=clean,
                    device_guard_cleared=lease.cleared, queries=session.queries if session else [],
                    controls=session.controls if session else [], transport_cleanup=session.cleanup if session else {},
                    screens=client.state['screens'] if client else [],
                    complete=report['complete'] and clean and lease.cleared)
                atomic_json(target, report)
    if error:
        raise RuntimeError(str(error)+'; evidence: '+str(target)) from error
    if not report['complete']:
        raise RuntimeError('panel action incomplete; evidence: '+str(target))
    return {'evidence': str(target), **report['result'], 'screens': report['screens'], 'complete': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key', required=True, choices=KEYS)
    parser.add_argument('--expect-lcd-sha256', required=True)
    parser.add_argument('--until-utc', required=True)
    args = parser.parse_args()
    print(json.dumps(control(dt.datetime.fromisoformat(args.until_utc), args.key, args.expect_lcd_sha256)))


if __name__ == '__main__':
    main()
