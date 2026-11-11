"""Disabled hardware experiment, preserved for offline review and tests.

The host supplies immutable-image copy slices after allocation. Every copied
byte is compared with the locally built fixed program before execution. The
native transaction is intended to restore its target before returning. The
first hardware trial stalled; no successful native rollback has been proved.
execute() is blocked before any configuration, allocation or USB access.
"""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time

from access_lock import usb_lock
from batch_read import USBTrace, BatchClient, check_queue, check_active, restored
from batch_usb import ReadSession
from device_guard import DeviceGuard, guard_path
from local_config import configuration, capture_directory
from storage import atomic_json
from trace_sequential_echo import idle_adapter
import probe_printer as probe
import status_snapshot as support
from ram_rollback_program import (build, checked_workspace, ALLOCATION_BYTES,
                                  CACHE_CLEAR, COPY, PRODUCTION_WORD, MAGIC)


def frame(commands, nonce):
    if not re.fullmatch(r'[a-f0-9]{6}', nonce):
        raise ValueError('fresh nonce required')
    if not commands or len(commands) > 4 or any('\n' in s for s in commands):
        raise ValueError('one to four fixed native commands required')
    script = (f'puts B{nonce}\n' + '\n'.join(commands) + f'\nputs E{nonce}\nexit\n').encode('ascii')
    prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
    tail = b'\n' + probe.UEL + b'\r\n'
    length = 513 if len(commands) > 1 else 257
    padding = length - len(prefix) - len(tail)
    if padding < 1:
        raise ValueError('reviewed native frame size exceeded')
    return prefix + b'#' + b' ' * (padding - 1) + tail


def parse(raw, nonce, count):
    pattern = rb'B' + nonce.encode() + rb'\n' + rb'(-?[0-9]+)\n' * count + rb'E' + nonce.encode() + rb'\n'
    match = re.fullmatch(pattern, raw)
    if not match:
        raise ValueError('fixed native reply is not uniquely framed')
    return [int(value) for value in match.groups()]


class RamSession(ReadSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.plans = {}
        self.workspace = None

    def schedule(self, kind, commands):
        if not kind.startswith('ram_') or kind in self.plans:
            raise ValueError('fixed unique RAM operation kind required')
        if kind == 'ram_allocate':
            if commands != ['osMemAlloc 1024'] or self.workspace is not None:
                raise ValueError('one fixed allocation only')
        else:
            checked_workspace(self.workspace)
            if kind.startswith('ram_load_'):
                for command in commands:
                    match = re.fullmatch(r'osFuncCall 0xa0010770 3 (0x[a-f0-9]+) (0x[a-f0-9]+) (0x[a-f0-9]+)', command)
                    if not match:
                        raise ValueError('only bounded immutable-to-owned-workspace copies are allowed')
                    source, destination, length = (int(x, 16) for x in match.groups())
                    if (not 1 <= length <= 64 or not 0xa0001000 <= source <= 0xa0380000 - length
                            or not self.workspace <= destination <= self.workspace + 576 - length):
                        raise ValueError('copy leaves its fixed memory bounds')
            elif kind == 'ram_program_cache_clear':
                if commands != [fixed_call(CACHE_CLEAR, 0, self.workspace, 576)]:
                    raise ValueError('only constructed workspace cache range allowed')
            elif kind in ('ram_shadow', 'ram_production'):
                mode = 0 if kind == 'ram_shadow' else 1
                if commands != ['osFuncCall ' + hex(self.workspace) + ' 1 ' + str(mode)]:
                    raise ValueError('only the verified owned transaction program may execute')
            elif kind == 'ram_free':
                if commands != ['osMemFree ' + hex(self.workspace)]:
                    raise ValueError('only our owned allocation may be freed')
            else:
                raise ValueError('unknown RAM operation')
        self.plans[kind] = tuple(commands)

    def command_payload(self, kind, nonce, memory=None):
        # Keep the ordinary read window unchanged. Only our fresh allocation
        # may be read above it; this printer also has live A1xxxxxx RAM.
        if kind == 'runtime_mem' and memory is not None and self.workspace is not None:
            address, length = memory
            if (type(address) is int and type(length) is int and 1 <= length <= 128
                    and self.workspace <= address <= self.workspace + ALLOCATION_BYTES - length):
                script = (f'puts B{nonce}\nosMemDump {hex(address)} {length}\n'
                          f'puts E{nonce}\nexit\n').encode('ascii')
                prefix = probe.UEL + b'@PJL ENTER LANGUAGE=TCLWARE\r\n' + script
                tail = b'\n' + probe.UEL + b'\r\n'
                padding = 129 - len(prefix) - len(tail)
                if padding < 1:
                    raise ValueError('owned memory read frame exceeds 129 bytes')
                return prefix + b'#' + b' ' * (padding - 1) + tail
        if kind not in self.plans:
            return super().command_payload(kind, nonce, memory)
        if memory is not None or any(q['kind'] == kind for q in self.queries):
            raise RuntimeError('one native operation attempt only; no replay')
        return frame(self.plans[kind], nonce)

    def phase_limit(self, kind):
        return 20 if kind in self.plans else super().phase_limit(kind)

    def validate_reply(self, kind, nonce, raw, memory, report):
        if kind not in self.plans:
            return super().validate_reply(kind, nonce, raw, memory, report)
        report['native_results'] = parse(raw, nonce, len(self.plans[kind]))


def fixed_call(address, *args):
    if address not in (COPY, CACHE_CLEAR):
        raise ValueError('only fixed copy/cache helpers are available here')
    return 'osFuncCall ' + hex(address) + ' ' + str(len(args)) + ' ' + ' '.join(hex(x) for x in args)


def expected_blob(workspace):
    program = build(workspace)
    blob = bytearray(576)
    blob[:len(program['code'])] = program['code']
    blob[512:516] = bytes.fromhex('70014e75')
    return program, bytes(blob)


def validate_plan(plan, workspace):
    program, blob = expected_blob(workspace)
    if (plan.get('workspace') != workspace or plan.get('blob_sha256') != hashlib.sha256(blob).hexdigest()
            or not isinstance(plan.get('copies'), list) or not 1 <= len(plan['copies']) <= 160):
        raise ValueError('copy plan does not describe the fixed owned program')
    position = workspace
    for item in plan['copies']:
        if (not isinstance(item, list) or len(item) != 3 or any(type(x) is not int for x in item)):
            raise ValueError('invalid copy slice')
        source, destination, length = item
        if (not 1 <= length <= 64 or destination != position
                or not 0xa0001000 <= source <= 0xa0380000 - length
                or destination + length > workspace + len(blob)):
            raise ValueError('copy would leave the immutable image or owned workspace')
        position += length
    if position != workspace + len(blob):
        raise ValueError('copy plan has incomplete coverage')
    return program, blob


def read_bytes(client, address, length):
    return b''.join(client.memory(address + offset, min(128, length - offset))
                    for offset in range(0, length, 128))


def execute(cutoff, folder, proof_record, manifest, production_roundtrip=False):
    raise RuntimeError('hardware RAM execution disabled: first native trial stalled; recovery and independent ColdFire validation required')
    # Retain the attempted orchestration for review, not as an executable path.
    folder = Path(folder)
    if folder.exists():
        raise RuntimeError('use a new private operation directory; preserve previous evidence')
    if not {'command_payload', 'validate_reply'}.issubset(ReadSession.query.__code__.co_names):
        raise RuntimeError('matching transport hooks are required before opening USB')
    config = configuration()
    if (os.geteuid() != 0 or config['executor'] != 'local' or config['idle_driver'] != 'none'
            or config['small_query_bytes'] != 129):
        raise RuntimeError('require local root / none / alt0 /129 profile')
    if folder.parent != capture_directory(config):
        raise ValueError('operation directory must belong to configured private captures')
    folder.mkdir(mode=0o700)
    target = folder / 'result.json'
    for key, value in (('MACHINE_ID', config['machine_id']),
                       ('ADAPTER_DESCRIPTOR_SHA256', config['adapter_descriptor_sha256']),
                       ('QUEUE', config['queue']), ('URI', 'ipp://localhost:631/printers/' + config['queue']),
                       ('IDLE_DRIVER', None), ('IDLE_ALTERNATE', 0)):
        setattr(support, key, value)
    report = {'purpose': 'temporary_RAM_roundtrip', 'complete': False, 'workspace': None,
              'workspace_freed': False, 'production_roundtrip_requested': production_roundtrip,
              'production_rollback_verified': False, 'persistent_bypass_installed': False,
              'pump_commands_sent': 0, 'EEPROM_or_flash_commands_sent': 0,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    session = trace = client = None
    pending = False
    with usb_lock(config['lock_file']):
        before = support.snapshot(class_read=False)
        check_queue(before)
        adapter = idle_adapter(before['adapters'], support.__dict__)
        source = Path(proof_record)
        prior = json.loads(source.read_text())
        prior_batch = json.loads(source.with_name(source.stem + '-batch.json').read_text())
        if (prior.get('ram_live_proofs') != manifest or not prior['complete']
                or not prior_batch['hardware_cleanup_verified'] or not prior_batch['device_guard_cleared']
                or prior_batch['preflight']['btt_boot']['boot_id'] != before['btt_boot']['boot_id']
                or not 0 <= (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(
                    prior_batch['queries'][0]['observed_utc'])).total_seconds() <= 900):
            raise RuntimeError('fresh complete code proofs from this boot required')
        report['code_proof_record'] = str(source)
        with DeviceGuard(str(guard_path(config)), 'ram-rollback-roundtrip') as lease:
            was_loaded = Path('/sys/module/usbmon').exists()
            try:
                trace = USBTrace(int(adapter['busnum']), int(adapter['devnum']), cutoff)
                trace.start()
                session = RamSession(int(adapter['busnum']), int(adapter['devnum']), cutoff,
                                     refresh_id_each_query=True, comment_bytes=63)
                def check():
                    if trace.errors:
                        raise RuntimeError('USB trace stopped')
                    check_active(support.snapshot(class_read=False), before, os.getpid())
                with session:
                    client = BatchClient(cutoff, 'ram-rollback', 1, session, check)
                    client.state.update(print_jobs_created=False, investigation='temporary_RAM_roundtrip')
                    client.identify()
                    for kind in ('telemetry_diag_busy', 'telemetry_diag_printing', 'telemetry_diag_cover_open'):
                        if client.value(kind) != '0':
                            raise RuntimeError('printer is not idle and closed')
                    cache_bytes = client.memory(0xa038e40c, 20)
                    cacr, index_mask, cache_bytes_per_way, index_count, _ = struct.unpack('>5I', cache_bytes)
                    if (not cacr & 0x80000000 or not cacr & 0x10000000
                            or index_mask != 0x7f0 or cache_bytes_per_way != 0x800 or index_count != 0x80):
                        raise RuntimeError('cache configuration differs from the reviewed live profile')
                    report['cache_runtime_before'] = cache_bytes.hex()
                    def native(kind, commands):
                        nonlocal pending
                        session.schedule(kind, commands)
                        report['phase'] = kind + '_attempt_started'
                        pending = True
                        atomic_json(target, report)
                        reply = client.query(kind)
                        pending = False
                        report['phase'] = kind + '_reply_closed'
                        atomic_json(target, report)
                        return reply['transport']['native_results']
                    address, = native('ram_allocate', ['osMemAlloc 1024'])
                    report['workspace'] = address
                    atomic_json(target, report)
                    checked_workspace(address)
                    session.workspace = address
                    atomic_json(folder / 'allocation.json', {'workspace': address,
                        'bytes': ALLOCATION_BYTES, 'boot': before['btt_boot']['boot_id'],
                        'proof_record': str(source), 'native_program_sha256': hashlib.sha256(build(address)['code']).hexdigest()})
                    atomic_json(target, report)
                    plan_path = folder / 'copy-plan.json'
                    plan_deadline = time.monotonic() + 180
                    while not plan_path.exists() and time.monotonic() < plan_deadline:
                        if (cutoff - dt.datetime.now(dt.timezone.utc)).total_seconds() < 300:
                            raise RuntimeError('not enough time to load and free the workspace')
                        time.sleep(.25)
                    if not plan_path.exists():
                        raise RuntimeError('host copy plan did not arrive')
                    st = plan_path.lstat()
                    if not plan_path.is_file() or st.st_uid != 0 or st.st_mode & 0o077 or st.st_nlink != 1:
                        raise RuntimeError('copy plan ownership or permissions differ')
                    plan = json.loads(plan_path.read_text())
                    program, blob = validate_plan(plan, address)
                    copies = plan['copies']
                    for index in range(0, len(copies), 4):
                        commands = [fixed_call(COPY, *item) for item in copies[index:index + 4]]
                        native('ram_load_%03d' % index, commands)
                    loaded = read_bytes(client, address, len(blob))
                    if loaded != blob:
                        raise RuntimeError('constructed workspace bytes differ; do not execute')
                    report['constructed_bytes_verified'] = len(blob)
                    result, = native('ram_program_cache_clear', [fixed_call(CACHE_CLEAR, 0, address, len(blob))])
                    if result != 0:
                        raise RuntimeError('program cache clear failed')
                    for mode in ((0, 1) if production_roundtrip else (0,)):
                        if mode == 1 and not report.get('shadow_rollback_verified'):
                            raise RuntimeError('production change requires an accepted shadow roundtrip')
                        kind = 'ram_shadow' if mode == 0 else 'ram_production'
                        value, = native(kind, ['osFuncCall ' + hex(address) + ' 1 ' + str(mode)])
                        receipt = struct.unpack('>7I', client.memory(program['receipt'], 28))
                        original = 0x70014e75 if mode == 0 else 0x00006704
                        changed = 0x70024e75 if mode == 0 else 0x00004e71
                        if value != 7 or receipt != (MAGIC, 4, 7, original, changed, original, mode):
                            raise RuntimeError('native roundtrip did not prove change and restoration')
                        read_target = program['shadow_target'] if mode == 0 else PRODUCTION_WORD
                        if client.memory(read_target, 4) != struct.pack('>I', original):
                            raise RuntimeError('external restored-word readback differs')
                        report[kind + '_receipt'] = list(receipt)
                        report['shadow_rollback_verified' if mode == 0 else 'production_rollback_verified'] = True
                        atomic_json(target, report)
                    result, = native('ram_free', ['osMemFree ' + hex(address)])
                    if result != 0:
                        raise RuntimeError('owned workspace free was not acknowledged')
                    report['workspace_freed'] = True
                    client.identify()
                    report['complete'] = True
            except BaseException as error:
                report['error'] = str(error)
            finally:
                if session:
                    session.close()
                tr = trace.close() if trace else {'reader_closed': True,
                    'module_loaded_before': was_loaded, 'module_loaded_after': Path('/sys/module/usbmon').exists(), 'errors': []}
                after = support.snapshot(class_read=False)
                clean = restored(before, after, session, tr)
                safe = report['workspace_freed'] or (report['workspace'] is None and not pending)
                if clean and (session is None or session.stream_closed) and safe and not pending:
                    lease.clear()
                report.update(preflight=before, postflight=after, trace=tr,
                    hardware_cleanup_verified=clean, device_guard_cleared=lease.cleared,
                    queries=session.queries if session else [], controls=session.controls if session else [],
                    transport_cleanup=session.cleanup if session else {},
                    complete=report['complete'] and clean and lease.cleared and not tr['errors'])
                atomic_json(target, report)
    return target, report
