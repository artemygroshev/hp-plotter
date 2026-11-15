"""Check the real A04 IDS dispatcher and a one-shot route offline.

The caller supplies the official image. Kernel, mechanical, accounting and UI
calls are stubbed. This does not emulate the scheduler, physical preparation,
cache or cancellation, and never opens USB. It cannot confirm an HP Setup test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from check_ram_coldfire import source_for
from setup_gate_map import BASE, IMAGE_SHA256
from setup_ids_route import build, CASE_SLOT, STOCK_CASE, DISPATCH_CONTINUE
from setup_worker_clone import WORKER_ADDRESS, WORKER_BYTES, IDS_STATE, IDS_REQUEST

SUBMIT = 0xa00f10f8
ACTION = 0xa00f73c0
WORKER_LOOP = 0xa00f1208
MUTEX = 0xa039d3ac
MUTEX_VALUE = 0xa1e95c8c
KERNEL = (0xa0292c7c, 0xa0292da8, 0xa02931e4)


def check(image, assembler, objcopy, workspace):
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('require the pinned official A04 image')
    worker = image[WORKER_ADDRESS - BASE:WORKER_ADDRESS - BASE + WORKER_BYTES]
    program = build(workspace, worker)
    if struct.unpack_from('>I', image, CASE_SLOT - BASE)[0] != STOCK_CASE:
        raise ValueError('stock request6 dispatch target differs')
    transitions = []
    for index in range(348):
        address = 0xa039d3fc + 28 * index
        state, kind, event, timeout, guard, following, action = struct.unpack_from(
            '>7I', image, address - BASE)
        if state == 35 and ((kind == 0 and event in (2, 7, 17, 18)) or kind == 1):
            transitions.append({'address': hex(address), 'type': kind, 'event': event,
                'timeout_raw': timeout, 'guard': guard, 'following': following, 'action': hex(action)})
    by_event = {row['event']: row for row in transitions if row['type'] == 0}
    if (by_event[17]['following'], by_event[18]['following']) != (37, 21):
        raise ValueError('Setup result transitions differ')
    for event in (2, 7):
        if (by_event[event]['following'], by_event[event]['action']) != (35, '0x0'):
            raise ValueError('IDS cancel behavior differs')
    timeout_row, = [row for row in transitions if row['type'] == 1]
    if (timeout_row['following'], timeout_row['action']) != (35, '0xa00f7484'):
        raise ValueError('Setup timeout is not the expected progress-only self transition')
    route_checks = []
    with tempfile.TemporaryDirectory(prefix='hp-ids-route-') as temporary:
        root = Path(temporary)
        source = source_for(program['route_code'], program['route'])
        for cpu in ('5206', '5307', '5475'):
            obj, binary = root / (cpu + '.o'), root / (cpu + '.bin')
            subprocess.run([assembler, '--register-prefix-optional', '-mcpu=' + cpu,
                            '-o', str(obj), '-'], input=source, text=True,
                           capture_output=True, check=True, timeout=20,
                           env=dict(os.environ, LC_ALL='C'))
            subprocess.run([objcopy, '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                           capture_output=True, check=True, timeout=20)
            if binary.read_bytes() != program['route_code']:
                raise ValueError('route instruction encoding differs: ' + cpu)
            route_checks.append({'cpu': cpu, 'bytes': len(program['route_code']), 'exact': True})

    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.m68k_const import UC_M68K_REG_D0, UC_M68K_REG_A7

    def machine():
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.mem_map(0xa0000000, 0x2000000); uc.mem_map(0x100000, 0x10000)
        uc.mem_write(BASE, image); uc.mem_write(workspace, program['blob'])
        uc.mem_write(MUTEX, struct.pack('>I', MUTEX_VALUE))
        uc.reg_write(UC_M68K_REG_A7, 0x108000)
        return uc

    def word(uc, address): return struct.unpack('>I', uc.mem_read(address, 4))[0]
    def put(uc, address, value): uc.mem_write(address, struct.pack('>I', value))
    def arguments(uc, count):
        sp = uc.reg_read(UC_M68K_REG_A7)
        return [word(uc, sp + 4 + i * 4) for i in range(count)]
    def stub(uc, addresses):
        for address in addresses: uc.mem_write(address, bytes.fromhex('4e75'))

    # Execute the actual stock action entering state35. Stub the dispatcher
    # itself here to inspect all six arguments, including both wait flags.
    uc = machine(); action_calls = []
    stub(uc, (SUBMIT, 0xa00fb930, 0xa00fb868, 0xa03087dc))
    put(uc, 0x108000, 0x101000)
    def action_visit(m, address, size, ignored):
        if address == SUBMIT:
            action_calls.append(arguments(m, 6)); m.reg_write(UC_M68K_REG_D0, 0)
    uc.hook_add(UC_HOOK_CODE, action_visit)
    uc.emu_start(ACTION, 0x101000, count=2000)
    if action_calls != [[3, 0, 0, 0, 1, 1], [6, 1, 17, 18, 0, 0]]:
        raise ValueError('stock mechanical-preparation/Setup sequence differs')

    # Execute the real dispatcher, not a host model. wait_available=0 and
    # wait_complete=0 avoid its condition-variable waits. The initial mutex
    # acquisition still uses an infinite timeout; no hardware bound is claimed.
    submissions = []
    for busy in (0, 3, 6, 8):
        uc = machine(); stub(uc, KERNEL); put(uc, IDS_REQUEST, busy)
        args = [6, 1, 17, 18, 0, 0]
        uc.mem_write(0x108000, struct.pack('>7I', 0x101000, *args)); kernel_calls = []
        def submit_visit(m, address, size, ignored):
            if address in KERNEL:
                count = 2 if address == KERNEL[0] else 1
                actual = arguments(m, count); kernel_calls.append([hex(address), actual])
                if actual[0] != MUTEX_VALUE:
                    raise ValueError('wrong dispatcher mutex argument')
                m.reg_write(UC_M68K_REG_D0, 0)
            elif address == 0xa0292ed0:
                raise ValueError('unexpected wait in nonwaiting submission')
        uc.hook_add(UC_HOOK_CODE, submit_visit)
        uc.emu_start(SUBMIT, 0x101000, count=1000)
        expected = 0 if busy == 0 else 0xffffffff
        if (uc.reg_read(UC_M68K_REG_D0) != expected or
                word(uc, IDS_REQUEST) != (6 if busy == 0 else busy) or
                uc.reg_read(UC_M68K_REG_A7) != 0x108004):
            raise ValueError('stock submission result/request/stack differs')
        if busy == 0 and (bytes(uc.mem_read(0xa039d3a8, 1)) != b'\x01' or
                         [word(uc, a) for a in (0xa039d3bc, 0xa039d3c0)] != [17, 18]):
            raise ValueError('success/failure notification fields differ')
        submissions.append({'previous_request': busy, 'return_u32': expected,
                            'kernel_calls': kernel_calls})

    # Execute the real request6 switch case and its real result-notification
    # path. Peripheral calls are stubs; no real FSM events are delivered.
    executions = []
    cases = [(False, 35, 10, False, 0), (True, 35, 10, False, 1),
             (True, 26, 10, False, 0), (True, 1, 10, False, 0),
             (True, 35, 2, False, 0), (True, 35, 1, False, 1),
             (True, 35, 10, True, None)]
    for routed, state, mask, blocked, expected in cases:
        uc = machine(); peripheral = {0xa00f0924: 1, 0xa0090d60: 0,
            0xa00f0480: 0, 0xa00eefcc: 0, 0xa00fb4a0: mask, 0xa00fa1ac: 0}
        stub(uc, KERNEL + tuple(peripheral) + (0xa00fb7f8,))
        put(uc, IDS_REQUEST, 6); put(uc, IDS_STATE, state)
        put(uc, 0xa039d3bc, 17); put(uc, 0xa039d3c0, 18)
        uc.mem_write(0xa039d3a8, b'\x01')
        if routed: put(uc, CASE_SLOT, program['route'])
        put(uc, 0x108000, 0x101000)
        visits, calls, events, slot_writes, direct_writes = [], [], [], [], []
        def worker_visit(m, address, size, ignored):
            if address == 0xa00f1240:
                visits.append(address)
                if len(visits) == 2: m.emu_stop()
            if address in KERNEL: m.reg_write(UC_M68K_REG_D0, 0)
            elif address in peripheral:
                if word(m, CASE_SLOT) != STOCK_CASE:
                    raise ValueError('route was not restored before peripheral call')
                calls.append(hex(address)); m.reg_write(UC_M68K_REG_D0, peripheral[address])
                if blocked and address == 0xa0090d60: m.emu_stop()
            elif address == 0xa00fb7f8:
                events.append(arguments(m, 2)); m.reg_write(UC_M68K_REG_D0, 0)
        def written(m, access, address, size, value, ignored):
            if 0x100000 <= address < 0x110000: return
            direct_writes.append([hex(address), size, value])
            if address == CASE_SLOT:
                if (size, value) != (4, STOCK_CASE): raise ValueError('invalid slot restore')
                slot_writes.append(value)
            elif address == IDS_REQUEST:
                if (size, value) != (4, 0): raise ValueError('invalid stock request clear')
            elif not program['receipt'] <= address < program['receipt'] + 16:
                raise ValueError('unexpected direct worker write: ' + hex(address))
        uc.hook_add(UC_HOOK_CODE, worker_visit); uc.hook_add(UC_HOOK_MEM_WRITE, written)
        uc.emu_start(WORKER_LOOP, 0x101000, count=3000)
        receipt = [word(uc, program['receipt'] + i * 4) for i in range(4)]
        if word(uc, CASE_SLOT) != STOCK_CASE or slot_writes != ([STOCK_CASE] if routed else []):
            raise ValueError('dispatch slot restoration differs')
        if blocked:
            if events or receipt[0] != 1 or word(uc, IDS_REQUEST) != 6 or len(visits) != 1:
                raise ValueError('blocked worker incorrectly claimed completion')
        else:
            if events != [[17 if expected else 18, 0]] or word(uc, IDS_REQUEST) != 0 or len(visits) != 2:
                raise ValueError('stock completion event/request clear differs')
            if routed and receipt != [2, expected, state, 6]:
                raise ValueError('route receipt differs')
        if bytes(uc.mem_read(WORKER_ADDRESS, WORKER_BYTES)) != worker:
            raise ValueError('stock worker was changed')
        executions.append({'routed': routed, 'state': state, 'mask': mask, 'blocked_stub': blocked,
            'expected_result': expected, 'receipt': receipt, 'events_enqueued_to_stub': events,
            'peripheral_calls_stubbed': calls, 'direct_writes': direct_writes,
            'stock_slot_restored': True, 'pending_request': word(uc, IDS_REQUEST)})
    return {'scope': 'offline_stock_IDS_with_stubbed_kernel_and_peripherals',
            'workspace': hex(workspace), 'route_bytes': len(program['route_code']),
            'GNU_checks': route_checks, 'stock_action_dispatch_arguments': action_calls,
            'stock_Setup_transitions': transitions,
            'nonwaiting_submissions': submissions, 'worker_executions': executions,
            'scheduler_cache_and_cancellation_not_emulated': True,
            'initial_dispatch_mutex_timeout_is_infinite': True,
            'IDS_KEY_CANCEL_does_not_abort_state35': True,
            'device_commands': 0, 'real_Setup_test_verified': False,
            'live_coordinator_available': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine_image', type=Path)
    parser.add_argument('--assembler', default='m68k-linux-gnu-as')
    parser.add_argument('--objcopy', default='m68k-linux-gnu-objcopy')
    parser.add_argument('--workspace', type=lambda value: int(value, 0), default=0xa0800000)
    args = parser.parse_args()
    print(json.dumps(check(args.engine_image.read_bytes(), args.assembler, args.objcopy,
                           args.workspace), indent=2))


if __name__ == '__main__': main()
