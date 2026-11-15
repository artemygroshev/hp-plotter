"""Offline check of the isolated worker copy; never opens USB.

Peripheral and accounting calls are stubbed in the emulator. GNU checks every
new instruction in the redirect/hook; the remaining 152 bytes must exactly
match the pinned HP body. The HP image is supplied locally, not distributed.
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
from setup_gate_map import IMAGE_SHA256, BASE
from setup_worker_clone import (build, WORKER_ADDRESS, WORKER_BYTES, IDS_STATE,
                                IDS_REQUEST, CALLBACK)


def check(image, assembler, objcopy, workspace):
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('require the pinned A04 image')
    stock = image[WORKER_ADDRESS - BASE:WORKER_ADDRESS - BASE + WORKER_BYTES]
    p = build(workspace, stock)
    assert p['worker_code'][:132] == stock[:132]
    assert p['worker_code'][140:] == stock[140:]
    checks = []
    with tempfile.TemporaryDirectory(prefix='hp-worker-clone-') as temporary:
        root = Path(temporary)
        for name, code, address in (('redirect', p['worker_code'][132:140], workspace + 132),
                                    ('hook', p['hook_code'], p['hook'])):
            source = source_for(code, address)
            for cpu in ('5206', '5307', '5475'):
                obj, binary = root / (name + cpu + '.o'), root / (name + cpu + '.bin')
                subprocess.run([assembler, '--register-prefix-optional', '-mcpu=' + cpu,
                    '-o', str(obj), '-'], input=source, text=True, capture_output=True,
                    check=True, timeout=20, env=dict(os.environ, LC_ALL='C'))
                subprocess.run([objcopy, '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                               capture_output=True, check=True, timeout=20)
                if binary.read_bytes() != code:
                    raise ValueError('new instruction encoding differs: ' + name + '/' + cpu)
                checks.append({'part': name, 'cpu': cpu, 'bytes': len(code), 'exact': True})

    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D7,
                                    UC_M68K_REG_A6, UC_M68K_REG_A7)
    emulations = []
    for copied, state, request, mask, monitor_active, expected in (
            (False, 35, 6, 10, 1, 0), (True, 35, 6, 10, 1, 1),
            (True, 1, 0, 10, 1, 0), (True, 26, 6, 10, 1, 0),
            (True, 35, 0, 10, 1, 0), (True, 35, 6, 2, 1, 0),
            (True, 35, 6, 1, 1, 1), (True, 35, 6, 10, 0, 1)):
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.mem_map(0xa0000000, 0x2000000)
        uc.mem_map(0x100000, 0x10000)
        uc.mem_write(WORKER_ADDRESS, stock)
        uc.mem_write(workspace, p['blob'])
        for address, value in ((IDS_STATE, state), (IDS_REQUEST, request), (CALLBACK, 0)):
            uc.mem_write(address, struct.pack('>I', value))
        functions = {0xa00f0924: monitor_active, 0xa0090d60: 0, 0xa00f0480: 0,
                     0xa00eefcc: 0, 0xa00fb4a0: mask, 0xa00fa1ac: 0}
        for address in functions:
            uc.mem_write(address, bytes.fromhex('4e75'))
        uc.reg_write(UC_M68K_REG_A7, 0x108000)
        uc.reg_write(UC_M68K_REG_A6, 0x11112222)
        uc.reg_write(UC_M68K_REG_D7, 0x33334444)
        uc.mem_write(0x108000, struct.pack('>2I', 0x101000, 0))
        calls, writes = [], []

        def called(machine, address, size, ignored):
            if address in functions:
                calls.append(address)
                machine.reg_write(UC_M68K_REG_D0, functions[address])

        def written(machine, access, address, size, value, ignored):
            writes.append(address)
            if not 0x100000 <= address < 0x110000:
                raise ValueError('worker directly wrote outside stack: ' + hex(address))

        uc.hook_add(UC_HOOK_CODE, called)
        uc.hook_add(UC_HOOK_MEM_WRITE, written)
        uc.emu_start(workspace if copied else WORKER_ADDRESS, 0x101000, count=2000)
        if (uc.reg_read(UC_M68K_REG_D0) != expected or uc.reg_read(UC_M68K_REG_A7) != 0x108004
                or uc.reg_read(UC_M68K_REG_A6) != 0x11112222
                or uc.reg_read(UC_M68K_REG_D7) != 0x33334444):
            raise ValueError('worker result, stack or callee-saved registers differ')
        expected_calls = [0xa00f0924, 0xa0090d60]
        if monitor_active:
            expected_calls += [0xa00f0480]
        expected_calls += [0xa00eefcc, 0xa00fb4a0]
        if expected == 0:
            expected_calls += [0xa00fa1ac]
        if calls != expected_calls:
            raise ValueError('unexpected peripheral/accounting call path')
        if bytes(uc.mem_read(WORKER_ADDRESS, WORKER_BYTES)) != stock:
            raise ValueError('stock worker changed')
        emulations.append({'copied': copied, 'state': state, 'request': request,
            'mask': mask, 'monitor_active': monitor_active, 'result': expected,
            'stubbed_calls': [hex(x) for x in calls]})
    return {'scope': 'offline_with_stubbed_peripherals', 'workspace': hex(workspace),
            'unchanged_stock_body_bytes': 152, 'GNU_checks': checks,
            'emulations': emulations, 'device_commands': 0,
            'real_Setup_procedure_proven': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine_image', type=Path)
    parser.add_argument('--assembler', default='m68k-linux-gnu-as')
    parser.add_argument('--objcopy', default='m68k-linux-gnu-objcopy')
    parser.add_argument('--workspace', type=lambda s: int(s, 0), default=0xa0800000)
    args = parser.parse_args()
    print(json.dumps(check(args.engine_image.read_bytes(), args.assembler,
                           args.objcopy, args.workspace), indent=2))


if __name__ == '__main__':
    main()
