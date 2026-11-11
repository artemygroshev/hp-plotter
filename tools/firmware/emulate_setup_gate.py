"""Run the original and candidate final Setup bit test in a local M68K emulator.

Requires Unicorn 2.1.4 and a locally supplied pinned HP engine image. Only the
small final predicate runs; the error callback is replaced with an RTS stub.
No printer, peripheral, complete servicing worker or priming cycle is emulated.
"""
import argparse
import json
from pathlib import Path

from setup_gate_map import BASE, extract


def emulate(data):
    extract(data)  # Pin image and expected instructions before emulation.
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_M68K_REG_D0, UC_M68K_REG_A7, UC_M68K_REG_SR
    cases = []
    for patched in (False, True):
        for mask in (0, 1, 2, 3, 0x0100000a, 0xffffffff):
            machine = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
            machine.mem_map(0xa00f0000, 0x10000)
            machine.mem_map(0x100000, 0x10000)
            machine.mem_write(0xa00f1796, data[0xa00f1796-BASE:0xa00f17a8-BASE])
            machine.mem_write(0xa00fa1ac, bytes.fromhex('4e75'))
            if patched:
                machine.mem_write(0xa00f179a, bytes.fromhex('4e71'))
            machine.reg_write(UC_M68K_REG_SR, 0x2700)
            machine.reg_write(UC_M68K_REG_A7, 0x108000)
            machine.reg_write(UC_M68K_REG_D0, mask)
            callbacks = []
            def visit(uc, address, size, user_data):
                if address == 0xa00fa1ac:
                    callbacks.append(address)
            machine.hook_add(UC_HOOK_CODE, visit)
            machine.emu_start(0xa00f1796, 0xa00f17a8, count=50)
            result = machine.reg_read(UC_M68K_REG_D0)
            if result != (1 if patched or mask & 1 else 0):
                raise RuntimeError('candidate or original predicate returned an unexpected result')
            if len(callbacks) != (0 if patched or mask & 1 else 1):
                raise RuntimeError('unexpected error-branch behavior')
            cases.append({'patched': patched, 'input_mask': hex(mask),
                          'return': result, 'error_callback_calls': len(callbacks)})
    return {'scope': 'isolated_final_predicate_only', 'device_patch_applied': False,
            'full_priming_emulated': False, 'error_callback_is_RTS_stub': True,
            'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine_image', type=Path)
    args = parser.parse_args()
    print(json.dumps(emulate(args.engine_image.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
