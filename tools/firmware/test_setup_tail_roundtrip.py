import struct
import unittest
import hashlib

from setup_tail_roundtrip import build, validate_plan, CALLBACK_HANDLE, CACHED_AND, ORIGINAL, CHANGED, TAIL_ENTRY
from ram_rollback_program import IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR, PRODUCTION_WORD


class SetupTailChecks(unittest.TestCase):
    def emulate(self, state=1, request=0, callback=0, mask=10, wrong_word=False, fail_cache=0):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D2, UC_M68K_REG_D3,
            UC_M68K_REG_D4, UC_M68K_REG_D5, UC_M68K_REG_D6, UC_M68K_REG_D7,
            UC_M68K_REG_A2, UC_M68K_REG_A6, UC_M68K_REG_A7, UC_M68K_REG_SR)
        program = build(0xa0800000)
        machine = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        machine.mem_map(0xa0000000, 0x1000000)
        machine.mem_map(0x100000, 0x10000)
        machine.mem_write(program['workspace'], program['blob'])
        # The real stock tail; the callback's null-handle path is stubbed.
        machine.mem_write(TAIL_ENTRY, bytes.fromhex('080000006704700160084eb9a00fa1ac70002e2efffc4e5e4e75'))
        if wrong_word:
            machine.mem_write(PRODUCTION_WORD, struct.pack('>I', 0x11223344))
        initial = 0x11223344 if wrong_word else ORIGINAL
        for address, value in ((0xa039d3e4, state), (0xa039d3b0, request),
                               (CALLBACK_HANDLE, callback), (CACHED_AND, mask)):
            machine.mem_write(address, struct.pack('>I', value))
        for address in (IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR, 0xa00fa1ac):
            machine.mem_write(address, bytes.fromhex('4e75'))
        machine.reg_write(UC_M68K_REG_SR, 0x2300)
        machine.reg_write(UC_M68K_REG_A7, 0x108000)
        machine.mem_write(0x108000, struct.pack('>I', 0x101000))
        preserved = (UC_M68K_REG_D2, UC_M68K_REG_D3, UC_M68K_REG_D4,
                     UC_M68K_REG_D5, UC_M68K_REG_D6, UC_M68K_REG_D7,
                     UC_M68K_REG_A2, UC_M68K_REG_A6)
        for index, register in enumerate(preserved):
            machine.reg_write(register, 0x11110000 + index)
        calls, writes, cache_calls = [], [], []
        def word(address):
            return struct.unpack('>I', machine.mem_read(address, 4))[0]
        def visit(uc, address, size, user_data):
            if address == IRQ_LOCK:
                calls.append('lock')
                uc.reg_write(UC_M68K_REG_D0, uc.reg_read(UC_M68K_REG_SR))
                uc.reg_write(UC_M68K_REG_SR, 0x2700)
            elif address == IRQ_UNLOCK:
                calls.append('unlock')
                self.assertEqual(word(PRODUCTION_WORD), initial)
                uc.reg_write(UC_M68K_REG_SR, word(uc.reg_read(UC_M68K_REG_A7) + 4))
            elif address == CACHE_CLEAR:
                sp = uc.reg_read(UC_M68K_REG_A7)
                self.assertEqual(tuple(word(sp + offset) for offset in (4, 8, 12)),
                                 (0, PRODUCTION_WORD, 4))
                cache_calls.append(address)
                uc.reg_write(UC_M68K_REG_D0, 0xffffffff if len(cache_calls) == fail_cache else 0)
            elif address == TAIL_ENTRY:
                calls.append('tail')
            elif address == 0xa00fa1ac:
                self.assertEqual(word(CALLBACK_HANDLE), 0)
                calls.append('null_callback_path')
        def written(uc, access, address, size, value, user_data):
            if address == PRODUCTION_WORD:
                self.assertEqual(size, 4)
                self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x700, 0x700)
                writes.append(value)
            elif not 0x100000 <= address < 0x110000:
                self.assertTrue(program['receipt'] <= address < program['receipt'] + 40, hex(address))
        machine.hook_add(UC_HOOK_CODE, visit)
        machine.hook_add(UC_HOOK_MEM_WRITE, written)
        machine.emu_start(program['workspace'], 0x101000, count=1500)
        self.assertEqual(word(PRODUCTION_WORD), initial)
        self.assertEqual(machine.reg_read(UC_M68K_REG_A7), 0x108004)
        self.assertEqual(machine.reg_read(UC_M68K_REG_SR) & 0xff00, 0x2300)
        for index, register in enumerate(preserved):
            self.assertEqual(machine.reg_read(register), 0x11110000 + index)
        receipt = struct.unpack('>10I', machine.mem_read(program['receipt'], 40))
        self.assertEqual(calls.count('lock'), 1)
        self.assertEqual(calls.count('unlock'), 1)
        return machine.reg_read(UC_M68K_REG_D0), receipt, calls, writes

    def test_actual_tail_decisions_change_and_restore_without_worker_dispatch(self):
        flags, receipt, calls, writes = self.emulate()
        self.assertEqual(flags, 7)
        self.assertEqual(receipt, build(0xa0800000)['expected_receipt'])
        self.assertEqual(calls.count('tail'), 3)
        self.assertEqual(calls.count('null_callback_path'), 2)
        self.assertEqual(writes, [CHANGED, ORIGINAL])

    def test_active_callback_or_nonidle_context_never_enters_tail(self):
        for options in ({'state': 35}, {'request': 1}, {'callback': 0xa0500000},
                        {'mask': 11}, {'wrong_word': True}):
            with self.subTest(options=options):
                flags, _, calls, writes = self.emulate(**options)
                self.assertEqual((flags, writes), (0, []))
                self.assertNotIn('tail', calls)

    def test_cache_failure_still_stores_the_original_word(self):
        for failure, expected in ((1, 6), (2, 5)):
            with self.subTest(failure=failure):
                flags, _, _, writes = self.emulate(fail_cache=failure)
                self.assertEqual(flags, expected)
                self.assertEqual(writes[-1], ORIGINAL)

    def test_wrapper_and_receipt_do_not_overlap(self):
        program = build(0xa0800000)
        self.assertLessEqual(len(program['code']), 512)
        self.assertLessEqual(program['wrapper'] + len(program['wrapper_code']), program['receipt'])
        self.assertEqual(len(program['blob']), 576)

    def test_copy_count_is_bounded_by_remaining_queries_and_cleanup(self):
        workspace = 0xa0800000
        program = build(workspace)
        copies = []
        position = workspace
        for length in [4] * 93 + [3] * 68:
            copies.append([0xa0001000, position, length])
            position += length
        plan = {'workspace': workspace, 'blob_sha256': hashlib.sha256(program['blob']).hexdigest(),
                'copies': copies}
        self.assertEqual(len(copies), 161)
        _, budget = validate_plan(plan, workspace, 26)
        self.assertEqual(budget['maximum_total_queries'], 79)
        with self.assertRaises(ValueError):
            validate_plan(plan, workspace, 35)
        bad = {**plan, 'copies': [row[:] for row in copies]}
        bad['copies'][0][1] = PRODUCTION_WORD
        with self.assertRaises(ValueError):
            validate_plan(bad, workspace, 26)


if __name__ == '__main__':
    unittest.main()
