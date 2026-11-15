"""Scoped recognition and restoration, with the worker/peripherals absent."""
import hashlib
import struct
import unittest

from ram_rollback_program import IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR
from setup_scoped_roundtrip import (build, build_hook, scoped_decision, validate_plan,
    PATCH_ADDRESS, IDS_STATE, IDS_REQUEST, ORIGINAL_WORDS, SCOPED_JUMP_WORD,
    CALLBACK_HANDLE, CACHED_AND, TAIL_ENTRY, RECEIPT_WORDS)


class ScopedSetupChecks(unittest.TestCase):
    def emulate(self, state=1, request=0, callback=0, mask=10,
                wrong_word=False, fail_cache=0):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D2, UC_M68K_REG_D3,
            UC_M68K_REG_D7, UC_M68K_REG_A6, UC_M68K_REG_A7, UC_M68K_REG_SR)
        p = build(0xa0800000)
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.mem_map(0xa0000000, 0x1000000)
        uc.mem_map(0x100000, 0x10000)
        uc.mem_write(p['workspace'], p['blob'])
        stock = bytes.fromhex('508f080000006704700160084eb9a00fa1ac70002e2efffc4e5e4e75')
        if wrong_word:
            stock = b'\x11\x22\x33\x44' + stock[4:]
        uc.mem_write(PATCH_ADDRESS, stock)
        for address, value in ((IDS_STATE, state), (IDS_REQUEST, request),
                               (CALLBACK_HANDLE, callback), (CACHED_AND, mask)):
            uc.mem_write(address, struct.pack('>I', value))
        for address in (IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR, 0xa00fa1ac):
            uc.mem_write(address, bytes.fromhex('4e75'))
        uc.reg_write(UC_M68K_REG_SR, 0x2300)
        uc.reg_write(UC_M68K_REG_A7, 0x108000)
        uc.mem_write(0x108000, struct.pack('>I', 0x101000))
        preserved = (UC_M68K_REG_D2, UC_M68K_REG_D3, UC_M68K_REG_D7, UC_M68K_REG_A6)
        for i, register in enumerate(preserved):
            uc.reg_write(register, 0x11110000 + i)
        calls, writes, caches = [], [], []
        def word(address):
            return struct.unpack('>I', uc.mem_read(address, 4))[0]
        def visit(machine, address, size, ignored):
            if address == IRQ_LOCK:
                calls.append(('lock',))
                machine.reg_write(UC_M68K_REG_D0, machine.reg_read(UC_M68K_REG_SR))
                machine.reg_write(UC_M68K_REG_SR, 0x2700)
            elif address == IRQ_UNLOCK:
                self.assertEqual(bytes(machine.mem_read(PATCH_ADDRESS, len(stock))), stock)
                self.assertEqual(word(IDS_STATE), state)
                calls.append(('unlock',))
                machine.reg_write(UC_M68K_REG_SR, word(machine.reg_read(UC_M68K_REG_A7) + 4))
            elif address == CACHE_CLEAR:
                sp = machine.reg_read(UC_M68K_REG_A7)
                self.assertEqual(tuple(word(sp + x) for x in (4, 8, 12)), (0, PATCH_ADDRESS, 8))
                caches.append(address)
                machine.reg_write(UC_M68K_REG_D0, 0xffffffff if len(caches) == fail_cache else 0)
            elif address == TAIL_ENTRY:
                calls.append(('tail', word(IDS_STATE)))
            elif address == 0xa00fa1ac:
                self.assertEqual(word(CALLBACK_HANDLE), 0)
                calls.append(('null_UI',))
        def written(machine, access, address, size, value, ignored):
            if PATCH_ADDRESS <= address < PATCH_ADDRESS + 8 or address == IDS_STATE:
                self.assertEqual(size, 4)
                self.assertEqual(address % 4, 0)
                self.assertEqual(machine.reg_read(UC_M68K_REG_SR) & 0x700, 0x700)
                writes.append((address, value))
            elif not 0x100000 <= address < 0x110000:
                self.assertTrue(p['receipt'] <= address < p['receipt'] + 4 * RECEIPT_WORDS, hex(address))
        uc.hook_add(UC_HOOK_CODE, visit)
        uc.hook_add(UC_HOOK_MEM_WRITE, written)
        uc.emu_start(p['workspace'], 0x101000, count=2000)
        self.assertEqual(bytes(uc.mem_read(PATCH_ADDRESS, len(stock))), stock)
        self.assertEqual(word(IDS_STATE), state)
        self.assertEqual(uc.reg_read(UC_M68K_REG_A7), 0x108004)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0xff00, 0x2300)
        for i, register in enumerate(preserved):
            self.assertEqual(uc.reg_read(register), 0x11110000 + i)
        receipt = struct.unpack('>' + str(RECEIPT_WORDS) + 'I', uc.mem_read(p['receipt'], 4 * RECEIPT_WORDS))
        self.assertEqual(calls.count(('lock',)), 1)
        self.assertEqual(calls.count(('unlock',)), 1)
        return uc.reg_read(UC_M68K_REG_D0), receipt, calls, writes

    def test_real_tail_override_only_in_setup_and_restores_state_and_code(self):
        flags, receipt, calls, writes = self.emulate()
        self.assertEqual(flags, 7)
        self.assertEqual(receipt, build(0xa0800000)['expected_receipt'])
        self.assertEqual([x[1] for x in calls if x[0] == 'tail'], [1, 1, 35, 26, 1])
        self.assertEqual([v for a, v in writes if a == IDS_STATE], [35, 26, 1])
        self.assertEqual([v for a, v in writes if a == PATCH_ADDRESS],
                         [SCOPED_JUMP_WORD, ORIGINAL_WORDS[0]])
        self.assertEqual(calls.count(('null_UI',)), 4)

    def test_nonidle_or_changed_prerequisite_never_patches_or_changes_state(self):
        for options in ({'state': 35}, {'request': 1}, {'callback': 0xa0500000},
                        {'mask': 11}, {'wrong_word': True}):
            with self.subTest(options=options):
                flags, _, calls, writes = self.emulate(**options)
                self.assertEqual((flags, writes), (0, []))
                self.assertFalse(any(x[0] == 'tail' for x in calls))

    def test_cache_failure_still_restores_code_and_state_before_unlock(self):
        for failure, expected_flags in ((1, 6), (2, 5)):
            with self.subTest(cache_failure=failure):
                flags, _, _, writes = self.emulate(fail_cache=failure)
                self.assertEqual(flags, expected_flags)
                self.assertIn((PATCH_ADDRESS, ORIGINAL_WORDS[0]), writes)
                self.assertIn((IDS_STATE, 1), writes)

    def test_hook_machine_code_preserves_stock_behavior_outside_exact_scope(self):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN
        from unicorn.m68k_const import UC_M68K_REG_D0, UC_M68K_REG_A7, UC_M68K_REG_SR
        for state in range(64):
            for mask in (0, 1, 2, 3, 10, 11, 0x0100000a, 0xffffffff):
                uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
                uc.mem_map(0xa0000000, 0x1000000)
                uc.mem_map(0x100000, 0x10000)
                uc.mem_write(0xa0800000, build_hook())
                uc.mem_write(IDS_STATE, struct.pack('>I', state))
                uc.mem_write(0xa00f179c, bytes.fromhex('70014e75'))
                uc.mem_write(0xa00f17a0, bytes.fromhex('70004e75'))
                uc.reg_write(UC_M68K_REG_SR, 0x2700)
                uc.reg_write(UC_M68K_REG_A7, 0x108000)
                uc.mem_write(0x108000, struct.pack('>I', 0x101000))
                uc.reg_write(UC_M68K_REG_D0, mask)
                uc.emu_start(0xa0800000, 0x101000, count=30)
                self.assertEqual(uc.reg_read(UC_M68K_REG_D0), scoped_decision(state, mask), (state, mask))
        for invalid in ((True, 10), (-1, 10), (35, 0x100000000)):
            with self.assertRaises(ValueError):
                scoped_decision(*invalid)

    def test_layout_and_copy_budget_require_owned_workspace_and_reserved_cleanup(self):
        p = build(0xa0800000)
        self.assertLessEqual(len(p['code']), 640)
        self.assertLessEqual(len(p['hook_code']), 64)
        self.assertEqual(len(p['blob']), 832)
        copies = [[0xa0001000, p['workspace'] + x, min(64, 832 - x)] for x in range(0, 832, 64)]
        plan = {'workspace': p['workspace'], 'blob_sha256': hashlib.sha256(p['blob']).hexdigest(), 'copies': copies}
        self.assertLessEqual(validate_plan(plan, p['workspace'], 14)[1]['maximum_total_queries'], 87)
        with self.assertRaises(ValueError):
            validate_plan(plan, p['workspace'], 80)
        bad = {**plan, 'copies': [row[:] for row in copies]}
        bad['copies'][0][1] = PATCH_ADDRESS
        with self.assertRaises(ValueError):
            validate_plan(bad, p['workspace'], 14)


if __name__ == '__main__':
    unittest.main()
