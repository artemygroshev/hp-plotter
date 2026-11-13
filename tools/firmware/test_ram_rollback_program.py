import struct
import unittest

from ram_rollback_program import (build, CACHE_CLEAR, IRQ_LOCK, IRQ_UNLOCK, MAGIC,
                                 PRODUCTION_WORD, Code, validate_instruction_subset)


class RollbackProgramTests(unittest.TestCase):
    def test_coldfire_rejects_old_immediate_to_absolute_move(self):
        old = bytes.fromhex('23fc48505242a1ffe1a8')
        with self.assertRaises(ValueError):
            validate_instruction_subset(old)
        code = Code()
        code.store(MAGIC, 0xa1ffe1a8)
        self.assertEqual(code.finish().hex(), '203c4850524223c0a1ffe1a8')
        self.assertEqual([size for _, size, _ in validate_instruction_subset(code.finish())], [6, 6])
        code = Code()
        code.store(4, 0xa1ffe1a8)
        self.assertEqual(code.finish().hex(), '700423c0a1ffe1a8')
        self.assertEqual([size for _, size, _ in validate_instruction_subset(code.finish())], [2, 6])

    def test_subset_rejects_partial_unknown_and_mid_instruction_branches(self):
        for data in (bytes.fromhex('203c0000'), bytes.fromhex('4afc'),
                     bytes.fromhex('66000003203c000000014e75')):
            with self.subTest(data=data.hex()), self.assertRaises(ValueError):
                validate_instruction_subset(data)
        for workspace in (0xa0800000, 0xa1ffdf88):
            instructions = validate_instruction_subset(build(workspace)['code'])
            self.assertTrue(all(size <= 6 for _, size, _ in instructions))

    def run_machine(self, mode, state=1, request=0, wrong_word=False, fail_cache=0):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D2, UC_M68K_REG_D3,
            UC_M68K_REG_D4, UC_M68K_REG_D5, UC_M68K_REG_D6, UC_M68K_REG_A2,
            UC_M68K_REG_A7, UC_M68K_REG_SR)
        p = build(0xa0800000)
        machine = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        machine.mem_map(0xa0000000, 0x1000000)
        machine.mem_map(0x100000, 0x10000)
        machine.mem_write(p['workspace'], p['code'])
        machine.mem_write(p['shadow_target'], bytes.fromhex('70014e75'))
        machine.mem_write(PRODUCTION_WORD, struct.pack('>I', 0x00006704))
        target = PRODUCTION_WORD if mode == 1 else p['shadow_target']
        original = 0x00006704 if mode == 1 else 0x70014e75
        if wrong_word:
            machine.mem_write(target, struct.pack('>I', 0x11223344))
            original = 0x11223344
        machine.mem_write(0xa039d3e4, struct.pack('>I', state))
        machine.mem_write(0xa039d3b0, struct.pack('>I', request))
        for address in (IRQ_LOCK, IRQ_UNLOCK, CACHE_CLEAR):
            machine.mem_write(address, bytes.fromhex('4e75'))
        machine.reg_write(UC_M68K_REG_SR, 0x2300)
        machine.reg_write(UC_M68K_REG_A7, 0x108000)
        machine.mem_write(0x108000, struct.pack('>II', 0x101000, mode))
        preserved = (UC_M68K_REG_D2, UC_M68K_REG_D3, UC_M68K_REG_D4,
                     UC_M68K_REG_D5, UC_M68K_REG_D6, UC_M68K_REG_A2)
        for index, register in enumerate(preserved):
            machine.reg_write(register, 0x11110000 + index)
        calls = []
        target_writes = []
        cache_calls = []
        def word(address):
            return struct.unpack('>I', machine.mem_read(address, 4))[0]
        def visit(uc, address, size, user_data):
            if address == IRQ_LOCK:
                calls.append('lock')
                uc.reg_write(UC_M68K_REG_D0, uc.reg_read(UC_M68K_REG_SR))
                uc.reg_write(UC_M68K_REG_SR, 0x2700)
            elif address == IRQ_UNLOCK:
                calls.append('unlock')
                self.assertEqual(word(target), original)
                uc.reg_write(UC_M68K_REG_SR, word(uc.reg_read(UC_M68K_REG_A7) + 4))
            elif address == CACHE_CLEAR:
                sp = uc.reg_read(UC_M68K_REG_A7)
                self.assertEqual(tuple(word(sp + offset) for offset in (4, 8, 12)), (0, target, 4))
                self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x700, 0x700)
                cache_calls.append(address)
                uc.reg_write(UC_M68K_REG_D0, 0xffffffff if len(cache_calls) == fail_cache else 0)
            elif address == p['shadow_target']:
                calls.append('shadow')
        def written(uc, access, address, size, value, user_data):
            if address == target:
                self.assertEqual(size, 4)
                self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x700, 0x700)
                target_writes.append(value)
            elif 0x100000 <= address < 0x110000:
                pass
            else:
                self.assertTrue(p['receipt'] <= address < p['receipt'] + 28, hex(address))
        machine.hook_add(UC_HOOK_CODE, visit)
        machine.hook_add(UC_HOOK_MEM_WRITE, written)
        machine.emu_start(p['workspace'], 0x101000, count=1000)
        self.assertEqual(word(target), original)
        self.assertEqual(machine.reg_read(UC_M68K_REG_SR) & 0xff00, 0x2300)
        self.assertEqual(machine.reg_read(UC_M68K_REG_A7), 0x108004)
        for index, register in enumerate(preserved):
            self.assertEqual(machine.reg_read(register), 0x11110000 + index)
        receipt = tuple(word(p['receipt'] + n) for n in range(0, 28, 4))
        self.assertEqual(receipt[0], MAGIC)
        self.assertEqual(receipt[1], 4)
        self.assertEqual(receipt[6], mode)
        self.assertEqual(calls.count('lock'), 1)
        self.assertEqual(calls.count('unlock'), 1)
        return machine.reg_read(UC_M68K_REG_D0), target_writes, calls, receipt

    def test_shadow_executes_original_changed_and_restored(self):
        flags, writes, calls, receipt = self.run_machine(0)
        self.assertEqual(flags, 7)
        self.assertEqual(writes, [0x70024e75, 0x70014e75])
        self.assertEqual(calls.count('shadow'), 3)
        self.assertEqual(receipt[3:6], (0x70014e75, 0x70024e75, 0x70014e75))

    def test_production_changes_only_aligned_word_and_restores(self):
        flags, writes, calls, receipt = self.run_machine(1)
        self.assertEqual(flags, 7)
        self.assertEqual(writes, [0x00004e71, 0x00006704])
        self.assertNotIn('shadow', calls)
        self.assertEqual(receipt[3:6], (0x6704, 0x4e71, 0x6704))

    def test_wrong_state_pending_request_or_original_word_does_not_write(self):
        for kwargs in ({'state': 35}, {'request': 6}, {'wrong_word': True}):
            with self.subTest(kwargs=kwargs):
                flags, writes, _, _ = self.run_machine(1, **kwargs)
                self.assertEqual((flags, writes), (0, []))

    def test_failed_cache_operation_still_restores_word(self):
        for index, expected in ((1, 6), (2, 5)):
            with self.subTest(cache_failure=index):
                flags, writes, _, _ = self.run_machine(1, fail_cache=index)
                self.assertEqual(flags, expected)
                self.assertEqual(writes[-1], 0x6704)

    def test_workspace_bounds(self):
        for address in (0, 0xa0010000, 0xa0800001, 0xa1ffff00):
            with self.assertRaises(ValueError):
                build(address)


if __name__ == '__main__':
    unittest.main()
