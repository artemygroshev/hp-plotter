import struct
import unittest

from setup_ids_control import (control_code, CONTROL_OFFSET, CONTROL_RECEIPT_OFFSET,
                               CASE_SLOT, STOCK_CASE, CACHED_HEAD_AND, MAGIC)
from setup_ids_route import ROUTE_OFFSET, RECEIPT_OFFSET
from setup_worker_clone import IDS_STATE, IDS_REQUEST
from ram_rollback_program import IRQ_LOCK, IRQ_UNLOCK


class IDSControlChecks(unittest.TestCase):
    def execute(self, mode=0, state=29, request=0, phase=0, mask=10, slot=STOCK_CASE):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D2, UC_M68K_REG_D3,
            UC_M68K_REG_D4, UC_M68K_REG_D6, UC_M68K_REG_D7, UC_M68K_REG_A6, UC_M68K_REG_A7, UC_M68K_REG_SR)
        ws = 0xa0800000; route = ws + ROUTE_OFFSET
        if slot == 'owned': slot = route
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.mem_map(0xa0000000, 0x1000000); uc.mem_map(0x100000, 0x10000)
        uc.mem_write(ws + CONTROL_OFFSET, control_code(ws))
        uc.reg_write(UC_M68K_REG_SR, 0x2300); uc.reg_write(UC_M68K_REG_A7, 0x108000)
        uc.mem_write(0x108000, struct.pack('>2I', 0x101000, mode))
        preserved = (UC_M68K_REG_D2, UC_M68K_REG_D3, UC_M68K_REG_D4,
                     UC_M68K_REG_D6, UC_M68K_REG_D7, UC_M68K_REG_A6)
        for i, reg in enumerate(preserved): uc.reg_write(reg, 0x12340000 + i)
        for address, value in ((IDS_STATE, state), (IDS_REQUEST, request),
                                (ws + RECEIPT_OFFSET, phase), (CACHED_HEAD_AND, mask), (CASE_SLOT, slot)):
            uc.mem_write(address, struct.pack('>I', value))
        for address in (IRQ_LOCK, IRQ_UNLOCK): uc.mem_write(address, bytes.fromhex('4e75'))
        def word(address): return struct.unpack('>I', uc.mem_read(address, 4))[0]
        calls, writes = [], []
        def visit(m, address, size, ignored):
            if address == IRQ_LOCK:
                calls.append('lock'); m.reg_write(UC_M68K_REG_D0, m.reg_read(UC_M68K_REG_SR))
                m.reg_write(UC_M68K_REG_SR, 0x2700)
            elif address == IRQ_UNLOCK:
                calls.append('unlock'); sp = m.reg_read(UC_M68K_REG_A7)
                m.reg_write(UC_M68K_REG_SR, word(sp + 4))
        def written(m, access, address, size, value, ignored):
            if address == CASE_SLOT:
                self.assertEqual(size, 4); self.assertEqual(m.reg_read(UC_M68K_REG_SR) & 0x700, 0x700)
                writes.append(value)
            elif not (0x100000 <= address < 0x110000 or
                       ws + CONTROL_RECEIPT_OFFSET <= address < ws + CONTROL_RECEIPT_OFFSET + 36):
                self.fail('unexpected write: ' + hex(address))
        uc.hook_add(UC_HOOK_CODE, visit); uc.hook_add(UC_HOOK_MEM_WRITE, written)
        uc.emu_start(ws + CONTROL_OFFSET, 0x101000, count=600)
        self.assertEqual(calls, ['lock', 'unlock'])
        self.assertEqual(uc.reg_read(UC_M68K_REG_A7), 0x108004)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0xff00, 0x2300)
        for i, reg in enumerate(preserved): self.assertEqual(uc.reg_read(reg), 0x12340000 + i)
        for address, value in ((IDS_STATE, state), (IDS_REQUEST, request),
                                (ws + RECEIPT_OFFSET, phase), (CACHED_HEAD_AND, mask)):
            self.assertEqual(word(address), value)
        result = uc.reg_read(UC_M68K_REG_D0)
        receipt = [word(ws + CONTROL_RECEIPT_OFFSET + 4 * i) for i in range(9)]
        self.assertEqual(receipt, [MAGIC, result, mode, slot, state, request, phase, mask, word(CASE_SLOT)])
        return result, word(CASE_SLOT), writes

    def test_arm_only_real_Setup_wait_states_with_unused_route(self):
        for state in (29, 31):
            with self.subTest(state=state):
                self.assertEqual(self.execute(state=state), (1, 0xa0800100, [0xa0800100]))

    def test_no_arm_in_idle_or_already_checking_and_no_busy_request_is_changed(self):
        for state in (1, 21, 26, 34, 35, 37):
            with self.subTest(state=state): self.assertEqual(self.execute(state=state), (0, STOCK_CASE, []))
        for request in (1, 3, 6, 8):
            with self.subTest(request=request): self.assertEqual(self.execute(request=request), (0, STOCK_CASE, []))

    def test_started_completed_foreign_or_unexpected_heads_never_rearm(self):
        for phase in (1, 2, 3, 0xffffffff):
            with self.subTest(phase=phase): self.assertEqual(self.execute(phase=phase), (0, STOCK_CASE, []))
        for mask in (0, 1, 11, 0x0100000a):
            with self.subTest(mask=mask): self.assertEqual(self.execute(mask=mask), (0, STOCK_CASE, []))
        for slot in ('owned', 0xa0810000):
            actual = 0xa0800100 if slot == 'owned' else slot
            with self.subTest(slot=slot): self.assertEqual(self.execute(slot=slot), (0, actual, []))

    def test_disarm_unused_own_route_or_accept_confirmed_return(self):
        self.assertEqual(self.execute(mode=1, slot='owned'), (2, STOCK_CASE, [STOCK_CASE]))
        for phase in (0, 2):
            with self.subTest(phase=phase): self.assertEqual(self.execute(mode=1, phase=phase), (2, STOCK_CASE, []))

    def test_disarm_never_claims_success_for_pending_or_entered_worker(self):
        for request in (3, 6, 8):
            with self.subTest(request=request):
                self.assertEqual(self.execute(mode=1, slot='owned', request=request), (0, 0xa0800100, []))
        for phase, slot in ((1, STOCK_CASE), (1, 'owned'), (2, 'owned'), (3, STOCK_CASE), (0, 0xa0810000)):
            actual = 0xa0800100 if slot == 'owned' else slot
            with self.subTest(phase=phase, slot=slot):
                self.assertEqual(self.execute(mode=1, slot=slot, phase=phase), (0, actual, []))

    def test_unknown_modes_and_workspaces_are_rejected(self):
        for mode in (2, 0xffffffff):
            with self.subTest(mode=mode): self.assertEqual(self.execute(mode=mode), (0, STOCK_CASE, []))
        for ws in (True, 0xa039d3b0, 0xa0800001):
            with self.assertRaises(ValueError): control_code(ws)

    def test_GNU_source_keeps_unconditional_branches_on_instruction_boundaries(self):
        from check_ram_coldfire import source_for
        source = source_for(bytes.fromhex('6000000270014e75'), 0xa0800000)
        self.assertIn('bra.w .L4', source)
        for code in ('6000000170014e75', '6000002070014e75'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                source_for(bytes.fromhex(code), 0xa0800000)
