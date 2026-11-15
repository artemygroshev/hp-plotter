import struct
import unittest

from setup_ids_route import (route_code, CASE_SLOT, STOCK_CASE, DISPATCH_CONTINUE,
                             ROUTE_OFFSET, RECEIPT_OFFSET)
from setup_worker_clone import IDS_STATE, IDS_REQUEST


class IDSRouteChecks(unittest.TestCase):
    def execute(self, result=1, foreign=None, blocked=False):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_D6,
                                        UC_M68K_REG_D7, UC_M68K_REG_A6, UC_M68K_REG_A7)
        ws, sp = 0xa0800000, 0x108000
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.mem_map(0xa0000000, 0x1000000); uc.mem_map(0x100000, 0x10000)
        uc.mem_write(ws + ROUTE_OFFSET, route_code(ws))
        uc.mem_write(ws, bytes.fromhex('4e75'))
        selected = ws + ROUTE_OFFSET if foreign is None else foreign
        for address, value in ((CASE_SLOT, selected), (IDS_STATE, 35), (IDS_REQUEST, 6)):
            uc.mem_write(address, struct.pack('>I', value))
        for register, value in ((UC_M68K_REG_A7, sp), (UC_M68K_REG_A6, 0x12345678),
                                 (UC_M68K_REG_D7, 6), (UC_M68K_REG_D6, 0x55667788)):
            uc.reg_write(register, value)
        def word(address): return struct.unpack('>I', uc.mem_read(address, 4))[0]
        calls, writes, destination = [], [], []
        def visit(machine, address, size, ignored):
            if address == ws:
                calls.append(address)
                self.assertEqual(word(CASE_SLOT), STOCK_CASE)
                self.assertEqual(word(ws + RECEIPT_OFFSET), 1)
                self.assertEqual(word(machine.reg_read(UC_M68K_REG_A7) + 4), 0)
                machine.reg_write(UC_M68K_REG_D0, result)
                if blocked: machine.emu_stop()
            elif address in (STOCK_CASE, DISPATCH_CONTINUE):
                destination.append(address); machine.emu_stop()
        def written(machine, access, address, size, value, ignored):
            if address == CASE_SLOT:
                self.assertEqual((size, value), (4, STOCK_CASE)); writes.append(value)
            elif not (0x100000 <= address < 0x110000 or
                       ws + RECEIPT_OFFSET <= address < ws + RECEIPT_OFFSET + 16):
                self.fail('write outside stack/owned receipt/one table slot: ' + hex(address))
        uc.hook_add(UC_HOOK_CODE, visit); uc.hook_add(UC_HOOK_MEM_WRITE, written)
        uc.emu_start(ws + ROUTE_OFFSET, 0, count=300)
        self.assertEqual(uc.reg_read(UC_M68K_REG_D7), 6)
        self.assertEqual(uc.reg_read(UC_M68K_REG_A6), 0x12345678)
        self.assertEqual(word(IDS_STATE), 35); self.assertEqual(word(IDS_REQUEST), 6)
        return uc, word, calls, writes, destination

    def test_restores_slot_before_worker_and_preserves_stock_case_ABI(self):
        from unicorn.m68k_const import UC_M68K_REG_D6, UC_M68K_REG_A7
        for result in (0, 1):
            with self.subTest(result=result):
                uc, word, calls, writes, target = self.execute(result=result)
                self.assertEqual((calls, writes, target), ([0xa0800000], [STOCK_CASE], [DISPATCH_CONTINUE]))
                self.assertEqual(uc.reg_read(UC_M68K_REG_D6), result)
                self.assertEqual(uc.reg_read(UC_M68K_REG_A7), 0x108000)
                self.assertEqual([word(0xa0800200 + i * 4) for i in range(4)], [2, result, 35, 6])

    def test_blocked_worker_restores_slot_but_never_claims_completion(self):
        _, word, calls, writes, target = self.execute(blocked=True)
        self.assertEqual((len(calls), writes, target), (1, [STOCK_CASE], []))
        self.assertEqual(word(0xa0800200), 1)

    def test_old_fetched_pointer_does_not_overwrite_foreign_slot(self):
        for foreign in (STOCK_CASE, 0xa0810000):
            with self.subTest(foreign=foreign):
                _, word, calls, writes, target = self.execute(foreign=foreign)
                self.assertEqual((calls, writes, target), ([], [], [STOCK_CASE]))
                self.assertEqual(word(CASE_SLOT), foreign)
                self.assertEqual(word(0xa0800200), 3)

    def test_rejects_unaligned_or_production_workspace(self):
        for address in (True, 0xa039d3e4, 0xa0800001):
            with self.assertRaises(ValueError): route_code(address)
