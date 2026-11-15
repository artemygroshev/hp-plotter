import struct
import unittest

from setup_worker_clone import hook, decision, build, IDS_STATE, IDS_REQUEST, CALLBACK


class WorkerCloneChecks(unittest.TestCase):
    def test_hook_executes_only_exact_idle_override_and_preserves_stock_otherwise(self):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN
        from unicorn.m68k_const import UC_M68K_REG_D0, UC_M68K_REG_A7
        ws = 0xa0800000
        for state, request, callback in ((35, 6, 0), (1, 0, 0), (26, 6, 0),
                                         (35, 0, 0), (35, 6, 0xa0500000)):
            for mask in (0, 1, 2, 3, 10, 11, 0x0100000a, 0xffffffff):
                with self.subTest(context=(state, request, callback), mask=mask):
                    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
                    uc.mem_map(0xa0000000, 0x1000000)
                    uc.mem_map(0x100000, 0x10000)
                    uc.mem_write(ws + 160, hook(ws))
                    uc.mem_write(ws + 140, bytes.fromhex('70014e75'))
                    uc.mem_write(ws + 144, bytes.fromhex('70004e75'))
                    for address, value in ((IDS_STATE, state), (IDS_REQUEST, request),
                                           (CALLBACK, callback)):
                        uc.mem_write(address, struct.pack('>I', value))
                    uc.reg_write(UC_M68K_REG_A7, 0x108000)
                    uc.mem_write(0x108000, struct.pack('>I', 0x101000))
                    uc.reg_write(UC_M68K_REG_D0, mask)
                    uc.emu_start(ws + 160, 0x101000, count=100)
                    self.assertEqual(uc.reg_read(UC_M68K_REG_D0),
                                     decision(state, request, callback, mask))
                    self.assertEqual(uc.reg_read(UC_M68K_REG_A7), 0x108004)
                    for address, value in ((IDS_STATE, state), (IDS_REQUEST, request),
                                           (CALLBACK, callback)):
                        self.assertEqual(bytes(uc.mem_read(address, 4)), struct.pack('>I', value))

    def test_refuses_unpinned_body_or_unowned_workspace(self):
        for stock in (bytes(160), bytes(159), bytearray(160)):
            with self.assertRaises(ValueError):
                build(0xa0800000, stock)
        for address in (True, 0xa039d3b0, 0xa0800001):
            with self.assertRaises(ValueError):
                hook(address)
        for context in ((True, 0, 0, 10), (1, -1, 0, 10), (1, 0, 0, 0x100000000)):
            with self.assertRaises(ValueError):
                decision(*context)
