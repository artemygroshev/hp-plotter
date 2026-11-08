import struct
import unittest
import head_journal as history


class HeadHistoryChecks(unittest.TestCase):
    def test_only_runtime_cache_handles_can_differ_in_color_mapping(self):
        raw=bytearray(history.COLOR_MAP)
        for i in range(4):struct.pack_into('>I',raw,22*i+4,0xa03f6000+80*i)
        history.verify_color_map(raw)
        wrong=bytearray(raw);wrong[16]^=1
        with self.assertRaises(ValueError):history.verify_color_map(wrong)
        struct.pack_into('>I',raw,4,0xdeadbeef)
        with self.assertRaises(ValueError):history.verify_color_map(raw)

    def test_current_slot_wrap_color_order_and_native_units(self):
        raw=bytearray(302);struct.pack_into('>H',raw,0,0x4321)
        struct.pack_into('>IIHHHB',raw,2+15,123,0x80000,43,90,17,7)
        row=history.decode_history(raw)['colors'][0]
        self.assertEqual((row['color'],row['odb_suffix'],row['current_slot_raw']),('Black',3,1))
        record=row['records'][0]
        self.assertTrue(record['current_slot'])
        self.assertEqual((record['tag'],record['native_format_code_derived']),(823,'0033'))
        self.assertEqual((record['used_ink_cc'],record['usage_days'],record['cleaning_level']),(43,90,3))
        self.assertEqual(record['field_3_raw'],17)
        self.assertFalse(record['current_physical_cause_proven'])

    def test_bad_index_is_preserved_instead_of_native_automatic_repair(self):
        raw=bytearray(302);struct.pack_into('>H',raw,0,0xffff)
        struct.pack_into('>IIHHHB',raw,2,123,0x80000,1,2,3,0)
        decoded=history.decode_history(raw)
        self.assertEqual(decoded['packed_indices_raw'],65535)
        self.assertEqual(bytes.fromhex(decoded['raw_hex']),raw)
        for color in decoded['colors']:self.assertFalse(color['index_valid'])
        self.assertIsNone(decoded['colors'][0]['records'][0]['current_slot'])

    def test_native_code_priority_warranty_group_and_color_namespaces(self):
        self.assertEqual([history.native_head_code(i,0x80000) for i in range(4)],['0033','0233','0133','0333'])
        self.assertEqual(history.native_head_code(0,0x80008),'1033')
        self.assertEqual(history.native_head_code(0,0x82000),'0012')
        self.assertEqual(history.native_head_code(0,0x80002),'0000')
        self.assertIsNone(history.native_head_code(0,2))
        self.assertIsNone(history.native_head_code(0,0))

    def test_lengths_and_masks_are_bounded_and_empty_identity_is_not_a_head(self):
        self.assertTrue(all(not c['records'] for c in history.decode_history(bytes(302))['colors']))
        for n in (0,301,303):
            with self.assertRaises(ValueError):history.decode_history(bytes(n))
        for color,mask in ((4,0),(-1,0),(True,0),(0,-1),(0,1<<32)):
            with self.assertRaises(ValueError):history.native_head_code(color,mask)


if __name__=='__main__':unittest.main()
