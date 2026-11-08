import hashlib
import struct
import unittest
from unittest import mock
import error_journal as journal


class JournalChecks(unittest.TestCase):
    def test_ring_wrap_and_embedded_zero_bytes_preserve_historical_fields(self):
        data=bytearray(journal.RING_BYTES);data[0]=0
        data[181:201]=struct.pack('>HHH14s',1234,9310,432,b'engine.c\0')
        result=journal.decode_ring(bytes(data));row=result['records'][0]
        self.assertEqual((row['slot'],row['tag'],row['system_code_text']),(9,820,'93:10'))
        self.assertEqual((row['source_name'],row['source_line']),('engine.c',432))
        self.assertEqual(row['date_field_raw'],1234)
        self.assertFalse(row['date_units_confirmed'])
        self.assertTrue(row['historical_event']);self.assertFalse(row['current_fault_proven'])
        self.assertEqual(len(bytes.fromhex(result['raw_hex'])),201)

    def test_binary_name_is_retained_without_fabricating_text(self):
        data=bytearray(201);data[0]=1
        data[1:21]=struct.pack('>HHH14s',5,2210,1,b'\xff\x00')
        row=journal.decode_ring(bytes(data))['records'][0]
        self.assertIsNone(row['source_name']);self.assertTrue(row['source_bytes_hex'].startswith('ff00'))

    def test_native_uninitialized_index_and_empty_slots_do_not_become_faults(self):
        for index in (10,255):
            result=journal.decode_ring(bytes([index])+b'\xff'*200)
            self.assertFalse(result['native_menu_has_entries']);self.assertEqual(result['records'],[])
        self.assertEqual(journal.decode_ring(bytes(201))['records'],[])
        for count in (0,200,202):
            with self.assertRaises(ValueError):journal.decode_ring(bytes(count))

    def test_mirror_and_version_reject_missing_or_unsafe_addresses(self):
        header=bytearray(20);struct.pack_into('>I',header,0,0xa0500000)
        struct.pack_into('>h',header,16,2048);header[19]=1
        self.assertEqual(journal.parse_header(header)['pointer'],0xa0500000)
        for address in (0,0xa0400000,0xa0500001,0xa0fffc00):
            bad=bytearray(header);struct.pack_into('>I',bad,0,address)
            with self.assertRaises(ValueError):journal.parse_header(bad)
        for offset,value in ((19,0),(18,7)):
            bad=bytearray(header);bad[offset]=value
            with self.assertRaises(ValueError):journal.parse_header(bad)
        config=struct.pack('>IIBBH',0xa03a0f78,0xa011af50,7,6,0)
        self.assertEqual(journal.parse_config(config)['table_version'],6)
        running=bytearray(config);running[10]=1
        self.assertEqual(journal.parse_config(running)['runtime_status_raw'],1)
        unknown=bytearray(config);unknown[10]=2
        with self.assertRaises(ValueError):journal.parse_config(unknown)
        bad=bytearray(config);bad[9]=5
        with self.assertRaises(ValueError):journal.parse_config(bad)

    def test_changed_code_is_rejected_before_reading_the_mirror(self):
        class Client:
            state={}
            copies=0
            def memory(self,address,length):
                for start,n,digest in journal.CODE_PROOFS:
                    if start<=address<start+n:return b'x'*length
                raise AssertionError('code proof should stop before data')
            def checkpoint(self):raise AssertionError('unverified journal published')
        with self.assertRaisesRegex(RuntimeError,'code differs'):journal.read_journal(Client())

    def test_complete_ring_copies_must_match_before_publication(self):
        class Client:
            def __init__(self,change):
                self.change=change;self.copies=0;self.state={};self.saved=0
            def memory(self,address,length):
                if 0xa0100000<=address<0xa0100081:return b'x'*length
                if address==journal.CONFIG_ADDRESS:return struct.pack('>IIBBH',0xa03a0f78,0xa011af50,7,6,0)
                if address==journal.DESCRIPTORS_ADDRESS:return journal.DESCRIPTORS
                if address==journal.HEADER_ADDRESS:
                    raw=bytearray(20);struct.pack_into('>I',raw,0,0xa0500000)
                    struct.pack_into('>h',raw,16,2048);raw[19]=1;return bytes(raw)
                raw=bytearray(201);raw[0]=1
                raw[1:21]=struct.pack('>HHH14s',1234,9310,432,b'engine.c\0')
                offset=address-(0xa0500000+journal.RING_OFFSET)
                if offset==0:self.copies+=1
                if self.change and self.copies==2:raw[2]^=1
                return bytes(raw[offset:offset+length])
            def checkpoint(self):self.saved+=1
        proof=((0xa0100000,129,hashlib.sha256(b'x'*129).hexdigest()),)
        with mock.patch.object(journal,'CODE_PROOFS',proof):
            bad=Client(True)
            with self.assertRaisesRegex(RuntimeError,'changed between complete copies'):journal.read_journal(bad)
            self.assertEqual((bad.state,bad.saved),({},0))
            good=Client(False);journal.read_journal(good)
            self.assertTrue(good.state['system_error_journal']['two_copies_identical'])
            self.assertEqual(good.saved,1)


if __name__=='__main__':unittest.main()
