import base64
import datetime as dt
import hashlib
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import reset_info as reset
from batch_usb import ReadSession,payload_for,probe
from test_batch_usb import Fake,Clock

NORMAL=(b'Calling code: 0x79\nKernel state: 0x1\n'
        b'TID: 0x12345678  PRIO: 0x30\nName: MAIN\n')


class ResetInfoChecks(unittest.TestCase):
    def reply(self,body,begin=True,nonce='123abc'):
        return (b'B'+nonce.encode()+b'\n' if begin else b'')+body+b'E'+nonce.encode()+b'\n'

    def test_native_task_report_with_and_without_begin(self):
        for begin in (False,True):
            parsed=reset.parse_reply(self.reply(NORMAL,begin),'123abc')
            self.assertEqual(parsed['calling_code_raw'],0x79)
            self.assertEqual(parsed['task_id_raw'],0x12345678)
            self.assertEqual(parsed['priority_raw'],0x30)
            self.assertEqual(parsed['task_name_text'],'MAIN')
            self.assertEqual(bytes.fromhex(parsed['native_report_hex']),NORMAL)
            self.assertEqual(parsed['begin_marker_verified'],begin)
            self.assertFalse(parsed['current_fault_proven'])

    def test_all_native_branches_and_optional_hardware_reset_line(self):
        branches=(reset.NO_INFO,
            b'Calling code: 0xffffffff\nKernel state: 0x0\nCalled from ISR\n',
            b'Calling code: 0x0\nKernel state: 0xdeadbeef\nInvalid TID\n')
        for body in branches:
            for suffix in (b'',reset.RAIER):
                parsed=reset.parse_reply(self.reply(body+suffix),'123abc')
                self.assertEqual(parsed['valid_reset_signature'],body!=reset.NO_INFO)
                self.assertEqual(parsed['raier_not_in_reset_reported'],bool(suffix))
        self.assertEqual(reset.parse_reply(self.reply(branches[1]),'123abc')['task_state'],'called_from_ISR')
        self.assertEqual(reset.parse_reply(self.reply(branches[2]),'123abc')['task_state'],'invalid_TID')

    def test_nonprintable_task_name_preserves_four_bytes(self):
        body=NORMAL.replace(b'MAIN',b'\x00\xff\n<')
        parsed=reset.parse_reply(self.reply(body),'123abc')
        self.assertIsNone(parsed['task_name_text'])
        self.assertEqual(parsed['task_name_hex'],'00ff0a3c')

    def test_partial_old_or_mixed_replies_are_rejected_whole(self):
        good=self.reply(NORMAL)
        bad=(good[:-1],good+b'extra',b'old\n'+good,good+good,
             self.reply(NORMAL,nonce='ffffff'),good.replace(b'0x79',b'0x100000000'),
             self.reply(NORMAL+reset.NO_INFO),self.reply(NORMAL.replace(b'Name: MAIN\n',b'')),
             self.reply(reset.NO_INFO+reset.RAIER*2),b'x'*513)
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):reset.parse_reply(raw,'123abc')

    def test_fixed_getter_has_no_arguments_or_write_commands(self):
        packet=payload_for('reset_info_native','123abc')
        self.assertEqual(len(packet),129)
        self.assertIn(b'\nflush stdout\nsysShowResetInfo\nputs E123abc\nexit\n',packet)
        for word in (b'sysCleanResetInfo',b'\nsysReset',b'osFuncCall'):
            self.assertNotIn(word,packet)

    def test_malformed_native_report_poison_closes_USB_and_blocks_next_query(self):
        class NativeReplyFake(Fake):
            def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
                rc=super().bulk_transfer(handle,endpoint,data,length,count,timeout)
                if endpoint==1 and self.pending:
                    self.pending=b'Not sysReset valid info\nE123abc\nextra'
                return rc
        fake=NativeReplyFake()
        session=ReadSession(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),
            lib=fake,alt_observer=lambda:fake.alt,now=Clock(),sleep=lambda _:None,
            nonce_factory=lambda:'123abc',comment_bytes=63)
        with session:
            with self.assertRaises(ValueError):session.query('reset_info_native')
            self.assertTrue(session.poisoned)
            with self.assertRaises(RuntimeError):session.query('fw_info_tagged')
        self.assertTrue(session.cleanup_verified)
        self.assertFalse(session.stream_closed)

    def test_native_report_needs_two_executed_quiet_phases_before_closure(self):
        import ctypes as C
        for body in (NORMAL,reset.NO_INFO):
            class NativeReplyFake(Fake):
                def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
                    rc=super().bulk_transfer(handle,endpoint,data,length,count,timeout)
                    if endpoint==1 and b'LANGUAGE=TCLWARE' in C.string_at(data,length):
                        self.pending=body+b'E123abc\n'
                    return rc
            fake=NativeReplyFake()
            session=ReadSession(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),
                lib=fake,alt_observer=lambda:fake.alt,now=Clock(),sleep=lambda _:None,
                nonce_factory=lambda:'123abc',comment_bytes=63)
            with session:reply=session.query('reset_info_native')
            self.assertTrue(reply['stream_closed']);self.assertTrue(session.cleanup_verified)
            self.assertEqual(len(reply['phases']),3)
            self.assertTrue(all(p['reads'] for p in reply['phases']))
            self.assertEqual([p['received_bytes'] for p in reply['phases'][-2:]],[0,0])
            self.assertEqual(reply['reset_info_proof']['valid_reset_signature'],body!=reset.NO_INFO)

    def test_getter_is_not_called_if_any_code_proof_differs(self):
        class Client:
            def __init__(self):self.called=False
            def memory(self,address,length):return bytes(length)
            def query(self,kind):self.called=True;raise AssertionError('must not call getter')
        client=Client()
        with self.assertRaisesRegex(RuntimeError,'differs'):reset.read_reset_info(client)
        self.assertFalse(client.called)

    def test_complete_proofs_precede_getter_and_result_is_saved(self):
        regions={address:bytes((i+3)%256 for i in range(length)) for address,length,_ in reset.CODE_PROOFS}
        proofs=tuple((address,len(raw),hashlib.sha256(raw).hexdigest()) for address,raw in regions.items())
        class Client:
            def __init__(self):self.state={};self.reads=[];self.saved=False
            def memory(self,address,length):
                self.reads.append((address,length))
                for start,raw in regions.items():
                    if start<=address<address+length<=start+len(raw):return raw[address-start:address-start+length]
                raise AssertionError('outside proofs')
            def query(self,kind):
                assert len(self.reads)==4 and kind=='reset_info_native'
                return {'nonce':'123abc','transport':{'received_base64':base64.b64encode(b'Not sysReset valid info\nE123abc\n').decode()}}
            def checkpoint(self):self.saved=True
        client=Client()
        with patch.object(reset,'CODE_PROOFS',proofs):reset.read_reset_info(client)
        self.assertTrue(client.saved)
        self.assertFalse(client.state['previous_reset_info']['valid_reset_signature'])
        self.assertEqual([length for _,length in client.reads],[60,128,128,34])


if __name__=='__main__':unittest.main()
