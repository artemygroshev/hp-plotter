"""Complete native LCD/30-field plan over one emulated USB session."""
import copy
import datetime as dt
import hashlib
from pathlib import Path
import re
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contextlib
import io

import designjet_readonly as native
from batch_read import BatchClient,read_content,check_queue,check_active,restored,SERIAL
from batch_usb import ReadSession
from test_batch_usb import Fake,Clock


class NativeFake(Fake):
    def __init__(self):
        super().__init__()
        self.code=bytes(range(96));self.frame0=bytes((i*37+11)%256 for i in range(1024))
        self.frame1=bytes(x^16 for x in self.frame0)
        self.regions={0xa017d468:self.code,0xa03a74b0:struct.pack('>I',0xa05406ac),
            0xa05406ac+0x62a:struct.pack('>IIIBBI',0xa0540cfc,0xa054111c,2,1,0,0),
            0xa0540cfc:struct.pack('>III',128,64,0xa0540d08),
            0xa054111c:struct.pack('>III',128,64,0xa0541128),
            0xa0540d08:self.frame0,0xa0541128:self.frame1}
    def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
        if endpoint!=1:return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        import ctypes as C
        raw=C.string_at(data,length)
        if b'LANGUAGE=TCLWARE' not in raw:
            return super().bulk_transfer(handle,endpoint,data,length,count,timeout)
        self.events.append(('out',length));self.primary+=1;count._obj.value=length
        nonce=re.search(rb'puts B([a-f0-9]{6})\n',raw)[1]
        memory=re.search(rb'osMemDump 0x([a-f0-9]{8}) ([0-9]+)',raw)
        if memory:
            address=int(memory[1],16);size=int(memory[2]);found=None
            for start,region in self.regions.items():
                if start<=address and address+size<=start+len(region):
                    found=region[address-start:address-start+size];break
            assert found is not None,hex(address)
            rows=[]
            for row in range(address&~15,(address+size+15)&~15,16):
                rows.append('%08x:  '%row+''.join('%02x '%found[p-address]
                    if address<=p<address+size else '   ' for p in range(row,row+16)))
            body=('\n'.join(rows)+'\n').encode()
        else:
            tag,separator,value=b'R',b'_',b'0'
            if b'sysGetFwRevision' in raw:tag=b'F';value=b'A.04.02'
            elif b'DEV-SERIAL-NUMBER' in raw:value=SERIAL.encode()
            elif b'osFuncCall' in raw:tag=b'P';separator=b' ';value=str(0xa0540cfc-(1<<32)).encode()
            elif b'FP-MEDIA-NAME' in raw:value=b'Plain Paper'
            body=tag+nonce+separator+value+b'\n'
        self.pending=b'B'+nonce+b'\n'+body+b'E'+nonce+b'\n'
        return 0


class BatchCollectionChecks(unittest.TestCase):
    def collect_native(self,include_diagnostics):
        fake=NativeFake();nonces=iter('%06x'%n for n in range(1,100))
        cutoff=dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)
        session=ReadSession(5,2,cutoff,lib=fake,alt_observer=lambda:fake.alt,
                            sleep=lambda _:None,now=Clock(.001),nonce_factory=lambda:next(nonces))
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(native._CONFIG,capture_root=directory), \
             patch.object(native,'GETTER_SHA256',hashlib.sha256(fake.code).hexdigest()), \
             contextlib.redirect_stdout(io.StringIO()):
            with session:
                client=BatchClient(cutoff,'all',2,session,lambda:None)
                read_content(client,'all',include_diagnostics)
                self.assertTrue(client.state['complete'])
                self.assertEqual(len(client.state['queries']),87 if include_diagnostics else 73)
                self.assertEqual(len(client.state['status']),44 if include_diagnostics else 30)
                self.assertEqual([Path(s['binary']).read_bytes() for s in client.state['screens']],
                                 [fake.frame0,fake.frame0,fake.frame1])
                self.assertNotIn('hardware_cleanup_verified',client.state)
            self.assertTrue(session.cleanup_verified)
        self.assertEqual(fake.events.count('open'),1)
        self.assertEqual(fake.events.count('device_id'),1)
        self.assertEqual(fake.events.count('release'),1)

    def test_full_native_collection_keeps_one_handle_and_every_pixel(self):
        self.collect_native(False)

    def test_extended_44_field_plan_fits_the_same_bounded_session(self):
        self.collect_native(True)

    def test_only_own_handle_is_permitted_between_queries_and_jobs_yield(self):
        snapshot={'cups':{'unfinished_job_ids':[],'queue_command':{'rc':0,'out':''},
                         'usb_backend_pids':[],'attributes':{'printer-state':{'raw_value':'idle'}}},
                  'usb_handles':{'inspection_complete':True,'open_handles':[{'pid':123}]}}
        check_queue(snapshot,123)
        with self.assertRaises(RuntimeError):check_queue(snapshot,124)
        snapshot['cups']['unfinished_job_ids']=[9]
        with self.assertRaises(native.PrintPriority):check_queue(snapshot,123)

    def test_hardware_cleanup_does_not_require_a_queue_to_stay_empty(self):
        before={'machine_id':'same','btt_boot':{'boot_id':'same'},
                'adapters':[{'path':'same','alternate':0,'driver':None,
                             'descriptor_sha256':'same','busnum':'5','devnum':'2'}]}
        after=copy.deepcopy(before)
        after.update(usb_handles={'inspection_complete':True,'open_handles':[]},
                     cups={'unfinished_job_ids':[9]})
        trace={'reader_closed':True,'module_loaded_before':False,'module_loaded_after':False,'errors':[]}
        self.assertTrue(restored(before,after,SimpleNamespace(cleanup_verified=True),trace))
        after['adapters'][0]['alternate']=1
        self.assertFalse(restored(before,after,SimpleNamespace(cleanup_verified=True),trace))

    def test_claimed_usbfs_is_distinct_from_idle_or_a_foreign_driver(self):
        before={'machine_id':'same','btt_boot':{'boot_id':'same'},
                'adapters':[{'path':'same','alternate':0,'driver':None,
                             'descriptor_sha256':'same','busnum':'5','devnum':'2'}]}
        active=copy.deepcopy(before)
        active['adapters'][0].update(alternate=1,driver='/sys/bus/usb/drivers/usbfs')
        active.update(cups={'unfinished_job_ids':[],'queue_command':{'rc':0,'out':''},
                           'usb_backend_pids':[],'attributes':{'printer-state':{'raw_value':'idle'}}},
                      usb_handles={'inspection_complete':True,'open_handles':[{'pid':123}]})
        check_active(active,before,123)
        for driver in (None,'/sys/bus/usb/drivers/usblp'):
            changed=copy.deepcopy(active);changed['adapters'][0]['driver']=driver
            with self.assertRaises(RuntimeError):check_active(changed,before,123)
        with self.assertRaises(RuntimeError):check_active(active,before,124)
        changed=copy.deepcopy(active);changed['btt_boot']['boot_id']='another-boot'
        with self.assertRaises(RuntimeError):check_active(changed,before,123)


if __name__=='__main__':unittest.main()
