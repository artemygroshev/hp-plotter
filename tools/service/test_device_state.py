"""Device-side guards and address-specific rebind recovery, no live USB."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from device_guard import DeviceGuard,UnverifiedTransport
import usb_idle as idle
from transaction_outcome import safely_closed


class Function:
    def __init__(self,action):self.action=action
    def __call__(self,*args):return self.action(*args)


class USB:
    def __init__(self,bus=5,release=0):
        self.calls=[]
        def init(ctx):ctx._obj.value=1;return 0
        actions={'init':init,'exit':lambda *_:None,'open_device_with_vid_pid':lambda *_:2,
            'close':lambda *_:None,'get_device':lambda *_:3,'get_bus_number':lambda *_:bus,
            'get_device_address':lambda *_:2,'kernel_driver_active':lambda *_:0,
            'claim_interface':lambda *_:0,'release_interface':lambda *_:release,
            'set_interface_alt_setting':lambda *_:0}
        for name,action in actions.items():
            def recorded(*args,name=name,action=action):self.calls.append(name);return action(*args)
            setattr(self,'libusb_'+name,Function(recorded))


def adapter(driver='/sys/bus/usb/drivers/usblp',alternate=1):
    return {'sysfs_node':'/sys/bus/usb/devices/5-1','path':'recorded','busnum':'5','devnum':'2',
        'descriptor_sha256':'expected','bConfigurationValue':'1','driver':driver,'alternate':alternate}


def snapshot(row=None,jobs=None):
    return {'cups':{'unfinished_job_ids':jobs or [],'usb_backend_pids':[],
        'queue_command':{'rc':0,'out':''},'attributes':{'printer-state':{'raw_value':'idle'}}},
        'usb_handles':{'inspection_complete':True,'open_handles':[]},'adapters':[row or adapter()]}


class DeviceStateChecks(unittest.TestCase):
    def test_guard_requires_explicit_clear_and_does_not_replace_old_state(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'guard.json'
            with self.assertRaises(RuntimeError):
                with DeviceGuard(path,'read:test'):raise RuntimeError('lost process')
            old=path.read_bytes();self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with self.assertRaises(UnverifiedTransport),DeviceGuard(path,'print:17'):pass
            self.assertEqual(path.read_bytes(),old)

    def test_verified_clear_removes_only_its_own_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'guard.json'
            with DeviceGuard(path,'read:test') as lease:lease.clear()
            self.assertFalse(path.exists())
            with DeviceGuard(path,'read:test') as lease:
                path.rename(Path(folder)/'archive.json');path.write_text('{}');path.chmod(0o600)
                with self.assertRaises(RuntimeError):lease.clear()
            self.assertTrue(path.exists())

    def test_arriving_job_is_separate_from_successful_usb_restoration(self):
        report={'cleanup':{'verified':False,'usb_restored':True},
            'transport':{'cleanup_verified':True,'write_attempts':7,'written_bytes':512,
                'write_completed':True,'small_stopped_after_end_and_two_quiet_phases':True},
            'postflight':{'cups':{'unfinished_job_ids':[17]}}}
        self.assertTrue(safely_closed(report))
        report['cleanup']['usb_restored']=False
        self.assertFalse(safely_closed(report))

    def test_prepared_interface_can_yield_without_claiming_zero_control_transfers(self):
        report={'no_usb_started':False,'no_query_started':True,'no_bulk_out_attempted':True,
            'idle_preparation':{'changed':True,'idle_verified':True,'bulk_out_attempts':0}}
        self.assertTrue(safely_closed(report))
        report['transport']={'write_attempts':1,'written_bytes':32}
        self.assertFalse(safely_closed(report));report.pop('transport')
        report['idle_preparation']['idle_verified']=False
        self.assertFalse(safely_closed(report))

    def prepare(self,usb,before=None,after=None,row=None):
        config={'machine_id':'1'*32,'adapter_descriptor_sha256':'expected','idle_driver':'none'}
        states=[before or snapshot(),after or snapshot(adapter(None,0))]
        support={'adapters':lambda:[row or adapter()], 'snapshot':lambda **kwargs:states.pop(0)}
        unbind=[]
        with tempfile.TemporaryDirectory() as folder:
            identity=Path(folder)/'machine-id';identity.write_text('1'*32)
            with patch.object(idle,'Path',side_effect=lambda p:identity if p=='/etc/machine-id' else Path(p)):
                result=idle.ensure_idle(support,config,lib=usb,unbind=unbind.append)
        return result,unbind

    def test_prepare_changes_only_the_pinned_interface_and_never_sends_payload(self):
        usb=USB();result,unbind=self.prepare(usb)
        self.assertTrue(result['changed']);self.assertEqual(result['bulk_out_bytes'],0)
        self.assertEqual(unbind,['5-1:1.0'])
        self.assertEqual(usb.calls[-3:],['release_interface','close','exit'])
        self.assertEqual(usb.calls.count('set_interface_alt_setting'),1)

    def test_preparation_yields_before_unbind_when_a_job_arrives(self):
        usb=USB()
        with self.assertRaises(idle.PreparationRefused) as error:self.prepare(usb,before=snapshot(jobs=[17]))
        self.assertTrue(error.exception.print_pending);self.assertEqual(usb.calls,[])

    def test_wrong_adapter_never_reaches_usb_or_unbind(self):
        usb=USB();row=adapter();row['descriptor_sha256']='other'
        with self.assertRaises(idle.PreparationRefused):self.prepare(usb,row=row)
        self.assertEqual(usb.calls,[])

    def test_reenumeration_during_prepare_closes_handle_without_claiming_other_device(self):
        usb=USB(bus=6)
        with self.assertRaises(RuntimeError):self.prepare(usb)
        self.assertNotIn('claim_interface',usb.calls);self.assertEqual(usb.calls[-2:],['close','exit'])

    def test_failed_release_still_closes_context_and_does_not_claim_clean_idle(self):
        usb=USB(release=-1)
        with self.assertRaises(RuntimeError):self.prepare(usb)
        self.assertEqual(usb.calls[-2:],['close','exit'])

    def test_already_idle_needs_no_control_operation(self):
        usb=USB();result,unbind=self.prepare(usb,row=adapter(None,0))
        self.assertFalse(result['changed']);self.assertEqual(usb.calls,[]);self.assertEqual(unbind,[])


if __name__=='__main__':unittest.main()
