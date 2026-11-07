"""Recovery failure guards, emulated only; no device access."""
import copy
from pathlib import Path
import types
import unittest

module=types.ModuleType('reset_under_test')
p=Path(__file__).parent/'reset_adapter_once.py'
exec(compile(p.read_text(),str(p),'exec'),module.__dict__)

class Function:
    def __init__(self,action):self.action=action
    def __call__(self,*args):return self.action(*args)

class USB:
    def __init__(self,bus=5,kernel=1,reset_rc=0):
        self.resets=0;self.closed=False;self.left=False
        def init(ctx):ctx._obj.value=1;return 0
        def reset(handle):self.resets+=1;return reset_rc
        def close(handle):self.closed=True
        def leave(ctx):self.left=True
        calls={'init':init,'exit':leave,'open_device_with_vid_pid':lambda *_:2,
          'close':close,'get_device':lambda *_:3,'get_bus_number':lambda *_:bus,
          'get_device_address':lambda *_:2,'kernel_driver_active':lambda *_:kernel,
          'reset_device':reset}
        for name,fn in calls.items():setattr(self,'libusb_'+name,Function(fn))

def snapshot():
    return {'cups':{'unfinished_job_ids':[],'queue_command':{'rc':0,'out':''},
      'usb_backend_pids':[],'attributes':{'printer-state':{'raw_value':'idle'}}},
      'usb_handles':{'inspection_complete':True,'open_handles':[]},
      'adapters':[{'descriptor_sha256':'expected','bConfigurationValue':'1',
      'alternate':1,'driver':'/sys/bus/usb/drivers/usblp','busnum':'5',
      'devnum':'2','path':'recorded'}],
      'class_read':{'requests':{'GET_DEVICE_ID':{'decoded':{'hp_c7769b_identified':False}}}}}

class RecoveryChecks(unittest.TestCase):
    def run_case(self,usb,before=None,after=None,policy=None):
        states=[before or snapshot(),after or snapshot()]
        return module.run({'ADAPTER_DESCRIPTOR_SHA256':'expected',
            'snapshot':lambda **kwargs:states.pop(0),**(policy or {})},lib=usb,delay=lambda _:None,deadline_utc='2099-01-01T00:00:00+00:00')
    def test_explicit_unbound_idle_does_not_attach_a_kernel_driver(self):
        before=snapshot();before['adapters'][0].update(driver=None,alternate=0)
        usb=USB(kernel=0)
        r=self.run_case(usb,before,copy.deepcopy(before),{'IDLE_DRIVER':None,'IDLE_ALTERNATE':0})
        self.assertEqual(usb.resets,1);self.assertTrue(r['cleanup']['verified'])
        self.assertEqual(r['bulk_out_bytes'],0)
    def test_successful_reset_not_falsely_declared_restored(self):
        usb=USB();r=self.run_case(usb)
        self.assertEqual(usb.resets,1);self.assertTrue(usb.closed and usb.left)
        self.assertFalse(r['hp_readback_restored']);self.assertTrue(r['cleanup']['verified'])
    def test_reset_failure_never_replayed(self):
        usb=USB(reset_rc=-4);r=self.run_case(usb)
        self.assertEqual(usb.resets,1);self.assertEqual(r['reset_rc'],-4)
        self.assertTrue(usb.closed and usb.left)
    def test_busy_queue_prevents_reset(self):
        usb=USB();before=snapshot();before['cups']['unfinished_job_ids']=[6]
        with self.assertRaisesRegex(RuntimeError,'queue'):self.run_case(usb,before)
        self.assertEqual(usb.resets,0)
    def test_descriptor_mismatch_prevents_reset(self):
        usb=USB();before=snapshot();before['adapters'][0]['descriptor_sha256']='different'
        with self.assertRaisesRegex(RuntimeError,'adapter'):self.run_case(usb,before)
        self.assertEqual(usb.resets,0)
    def test_address_change_prevents_reset_but_closes_handle(self):
        usb=USB(bus=6);r=self.run_case(usb)
        self.assertEqual(usb.resets,0);self.assertIn('address changed',r['error'])
        self.assertTrue(usb.closed and usb.left)
    def test_missing_binding_is_detected_after_reset(self):
        usb=USB();after=snapshot();after['adapters'][0]['driver']=None
        r=self.run_case(usb,after=after);self.assertFalse(r['cleanup']['verified'])

if __name__=='__main__':unittest.main()
