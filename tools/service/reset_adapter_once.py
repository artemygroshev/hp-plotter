"""One targeted USB adapter recovery under the user's resumed repair request.

No payload, Printer-Class SOFT_RESET, firmware, network, or persistent writes.
USB bus reset may discard transport buffers; only use with the verified empty
queue and exclusive recorded adapter. Preserves the kernel driver binding.
"""
import ctypes as C
import ctypes.util
import datetime
from pathlib import Path
import time


def run(support, lib=None, delay=time.sleep, deadline_utc=None):
    if deadline_utc is None:
        raise RuntimeError('explicit recovery deadline required')
    cutoff = datetime.datetime.fromisoformat(deadline_utc)
    if cutoff.tzinfo is None or datetime.datetime.now(datetime.timezone.utc) >= cutoff:
        raise RuntimeError('resumed diagnostic deadline')
    before=support['snapshot'](class_read=False)
    cups=before['cups']; devices=before['adapters']
    if (cups['unfinished_job_ids'] != [] or cups['queue_command']['rc'] != 0
        or cups['queue_command']['out'].strip() or cups['usb_backend_pids']
        or cups['attributes'].get('printer-state',{}).get('raw_value')!='idle'
        or not before['usb_handles']['inspection_complete']
        or before['usb_handles']['open_handles']):
        raise RuntimeError('queue/interface ownership not verifiably free')
    expected_driver=support.get('IDLE_DRIVER','/sys/bus/usb/drivers/usblp')
    expected_alt=support.get('IDLE_ALTERNATE',1)
    if (expected_driver,expected_alt) not in (('/sys/bus/usb/drivers/usblp',1),(None,0)):
        raise RuntimeError('unsupported explicit idle policy')
    if (len(devices)!=1 or devices[0]['descriptor_sha256']!=support['ADAPTER_DESCRIPTOR_SHA256']
        or devices[0]['bConfigurationValue']!='1' or devices[0]['alternate']!=expected_alt
        or devices[0]['driver']!=expected_driver):
        raise RuntimeError('recorded adapter or explicit idle binding not uniquely identified')
    adapter=devices[0]
    result={'preflight':before,'operation':'one USB bus reset of recorded 1a86:7584 adapter',
        'reset_attempts':0,'bulk_out_bytes':0,'printer_class_soft_reset_sent':False,
        'panel_currently_observed':False,'cleanup':{}}
    if lib is None:lib=C.CDLL(ctypes.util.find_library('usb-1.0'))
    def bind(name,args,result_type):
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=result_type;return fn
    ptr=C.c_void_p
    init=bind('libusb_init',[C.POINTER(ptr)],C.c_int)
    leave=bind('libusb_exit',[ptr],None)
    op=bind('libusb_open_device_with_vid_pid',[ptr,C.c_uint16,C.c_uint16],ptr)
    close=bind('libusb_close',[ptr],None)
    device=bind('libusb_get_device',[ptr],ptr)
    bus=bind('libusb_get_bus_number',[ptr],C.c_uint8)
    address=bind('libusb_get_device_address',[ptr],C.c_uint8)
    active=bind('libusb_kernel_driver_active',[ptr,C.c_int],C.c_int)
    reset=bind('libusb_reset_device',[ptr],C.c_int)
    context,handle=ptr(),None
    rc=init(C.byref(context))
    if rc:raise RuntimeError(('libusb_init',rc))
    try:
        handle=op(context,0x1a86,0x7584)
        if not handle:raise RuntimeError('adapter open failed')
        target=device(handle)
        if (bus(target),address(target))!=(int(adapter['busnum']),int(adapter['devnum'])):
            raise RuntimeError('adapter address changed before recovery; no reset')
        if active(handle,0)!=int(expected_driver is not None):
            raise RuntimeError('kernel binding changed; no reset')
        result['reset_attempts']=1
        result['reset_rc']=reset(handle)
    except Exception as error:
        result['error']=str(error)
    finally:
        if handle:close(handle)
        leave(context)
        result['cleanup']['own_usb_handle_closed']=True
    delay(1)
    after=support['snapshot'](class_read=True)
    result['postflight']=after
    matches=[d for d in after['adapters'] if d['path']==adapter['path']]
    result['cleanup']['verified']=(len(matches)==1
        and all(matches[0][k]==adapter[k] for k in ('descriptor_sha256','driver','alternate','bConfigurationValue'))
        and after['usb_handles']['inspection_complete']
        and not after['usb_handles']['open_handles']
        and after['cups']['unfinished_job_ids']==[]
        and not after['cups']['usb_backend_pids'])
    # A successful bus-reset API return is not proof that HP readback works.
    result['hp_readback_restored']=bool(after.get('class_read',{}).get('requests',{})
        .get('GET_DEVICE_ID',{}).get('decoded',{}).get('hp_c7769b_identified'))
    return result
