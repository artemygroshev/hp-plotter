"""Prepare only the pinned idle bridge for userspace operation after rebind.

Caller owns both USB lock and device guard. No Bulk OUT, printer reset, USB
device reset, module blacklist, network change or other-device operation.
"""
import ctypes as C
import ctypes.util
from pathlib import Path
import re


class PreparationRefused(RuntimeError):
    """Refusal before unbinding or any USB control operation."""
    def __init__(self,message,print_pending=False):
        super().__init__(message);self.print_pending=print_pending


def ensure_idle(support,config,allow_queued_job=False,lib=None,unbind=None):
    if config.get('idle_driver','usblp')!='none':return {'changed':False,'bulk_out_bytes':0,'bulk_out_attempts':0}
    if Path('/etc/machine-id').read_text().strip()!=config['machine_id']:
        raise PreparationRefused('BTT identity differs from the installation pin')
    rows=support['adapters']()
    if len(rows)!=1 or rows[0]['descriptor_sha256']!=config['adapter_descriptor_sha256']:
        raise PreparationRefused('pinned adapter missing or ambiguous')
    row=rows[0]
    if row['driver'] is None and row['alternate']==0:
        return {'changed':False,'bulk_out_bytes':0,'bulk_out_attempts':0,'idle_verified':True}
    before=support['snapshot'](class_read=False);cups=before['cups']
    if not allow_queued_job and isinstance(cups['unfinished_job_ids'],list) and cups['unfinished_job_ids']:
        raise PreparationRefused('CUPS job has priority',print_pending=True)
    if (cups['queue_command']['rc']!=0 or cups['unfinished_job_ids'] is None
            or cups['usb_backend_pids']
            or (not allow_queued_job and cups['attributes'].get('printer-state',{}).get('raw_value')!='idle')
            or not before['usb_handles']['inspection_complete'] or before['usb_handles']['open_handles']):
        raise PreparationRefused('queue or USB ownership cannot be verified')
    rows=before['adapters']
    if (len(rows)!=1 or rows[0]['descriptor_sha256']!=config['adapter_descriptor_sha256']
            or rows[0]['bConfigurationValue']!='1' or rows[0]['alternate'] not in (0,1)
            or rows[0]['driver'] not in (None,'/sys/bus/usb/drivers/usblp')):
        raise PreparationRefused('adapter state is outside the two supported idle modes')
    row=rows[0];port=Path(row['sysfs_node']).name
    if not re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*',port):
        raise PreparationRefused('unexpected USB interface name')
    if row['driver'] is not None:
        if unbind is None:Path('/sys/bus/usb/drivers/usblp/unbind').write_text(port+':1.0')
        else:unbind(port+':1.0')
    if lib is None:lib=C.CDLL(ctypes.util.find_library('usb-1.0'))
    def bind(name,args,result):
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=result;return fn
    ptr=C.c_void_p
    init=bind('libusb_init',[C.POINTER(ptr)],C.c_int);leave=bind('libusb_exit',[ptr],None)
    op=bind('libusb_open_device_with_vid_pid',[ptr,C.c_uint16,C.c_uint16],ptr);close=bind('libusb_close',[ptr],None)
    device=bind('libusb_get_device',[ptr],ptr);bus=bind('libusb_get_bus_number',[ptr],C.c_uint8)
    address=bind('libusb_get_device_address',[ptr],C.c_uint8)
    active=bind('libusb_kernel_driver_active',[ptr,C.c_int],C.c_int)
    claim=bind('libusb_claim_interface',[ptr,C.c_int],C.c_int)
    release=bind('libusb_release_interface',[ptr,C.c_int],C.c_int)
    alternate=bind('libusb_set_interface_alt_setting',[ptr,C.c_int,C.c_int],C.c_int)
    context=ptr();handle=None;claimed=False
    rc=init(C.byref(context))
    if rc:raise RuntimeError(('libusb_init',rc))
    try:
        handle=op(context,0x1a86,0x7584)
        if not handle:raise RuntimeError('pinned adapter cannot be opened for idle preparation')
        dev=device(handle)
        if (bus(dev),address(dev))!=(int(row['busnum']),int(row['devnum'])) or active(handle,0)!=0:
            raise RuntimeError('adapter identity or ownership changed during idle preparation')
        rc=claim(handle,0)
        if rc:raise RuntimeError(('claim',rc))
        claimed=True;rc=alternate(handle,0,0)
        if rc:raise RuntimeError(('select_idle_alt0',rc))
    finally:
        try:
            if claimed:
                rc=release(handle,0)
                if rc:raise RuntimeError(('release_after_idle_preparation',rc))
        finally:
            if handle:close(handle)
            leave(context)
    after=support['snapshot'](class_read=False);rows=after['adapters']
    if (len(rows)!=1 or any(rows[0][key]!=row[key] for key in ('path','busnum','devnum','descriptor_sha256'))
            or rows[0]['driver'] is not None or rows[0]['alternate']!=0
            or not after['usb_handles']['inspection_complete'] or after['usb_handles']['open_handles']):
        raise RuntimeError('userspace idle state did not pass verification')
    return {'changed':True,'bulk_out_bytes':0,'bulk_out_attempts':0,'idle_verified':True,'driver':None,'alternate':0,
            'target_interface':port+':1.0'}
