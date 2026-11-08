"""Read the fixed A.04.02 previous-reset report, without resetting or clearing it.

This report is separate from the system-error ring and the current LCD fault.
Only the registered, argument-free getter is called after its complete wrapper
and native body match the pinned image. No general function executor is added.
"""
import base64
import hashlib
import re

CODE_PROOFS=(
    (0xa026cf5c,60,'08d43af2eb56ccebaf51d4136ad0af5957937b62dc3673083620dd4dce9481e1'),
    (0xa010c0e8,290,'288145d01f4dad93bf0fd13becd554d431393931131bc30e0e8fae98e2330596'),
)
NO_INFO=b'Not sysReset valid info\n'
RAIER=b'Raier Dw was not in reset\n'


def parse_reply(raw,nonce):
    """Require the entire bounded native report and this query's final marker.

    The native FILE output may replace the Tcl begin marker, as with osMemDump.
    The final nonce, complete native grammar and two subsequent quiet phases
    (checked by ReadSession) are required; no substring salvage is performed.
    """
    if not isinstance(raw,bytes) or len(raw)>512 or not re.fullmatch(r'[a-f0-9]{6}',nonce):
        raise ValueError('invalid reset report envelope')
    begin=b'B'+nonce.encode()+b'\n';end=b'E'+nonce.encode()+b'\n'
    with_begin=raw.startswith(begin)
    body=raw[len(begin):] if with_begin else raw
    if not body.endswith(end):raise ValueError('fresh reset report end missing')
    body=body[:-len(end)]
    raier=body.endswith(RAIER)
    content=body[:-len(RAIER)] if raier else body
    result={'kind':'previous_software_reset','firmware':'A.04.02',
        'begin_marker_verified':with_begin,'fresh_end_verified':True,
        'native_report_hex':body.hex(),'raier_not_in_reset_reported':raier,
        'current_fault_proven':False,'persistent_device_changes':False,
        'calling_code_meaning_confirmed':False,'event_time_known':False}
    if content==NO_INFO:
        result['valid_reset_signature']=False
        return result
    match=re.fullmatch(
        rb'Calling code: 0x([0-9a-f]{1,8})\nKernel state: 0x([0-9a-f]{1,8})\n'
        rb'(Called from ISR\n|Invalid TID\n|TID: 0x([0-9a-f]{1,8})  PRIO: 0x([0-9a-f]{1,8})\nName: ([\s\S]{4})\n)',
        content)
    if match is None:raise ValueError('reset report differs from complete native format')
    result.update(valid_reset_signature=True,calling_code_raw=int(match[1],16),
        kernel_state_raw=int(match[2],16))
    if match[3]==b'Called from ISR\n':result['task_state']='called_from_ISR'
    elif match[3]==b'Invalid TID\n':result['task_state']='invalid_TID'
    else:
        name=match[6]
        result.update(task_state='recorded_task',task_id_raw=int(match[4],16),
            priority_raw=int(match[5],16),task_name_hex=name.hex(),
            task_name_text=name.decode('ascii') if all(32<=c<127 for c in name) else None)
    return result


def read_reset_info(client):
    proofs=[]
    for address,length,expected in CODE_PROOFS:
        raw=b''.join(client.memory(address+offset,min(128,length-offset))
                     for offset in range(0,length,128))
        digest=hashlib.sha256(raw).hexdigest()
        if digest!=expected:raise RuntimeError('live reset-report getter differs from pinned A.04.02')
        proofs.append({'address':hex(address),'bytes':length,'sha256':digest})
    report=client.query('reset_info_native')
    parsed=parse_reply(base64.b64decode(report['transport']['received_base64'],validate=True),report['nonce'])
    parsed['code_proofs']=proofs
    client.state['previous_reset_info']=parsed
    client.checkpoint()
