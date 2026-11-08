"""Read the A.04.02 system-error ring from its existing RAM mirror.

No EEROM function call, allocation, key injection, clear or write. This is a
separate read plan; historical events never become the current fault by default.
"""
import hashlib
import struct

CONFIG_ADDRESS=0xa03a0fa8
HEADER_ADDRESS=0xa03a0f10  # 0xa03a0e70 + 8 * 20, MAIN group
DESCRIPTORS_ADDRESS=0xa011ad14
DESCRIPTORS=bytes.fromhex(
    '032a2c90080100000000032b2c989401a0116858032c2d389401a0116858'
    '032d2dd89401a0116858032e2e789401a0116858032f2f189401a0116858'
    '03302fb89401a0116858033130589401a0116858033230f89401a0116858'
    '033331989401a0116858033432389401a0116858')
RING_OFFSET=1426
RING_BYTES=201
# The expected hashes are pinned to the official complete main image. They are
# populated from offline evidence, not learned from the printer's response.
CODE_PROOFS=((2685493680, 164, '88b831012ec4aeaad6f7c19bd5bd96fa6ddf2e374701a64b8311b7973bd09663'), (2685483728, 204, '29098132a24500b823c609b79aa82d485636dd954324469e7aceb6e4a1cedf74'), (2687064088, 194, '673fd161b07278c75a7ea009384f39713384b0686a70a0e3d4ed6599f7ae0d42'), (2687063904, 182, 'd74d8e3837467d352bf894602fae1bd9f3b068121ae6798d5f45ad69cc972d16'))


def parse_config(data):
    if len(data)!=12:raise ValueError('incomplete EEROM table configuration')
    pointers,counts,versions,current,status,reserved=struct.unpack('>IIBBBB',data)
    if ((pointers,counts,versions,current,reserved)!=(0xa03a0f78,0xa011af50,7,6,0)
            or status not in (0,1)):
        raise ValueError('require the reviewed MAIN layout version 6')
    # +10 is a separate runtime status byte, exposed by 0xa01162a8. It is
    # initially 0 in the image and observed as 1 on the running printer. It is
    # not part of the pointer table or the +9 layout-version field.
    return {'table_version':current,'versions':versions,'runtime_status_raw':status}


def parse_header(data):
    if len(data)!=20:raise ValueError('incomplete MAIN RAM mirror header')
    pointer=struct.unpack_from('>I',data)[0]
    length=struct.unpack_from('>h',data,16)[0]
    dirty,loaded=data[18:20]
    if pointer%4 or not 0xa044d000<=pointer<pointer+max(0,length)<=0xa1000000:
        raise ValueError('MAIN image pointer/length outside reviewed engine RAM')
    if not RING_OFFSET+RING_BYTES<=length<=32767 or loaded!=1 or dirty not in (0,1):
        raise ValueError('MAIN RAM mirror not loaded or too short')
    return {'pointer':pointer,'bytes':length,'dirty':bool(dirty),'loaded':True}


def decode_ring(data):
    if len(data)!=RING_BYTES:raise ValueError('error ring must contain exactly 201 bytes')
    index=data[0]
    if index>=10:
        # This is the native menu's "no entries" branch, not an invented date
        # or a promise that the device has never had an error.
        return {'next_slot_raw':index,'native_menu_has_entries':False,
                'records':[],'raw_hex':data.hex(),'current_fault_proven':False}
    records=[]
    for age in range(10):
        slot=(index-1-age)%10
        raw=data[1+20*slot:1+20*(slot+1)]
        if raw in (bytes(20),b'\xff'*20):continue
        date,code,line=struct.unpack_from('>HHH',raw)
        source=raw[6:20].split(b'\0',1)[0]
        name=source.decode('ascii') if all(32<=b<127 for b in source) else None
        records.append({'slot':slot,'tag':811+slot,'newest_first_index':age,
            'system_code_raw':code,'system_code_text':f'{code//100:02d}:{code%100:02d}',
            'source_name':name,'source_bytes_hex':raw[6:20].hex(),'source_line':line,
            'date_field_raw':date,'date_units_confirmed':False,'record_hex':raw.hex(),
            'historical_event':True,'current_fault_proven':False})
    return {'next_slot_raw':index,'native_menu_has_entries':True,'records':records,
            'raw_hex':data.hex(),'current_fault_proven':False}


def read_journal(client):
    if not CODE_PROOFS:raise RuntimeError('offline code proofs not configured')
    proofs=[]
    for address,length,expected in CODE_PROOFS:
        raw=b''.join(client.memory(address+offset,min(128,length-offset))
                     for offset in range(0,length,128))
        actual=hashlib.sha256(raw).hexdigest()
        if actual!=expected:raise RuntimeError('live MAIN ring code differs from pinned A.04.02')
        proofs.append({'address':hex(address),'bytes':length,'sha256':actual})
    config=client.memory(CONFIG_ADDRESS,12);parse_config(config)
    descriptors=client.memory(DESCRIPTORS_ADDRESS,len(DESCRIPTORS))
    if descriptors!=DESCRIPTORS:raise RuntimeError('live ring tag descriptors differ')
    before=client.memory(HEADER_ADDRESS,20);header=parse_header(before)
    address=header['pointer']+RING_OFFSET
    def copy():
        return b''.join(client.memory(address+offset,min(128,RING_BYTES-offset))
                        for offset in range(0,RING_BYTES,128))
    first=copy();second=copy()
    after=client.memory(HEADER_ADDRESS,20)
    if before!=after or config!=client.memory(CONFIG_ADDRESS,12):
        raise RuntimeError('MAIN mirror ownership/layout changed while reading')
    if first!=second:raise RuntimeError('MAIN ring changed between complete copies')
    journal=decode_ring(first)
    journal.update(source='existing MAIN EEROM RAM mirror, not direct EEPROM I/O',
        firmware='A.04.02',table_version=6,code_proofs=proofs,
        two_copies_identical=True,mirror_header_stable=True,
        mirror_bytes=header['bytes'],mirror_dirty=header['dirty'],
        persistent_device_changes=False,physical_menu_comparison_completed=False)
    client.state['system_error_journal']=journal
    client.checkpoint()
