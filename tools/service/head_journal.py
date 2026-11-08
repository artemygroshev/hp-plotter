"""Read the existing five-head histories for four colors from the MAIN RAM mirror.

No call to the native index getter: that getter can write EEPROM on bad indices.
All output is sampled history. A native-format code is derived from a stored mask.
"""
import hashlib
import struct
import error_journal as system

CODE_PROOFS=((2685363028, 424, '91f30cda8cecf7a2eae23cbf47ec7a11be79a080f80197a30056b7f3ff0a3085'), (2685362520, 252, '473490f344ac5f0c23bc755395463a0d06b3d1178948015d7f5725a7488e203e'), (2685334700, 214, '8c4b06fd8766d39336a5c4aa489f3cd306a58178281d7b89eb67d38f491b718b'), (2685335080, 190, '3d82b60e487932ec7988ed10e062df37d2eab012c4fa65b7ffb8766890bc6565'))
MAP_ADDRESS=0xa00f6c5c
MAP=bytes.fromhex('000408020a020c0204040e010e014e71000003360000033700000338000003390000033a0000033b0000033c0000033d0000033e0000033f00000340000003410000034200000343000003440000034500000346000003470000034800000349000f00f00f00f0000004080c')
DESCRIPTORS_ADDRESS=0xa011ad82
DESCRIPTORS=bytes.fromhex('033532d8100100000000033632e88f01a011686c033733608f01a011686c033833d88f01a011686c033934508f01a011686c033a34c88f01a011686c033b35408f01a011686c033c35b88f01a011686c033d36308f01a011686c033e36a88f01a011686c033f37208f01a011686c034037988f01a011686c034138108f01a011686c034238888f01a011686c034339008f01a011686c034439788f01a011686c034539f08f01a011686c03463a688f01a011686c03473ae08f01a011686c03483b588f01a011686c03493bd08f01a011686c')
COLOR_MAP_ADDRESS=0xa039d324
COLOR_MAP=bytes.fromhex('a00f0f1c000000000000000000000000000000000000a00f0f28000000000000000100000001020000000000a00f0f34000000000000000200000002010000000000a00f0f40000000000000000300000003030000000000')
HISTORY_OFFSET=1627
HISTORY_BYTES=302
COLORS=('Black','Cyan','Magenta','Yellow')
ODB_SUFFIX=(3,0,1,2)
PREFIX=(0,2,1,3)
ERROR_MASK=0x04feffe1


def verify_color_map(data):
    if len(data)!=88:raise ValueError('incomplete native color map')
    for i in range(4):
        live=data[22*i:22*(i+1)];expected=COLOR_MAP[22*i:22*(i+1)]
        # +4 holds the cached ODB object handle, initialized at runtime. Name
        # pointers, native indices, display order and code prefixes stay pinned.
        if live[:4]!=expected[:4] or live[8:]!=expected[8:]:
            raise ValueError('live immutable color mapping differs')
        handle=struct.unpack_from('>I',live,4)[0]
        if handle and (handle%4 or not 0xa0001000<=handle<0xa1000000):
            raise ValueError('cached ODB handle outside engine memory')


def native_head_code(color,mask):
    """A.04.02 UI's exact priority order; derived, not a stored four-digit word."""
    if type(color) is not int or color not in range(4):raise ValueError('invalid native color index')
    if type(mask) is not int or not 0<=mask<=0xffffffff:raise ValueError('invalid 32-bit head mask')
    if not mask&ERROR_MASK:return None
    subcode=0
    if not mask&0x16:
        for bit,value in ((13,12),(14,14),(15,10),(20,18),(21,19),(22,23),
                          (23,24),(9,7),(11,34),(12,34),(10,2),(7,30),(8,31),
                          (16,32),(17,18),(19,33),(26,34)):
            if mask&(1<<bit):subcode=value;break
    prefix=PREFIX[color]+(10 if mask&8 else 0)
    return f'{100*prefix+subcode:04d}'


def decode_history(data):
    if len(data)!=HISTORY_BYTES:raise ValueError('head history requires exactly 302 bytes')
    packed=struct.unpack_from('>H',data)[0];colors=[]
    for color,name in enumerate(COLORS):
        current=(packed>>(4*color))&15
        indices=[(current-age)%5 for age in range(5)] if current<5 else list(range(5))
        records=[]
        for age,slot in enumerate(indices):
            raw=data[2+75*color+15*slot:2+75*color+15*(slot+1)]
            identity,mask,cc,days,unknown,flags=struct.unpack('>IIHHHB',raw)
            if identity in (0,0xffffffff):continue
            records.append({'slot':slot,'tag':822+5*color+slot,
                'newest_first_index':age if current<5 else None,
                'current_slot':slot==current if current<5 else None,
                'identity_raw':identity,'status_mask_raw':mask,
                'native_format_code_derived':native_head_code(color,mask),
                'code_provenance':'derived_from_stored_mask_with_pinned_A.04.02_algorithm',
                'used_ink_cc':cc,'usage_days':days,'cleaning_level':(flags&6)>>1,
                'field_3_raw':unknown,'flags_raw':flags,'record_hex':raw.hex(),
                'historical_event':True,'current_physical_cause_proven':False})
        colors.append({'color':name,'native_index':color,'odb_suffix':ODB_SUFFIX[color],
            'current_slot_raw':current,'index_valid':current<5,'records':records})
    return {'packed_indices_raw':packed,'colors':colors,'raw_hex':data.hex(),
            'records_per_color_limit':5,'current_physical_cause_proven':False}


def read_history(client):
    if not CODE_PROOFS or len(MAP)!=108 or len(DESCRIPTORS)!=210 or len(COLOR_MAP)!=88:
        raise RuntimeError('offline head-map proofs not configured')
    proofs=[]
    for address,length,digest in system.CODE_PROOFS[:2]+CODE_PROOFS:
        raw=b''.join(client.memory(address+offset,min(128,length-offset)) for offset in range(0,length,128))
        if hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('live head-history code differs')
        proofs.append({'address':hex(address),'bytes':length,'sha256':digest})
    config=client.memory(system.CONFIG_ADDRESS,12);system.parse_config(config)
    if client.memory(MAP_ADDRESS,len(MAP))!=MAP:raise RuntimeError('live head field/index map differs')
    desc=b''.join(client.memory(DESCRIPTORS_ADDRESS+offset,min(128,len(DESCRIPTORS)-offset)) for offset in range(0,len(DESCRIPTORS),128))
    if desc!=DESCRIPTORS:raise RuntimeError('live head-history descriptors differ')
    verify_color_map(client.memory(COLOR_MAP_ADDRESS,len(COLOR_MAP)))
    before=client.memory(system.HEADER_ADDRESS,20);header=system.parse_header(before)
    if HISTORY_OFFSET+HISTORY_BYTES>header['bytes']:raise RuntimeError('MAIN mirror does not contain head history')
    address=header['pointer']+HISTORY_OFFSET
    def copy():
        return b''.join(client.memory(address+offset,min(128,HISTORY_BYTES-offset)) for offset in range(0,HISTORY_BYTES,128))
    first=copy();second=copy()
    if before!=client.memory(system.HEADER_ADDRESS,20) or config!=client.memory(system.CONFIG_ADDRESS,12):
        raise RuntimeError('MAIN mirror header/layout changed')
    if first!=second:raise RuntimeError('head history changed between complete copies')
    history=decode_history(first)
    client.status(tuple('telemetry_head_native_'+str(i) for i in range(4)))
    for color in history['colors']:
        value=client.state['status']['head_native_'+str(color['odb_suffix'])]
        active=next((r for r in color['records'] if r['current_slot']),None)
        color['current_ODB_status_raw']=value['raw'] if value['available'] else None
        color['current_mask_matches_history']=(active is not None and value['available']
            and str(active['status_mask_raw'])==value['raw'])
    history.update(source='existing MAIN EEROM RAM mirror; no EEPROM function called',
        firmware='A.04.02',table_version=6,two_copies_identical=True,mirror_header_stable=True,
        code_proofs=proofs,native_index_getter_called=False,persistent_device_changes=False,
        physical_menu_comparison_completed=False)
    client.state['head_history']=history;client.checkpoint()
