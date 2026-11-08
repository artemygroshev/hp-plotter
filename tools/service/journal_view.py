"""Publish a small whitelist from an already verified private history session.

This program never opens USB. System/head histories have their own sample time,
separate from the LCD monitor; old events are never labelled as current faults.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
from storage import atomic_json

MANUAL='https://www.laserexpressinc.com/manuals/HP/hp-dsj-500-510-800-series-service-manual.pdf'
MEANINGS={
    '02:10':('Сбой электроники каретки или внутренней связи с ней.','2-8'),
    '22:10':('Сбой станции подачи чернил; возможны EEPROM или датчики.','2-11'),
    '79:04':('Внутренняя ошибка прошивки.','2-17'),
    '86:01':('Остановка оси перемещения каретки.','2-18'),
    '93:10':('Не удалось запустить систему подачи чернил.','2-19'),
}


def integer(value,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError('history integer outside bounds')
    return value


def public_history(state,batch):
    if (not state.get('complete') or not state.get('hardware_cleanup_verified')
            or not state.get('device_guard_cleared') or state.get('error')
            or state['identity']['engine_firmware']!='A.04.02'
            or not batch.get('hardware_cleanup_verified')
            or not batch.get('all_query_streams_closed') or not batch.get('device_guard_cleared')):
        raise ValueError('history session or USB cleanup not verified')
    stamp=batch['postflight']['observed_utc']
    if dt.datetime.fromisoformat(stamp).tzinfo is None:raise ValueError('history sample time needs timezone')
    output={'version':1,'observed_utc':stamp,'firmware':'A.04.02',
        'source':'existing MAIN EEROM RAM mirror','current_fault_proven':False,
        'physical_menu_comparison_completed':False,'manual_url':MANUAL}
    if state['mode']=='journal':
        raw=state['system_error_journal']
        if not raw['two_copies_identical'] or not raw['mirror_header_stable'] or len(raw['records'])>10:
            raise ValueError('system ring not verified')
        records=[];slots=set()
        for item in raw['records']:
            slot=integer(item['slot'],0,9);code=integer(item['system_code_raw'],0,65535)
            if slot in slots:raise ValueError('duplicate history slot')
            slots.add(slot)
            text=f'{code//100:02d}:{code%100:02d}'
            if text!=item['system_code_text']:raise ValueError('history code text differs')
            name=item['source_name']
            if name is not None and (len(name)>14 or any(not 32<=ord(c)<127 for c in name)):
                raise ValueError('invalid history filename')
            meaning,page=MEANINGS.get(text,('Расшифровка не подтверждена.',None))
            records.append({'slot':slot,'code':text,'source_file':name,
                'source_line':integer(item['source_line'],0,65535),
                'date_field_raw':integer(item['date_field_raw'],0,65535),
                'date_units_confirmed':False,'description_ru':meaning,'manual_page':page})
        output.update(kind='system',records=records)
    elif state['mode']=='head-journal':
        raw=state['head_history']
        if not raw['two_copies_identical'] or not raw['mirror_header_stable'] or len(raw['colors'])!=4:
            raise ValueError('head history not verified')
        colors=[]
        for index,item in enumerate(raw['colors']):
            if item['color']!=('Black','Cyan','Magenta','Yellow')[index] or len(item['records'])>5:
                raise ValueError('head history color/count differs')
            records=[];slots=set()
            current=integer(item['current_slot_raw'],0,15)
            if type(item['index_valid']) is not bool or item['index_valid']!=(current<5):
                raise ValueError('head index validity differs')
            for record in item['records']:
                slot=integer(record['slot'],0,4)
                if slot in slots:raise ValueError('duplicate head slot')
                slots.add(slot)
                code=record['native_format_code_derived']
                if code is not None and not re.fullmatch(r'[0-9]{4}',code):raise ValueError('invalid derived head code')
                from head_journal import native_head_code
                if code!=native_head_code(index,record['status_mask_raw']):raise ValueError('derived head code differs')
                if record['current_slot']!=(slot==current if current<5 else None):raise ValueError('head current slot differs')
                records.append({'slot':slot,'current_slot':record['current_slot'],
                    'status_mask_raw':integer(record['status_mask_raw'],0,0xffffffff),
                    'derived_code':code,'used_ink_cc':integer(record['used_ink_cc'],0,65535),
                    'usage_days':integer(record['usage_days'],0,65535),
                    'cleaning_level':integer(record['cleaning_level'],0,3)})
            odb=item['current_ODB_status_raw']
            if odb is not None and not re.fullmatch(r'[0-9]{1,10}',odb):raise ValueError('invalid sampled head status')
            active=next((r for r in records if r['current_slot']),None)
            matches=active is not None and str(active['status_mask_raw'])==odb
            if type(item['current_mask_matches_history']) is not bool or item['current_mask_matches_history']!=matches:
                raise ValueError('head history/current status comparison differs')
            colors.append({'color':item['color'],'current_slot_raw':integer(item['current_slot_raw'],0,15),
                'index_valid':item['index_valid'],'current_ODB_status_raw':odb,
                'current_mask_matches_history':item['current_mask_matches_history'],'records':records})
        output.update(kind='heads',colors=colors,code_provenance='derived from stored masks with pinned native algorithm')
    else:raise ValueError('only verified journal/head-journal sessions can be published')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session',required=True)
    parser.add_argument('--view-root',required=True)
    args=parser.parse_args()
    state=json.loads(Path(args.session).read_text())
    batch=json.loads(Path(state['batch_report']).read_text())
    public=public_history(state,batch)
    view=Path(args.view_root);view.mkdir(mode=0o755,parents=True,exist_ok=True)
    path=view/('system-journal.json' if public['kind']=='system' else 'head-history.json')
    atomic_json(path,public);path.chmod(0o644)
    print(json.dumps({'published':path.name,'observed_utc':public['observed_utc'],'usb_queries':0}))


if __name__=='__main__':main()
