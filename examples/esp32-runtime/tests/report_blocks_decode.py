"""Decode non-payload block inventory from an isolated C6/native UART log.

Requested block bytes exclude allocator overhead and all other heap consumers.
Separate per-kind maxima must never be summed as a simultaneous heap peak.
"""
import argparse
import json
from pathlib import Path

COUNTERS=('samples','item_size','value_size','instances','logical','slots','blocks','headers','padding','retired',
          'value_slots','value_selected','value_headers','value_padding','value_retired','requested_bytes')
MODES={'peak-bytes','peak-padding','peak-joint','current'}


def validate(row):
    if set(row)!={'kind','phase','mode',*COUNTERS}:
        raise ValueError('unexpected block fields')
    if row.get('kind') not in ('read','subscribe') or row.get('mode') not in MODES or not isinstance(row.get('phase'),str):
        raise ValueError('invalid block identity')
    for key in COUNTERS:
        if type(row.get(key)) is not int or row[key]<0:
            raise ValueError('invalid counter '+key)
    if not row['item_size'] or not row['value_size']:
        raise ValueError('zero element size')
    if row['logical']>row['slots'] or row['value_selected']>row['value_slots']:
        raise ValueError('logical count exceeds slots')
    if row['padding']!=(row['slots']-row['logical'])*row['item_size']:
        raise ValueError('item padding mismatch')
    if row['value_padding']!=(row['value_slots']-row['value_selected'])*row['value_size']:
        raise ValueError('value padding mismatch')
    if row['retired']>row['logical']*row['item_size'] or row['value_retired']>row['value_selected']*row['value_size']:
        raise ValueError('retired count exceeds admitted records')
    expected=row['headers']+row['slots']*row['item_size']+row['value_headers']+row['value_slots']*row['value_size']
    if row['requested_bytes']!=expected:
        raise ValueError('byte conservation mismatch')
    if (not row['blocks']) != (not row['headers']):
        raise ValueError('block/header mismatch')
    if row['kind']=='read' and any(row[k] for k in ('value_slots','value_selected','value_headers','value_padding','value_retired')):
        raise ValueError('Read uses combined value/path records')
    return row


def decode(text):
    rows=[];registries=[]
    for line in text.splitlines():
        if line.startswith('BLOCK_AUDIT '):rows.append(validate(json.loads(line[len('BLOCK_AUDIT '):])))
        if line.startswith('BLOCK_REGISTRY '):
            r=json.loads(line[len('BLOCK_REGISTRY '):])
            if r.get('kind') not in ('read','subscribe') or type(r.get('empty')) is not bool:
                raise ValueError('invalid registry record')
            registries.append(r)
    if not rows:raise ValueError('no block records')
    final={}
    for kind in ('read','subscribe'):
        group=[r for r in rows if r['kind']==kind]
        if not group:continue
        phase=group[-1]['phase']
        if phase not in ('complete','native-complete'):raise ValueError('missing terminal phase')
        terminal=[r for r in group if r['phase']==phase]
        if len(terminal)!=len(MODES):raise ValueError('duplicate or missing terminal modes')
        selected={r['mode']:r for r in terminal}
        if set(selected)!=MODES:raise ValueError('incomplete final modes')
        registry=[r for r in registries if r['kind']==kind and r['phase']==phase]
        if len(registry)!=1 or not registry[0]['empty']:
            raise ValueError('missing final empty registry')
        if selected['current']['instances'] or selected['current']['requested_bytes']:
            raise ValueError('interactions still live')
        final[kind]=selected
    joint=None
    if set(final)=={'read','subscribe'}:
        pair=[final[k]['peak-joint'] for k in ('read','subscribe')]
        joint={key:sum(r[key] for r in pair) for key in ('requested_bytes','headers','padding','value_headers','value_padding','retired','value_retired')}
        if joint['requested_bytes']>sum(final[k]['peak-bytes']['requested_bytes'] for k in final):
            raise ValueError('joint peak exceeds individual bounds')
    return dict(records=len(rows),final=final,joint_peak=joint,
                limitations=['Owner samples and pre-delete samples are lower bounds, not a specification-wide maximum.',
                             'Only peak-joint records were captured at the same owner boundary; do not sum independent per-kind maxima.',
                             'Padding, headers and retired records are inventory, not an immediately reclaimable RAM promise.',
                             'Instrumented layout/timing and allocator metadata differ from a normal firmware image.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--log',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.log.resolve()==a.output.resolve():p.error('output must differ from input')
    result=decode(a.log.read_text(encoding='utf-8'));a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('PASS block inventory:',result['records'],'records')

if __name__=='__main__':main()
