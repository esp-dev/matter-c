"""Prepare a new MP04 TH import from a private exported project; no TH mutation."""
import argparse
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--endpoint',type=int,choices=(0,1),required=True)
    p.add_argument('--discriminator',type=int,required=True)
    a=p.parse_args()
    if not 0<=a.discriminator<=4095: p.error('discriminator must be 0..4095')
    project=json.loads(a.base.read_text()); project['name']='Matter C MP04 endpoint '+str(a.endpoint)
    project['config']['dut_config']['discriminator']=str(a.discriminator)
    project['config']['test_parameters']['endpoint']=str(a.endpoint)
    profiles=project['pics']['clusters']
    flags={
        'I': {'I.S':bool(a.endpoint),'I.S.A0000':bool(a.endpoint),'I.S.A0001':bool(a.endpoint),'I.S.C00.Rsp':bool(a.endpoint),'I.S.C40.Rsp':False},
        'MTRID': {'MTRID.S':bool(a.endpoint),'MTRID.S.F00':False,**{f'MTRID.S.A{x:04x}':bool(a.endpoint) and x<4 for x in range(5)}},
        'TIMESYNC': {'TIMESYNC.S':not a.endpoint,**{f'TIMESYNC.S.F{x:02x}':False for x in range(4)},
                     **{f'TIMESYNC.S.A{x:04x}':not a.endpoint and x<3 for x in range(13)},
                     **{f'TIMESYNC.S.C{x:02x}.Rsp':not a.endpoint and x==0 for x in (0,1,2,4,5)},
                     **{f'TIMESYNC.S.E{x:02x}':not a.endpoint and x==3 for x in range(5)}},
    }
    for cluster,items in flags.items(): profiles[cluster]={'name':cluster,'items':{k:{'number':k,'enabled':v} for k,v in items.items()}}
    with a.output.open('x') as f: json.dump(project,f,indent=2); f.write('\n')
    print('Prepared new MP04 project; import explicitly. Existing projects unchanged.')


if __name__=='__main__': main()
