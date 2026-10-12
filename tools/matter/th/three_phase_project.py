"""Prepare a NEW TH project import from an exported baseline, without contacting TH.

Use th-cli project export for --base, then project import for --output. Both
files can contain private lab configuration; keep them in ignored build/.
This describes the --three-phase host, not the default host or certification.
"""
import argparse
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--endpoint', type=int, choices=(0, 1, 3, 4, 5), required=True)
    p.add_argument('--discriminator', type=int, required=True)
    a = p.parse_args()
    if not 0 <= a.discriminator <= 4095:
        p.error('discriminator must be 0..4095')
    project = json.loads(a.base.read_text())
    project['name'] = 'Matter C MP02 endpoint ' + str(a.endpoint)
    project['config']['dut_config']['discriminator'] = str(a.discriminator)
    project['config']['test_parameters']['endpoint'] = str(a.endpoint)
    profiles = project['pics']['clusters']
    files = {'EPM': 'electrical-power-measurement.txt', 'EEM': 'electrical-energy-measurement.txt',
             'PWRTL': 'power-topology.txt'}
    for cluster, filename in files.items():
        flags = {}
        for raw in (Path(__file__).resolve().parents[1] / 'tests/pics' / filename).read_text().splitlines():
            line = raw.partition('#')[0].strip()
            if line:
                key, value = line.split('=')
                flags[key] = value == '1'
        if cluster == 'EPM':
            flags['EPM.S.F02'] = a.endpoint == 1
            for attribute in (4, 8, 9, 10, 12, 17):
                flags[f'EPM.S.A{attribute:04x}'] = attribute in ({8, 9, 10, 17} if a.endpoint == 1 else {4, 8, 9, 12})
        if cluster == 'EEM':
            flags['EEM.S.A0005'] = True
        if not a.endpoint or (cluster == 'EEM' and a.endpoint != 1):
            flags = dict.fromkeys(flags, False)
        profiles[cluster] = {'name': cluster, 'items': {key: {'number': key, 'enabled': value} for key, value in flags.items()}}
    flags = {'DESC.S': True, 'DESC.S.F00': a.endpoint != 0}
    flags.update({f'DESC.S.A{x:04x}': x != 4 or a.endpoint != 0 for x in range(5)})
    profiles['DESC'] = {'name': 'DESC', 'items': {key: {'number': key, 'enabled': value} for key, value in flags.items()}}
    with a.output.open('x') as f:
        json.dump(project, f, indent=2)
        f.write('\n')
    print('Prepared new endpoint project; import explicitly, no existing project changed.')


if __name__ == '__main__':
    main()
