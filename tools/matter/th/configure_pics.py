"""Apply one host cluster's PICS to an idle TH project, preserving its config.

The output directory must be new. It contains private project snapshots; keep
it outside version control. A capability declaration is not a test result.
"""
import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api', required=True, help='TH API base, ending in /api/v1')
    parser.add_argument('--project-id', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cluster', choices=('OPCREDS', 'CGEN', 'CNET', 'PWRTL', 'EPM', 'EEM', 'ACL'), default='OPCREDS')
    args = parser.parse_args()
    filenames = {'OPCREDS': 'operational-credentials.txt', 'CGEN': 'general-commissioning.txt',
                 'CNET': 'network-commissioning.txt', 'PWRTL': 'power-topology.txt',
                 'EPM': 'electrical-power-measurement.txt', 'EEM': 'electrical-energy-measurement.txt',
                 'ACL': 'access-control.txt'}
    pics_file = Path(__file__).resolve().parents[1] / 'tests/pics' / filenames[args.cluster]
    items = {}
    for raw in pics_file.read_text(encoding='utf-8').splitlines():
        line = raw.partition('#')[0].strip()
        if not line:
            continue
        key, value = (part.strip() for part in line.split('='))
        if not key.startswith(args.cluster + '.') or value not in ('0', '1') or key in items:
            raise ValueError(f'Invalid or duplicate PICS: {key}')
        items[key] = {'number': key, 'enabled': value == '1'}
    if not items or args.project_id < 1:
        raise ValueError('Missing PICS or invalid project id')

    def api(path, data=None):
        request = Request(args.api.rstrip('/') + '/' + path,
                          data=None if data is None else json.dumps(data).encode(),
                          headers={'Content-Type': 'application/json'},
                          method='GET' if data is None else 'PUT')
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    if api('test_run_executions/status')['state'] != 'idle':
        raise RuntimeError('TH is not idle; no configuration was changed')
    path = f'projects/{args.project_id}'
    before = api(path)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'project-before.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    pics = json.loads(json.dumps(before['pics']))
    pics['clusters'][args.cluster] = {'name': args.cluster, 'items': items}
    api(path, {'pics': pics})
    after = api(path)
    (args.output / 'project-after.json').write_text(json.dumps(after, indent=2), encoding='utf-8')
    if after['config'] != before['config'] or after['pics'] != pics:
        raise RuntimeError('Readback differs; inspect snapshots before proceeding')
    print(f'Saved and read back {len(items)} {args.cluster} PICS; project config unchanged.')


if __name__ == '__main__':
    main()
