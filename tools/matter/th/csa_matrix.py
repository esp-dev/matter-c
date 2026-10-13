"""Index a pinned installed TH catalog against the CSA01 x86 profile.

Inputs are private catalog/SDK metadata and scripts (not redistributed). The
output contains IDs, source hashes, applicability and run evidence references;
it does not copy test instructions. Missing gates remain BLOCKED, never PASS.
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from full_profile_project import flags_for

FAMILIES = set('ACL ACE BINFO CGEN CNET OPCREDS CADMIN TIMESYNC MTRID EPM EEM '
               'PWRTL DGGEN DGWIFI I DESC SC DA IDM MCORE GRPKEY SU BDX DD DT RR'.split())
MULTI = {'EPM': (1, 3, 4, 5), 'PWRTL': (1, 3, 4, 5), 'EEM': (1,), 'I': (1,), 'MTRID': (1,)}
NO_FEATURE = {
    'TC_DGWIFI_3_2': 'No Wi-Fi Network Diagnostics client role.',
    'TC_DD_3_23': 'No NFC commissioning transport.',
    'TC_DD_3_24': 'No unpowered NFC commissioning transport.',
    'TC_SC_5_1': 'No Groups endpoints; script skips the group-member steps.',
    'TC_SC_5_2': 'No Groups endpoints; group messaging is outside this profile.',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--queue', type=Path)
    a = p.parse_args()
    profile = json.loads(a.profile.read_text(encoding='utf-8'))
    catalog = json.loads((a.inputs / 'catalog.json').read_text(encoding='utf-8'))
    info = json.loads((a.inputs / 'python_tests_info.json').read_text(encoding='utf-8'))
    metadata = {t['function'].removeprefix('test_'): t for t in info['tests']}
    rows = []
    for collection, col in catalog['test_collections'].items():
        for suite, su in col['test_suites'].items():
            for case in su['test_cases']:
                normalized = case.replace('-', '_').replace('.', '_')
                family = normalized.split('_')[1] if normalized.startswith('TC_') else ''
                endpoints = MULTI.get(family, (0,))
                if case == 'TC_IDM_10_4':
                    endpoints = (0, 1, 3, 4, 5)
                for ep in endpoints:
                    plan_match = re.fullmatch(r'TC[_-](.+?)[_-](\d+)[_.](\d+)', case)
                    plan_id = ('TC-' + plan_match[1].replace('_', '-') + '-' +
                               plan_match[2] + '.' + plan_match[3]) if plan_match else case
                    row = dict(case=case, test_plan_id=plan_id, endpoint=ep, collection=collection, suite=suite,
                               status='PLANNED', reason='Automated official case; fresh DUT per case.')
                    if family not in FAMILIES:
                        row.update(status='NA', reason='Cluster/device role not present in the frozen profile.')
                        rows.append(row)
                        continue
                    meta = metadata.get(normalized, {}) if '_' in case and '-' not in case else {}
                    source = (a.inputs / 'python_testing/scripts' / (meta['path'] + '.py') if meta else
                              a.inputs / 'yaml_tests/yaml/sdk' / ('Test_' + normalized + '.yaml'))
                    gates = list(meta.get('pics', []))
                    if source.exists():
                        row['source'] = source.relative_to(a.inputs).as_posix()
                        row['source_sha256'] = digest(source)
                        if not meta:
                            match = re.search(r'^PICS:(.*?)(?=^[A-Za-z])', source.read_text(encoding='utf-8'), re.M | re.S)
                            if match:
                                gates = re.findall(r'^\s*-\s*([A-Za-z0-9_.]+)\s*$', match[1], re.M)
                    row['pics_required'] = gates
                    flags = flags_for(profile, ep)
                    false = [g for g in gates if g in flags and not flags[g]]
                    unknown = [g for g in gates if g not in flags]
                    if false:
                        row.update(status='NA', reason='Unsupported declared capability: ' + ', '.join(false))
                    elif normalized in NO_FEATURE:
                        row.update(status='NA', reason=NO_FEATURE[normalized])
                    elif normalized.startswith('TC_MCORE_FS_'):
                        row.update(status='NA', reason='No fabric synchronization administrator/bridge role.')
                    elif normalized.startswith('TC_SC_TC_'):
                        row.update(status='NA', reason='No Thread MeshCoP commissioning transport.')
                    elif unknown:
                        row.update(status='BLOCKED', reason='PICS applicability requires review: ' + ', '.join(unknown))
                    elif normalized in ('TC_EPM_2_2', 'TC_EEM_2_2', 'TC_EEM_2_3'):
                        row.update(status='BLOCKED', reason='Three-phase host rejects TestEventTrigger injection; legacy sum-only results do not cover this profile.')
                    elif family == 'SU':
                        row.update(status='BLOCKED', reason='OTA provider/image and apply/reboot fixture not configured for this frozen host.')
                    elif 'Manual' in suite or collection == 'Onboarding Payload Tests':
                        row.update(status='MANUAL', reason='Official procedure needs operator/packet-capture or onboarding-artifact evidence; not executed automatically.')
                        if normalized == 'TC_SC_4_4':
                            row['reason'] = ('Limited OTA client can initiate CASE/discovery; procedure uses a BINFO Read client '
                                             'which is not implemented. Resolve step applicability/fixture with CSA; not waived as NA.')
                    elif not source.exists():
                        row.update(status='BLOCKED', reason='Installed script source not included in the private source snapshot.')
                    # No automatic change of PICS after observing a failure.
                    result_path = a.inputs / 'runs' / f'CSA01-ep{ep}-{case}.json'
                    attempts = ([result_path] if result_path.exists() else []) + list((a.inputs / 'runs').glob(
                        f'CSA01-ep{ep}-{case}-attempt[0-9]*.json'))
                    if attempts:
                        for path in attempts:
                            attempt = json.loads(path.read_text(encoding='utf-8'))
                            executed = [t['public_id'] for s in attempt['test_suite_executions']
                                        for t in s['test_case_executions']]
                            if (attempt['title'] != path.stem or executed != [case]
                                    or not attempt['completed_at']):
                                raise ValueError(f'Incomplete or mismatched exact-case evidence: {path}')
                        attempts.sort(key=lambda path: json.loads(path.read_text(encoding='utf-8'))['id'])
                        row['attempts'] = [dict(run_id=(attempt := json.loads(path.read_text(encoding='utf-8')))['id'],
                                                th_state=attempt['state'], evidence_sha256=digest(path))
                                           for path in attempts]
                        result_path = attempts[-1]
                        result = json.loads(result_path.read_text(encoding='utf-8'))
                        row['run_id'] = result['id']
                        row['th_state'] = result['state']
                        row['evidence_sha256'] = digest(result_path)
                        row['started_at'] = result['started_at']
                        steps = [step for suite_result in result.get('test_suite_executions', [])
                                 for case_result in suite_result['test_case_executions']
                                 for step in case_result['test_step_executions']]
                        row['step_states'] = dict(Counter(s['state'].split('.')[-1] for s in steps))
                        row['failed_step_indices'] = [s['execution_index'] for s in steps
                                                      if s['state'].split('.')[-1] in ('failed', 'error')]
                        # Digests bind each result to the PICS actually used, including
                        # early root runs before the additional core-role declarations.
                        row['execution_pics_sha256'] = hashlib.sha256(json.dumps(
                            result['execution_pics'], sort_keys=True).encode()).hexdigest()
                        state = result['state'].split('.')[-1]
                        row['status'] = {'passed': 'PASS', 'failed': 'FAIL', 'error': 'ERROR',
                                         'cancelled': 'BLOCKED', 'canceled': 'BLOCKED', 'aborted': 'BLOCKED',
                                         'skipped': 'SKIP'}.get(state, 'BLOCKED')
                        log = result_path.with_suffix('.log')
                        text = log.read_text(encoding='utf-8', errors='replace') if log.exists() else ''
                        if 'CSA01_BLOCKED_PROMPT ' in text:
                            row.update(status='BLOCKED', reason='Operator action required; prompt recorded, no synthetic confirmation.')
                        else:
                            row['reason'] = 'Official TH result; see run/step evidence and triage.'
                        if row['status'] == 'PASS' and not row['step_states'].get('passed', 0):
                            row.update(status='SKIP', reason='No passed steps in the official case; do not count as coverage.')
                    rows.append(row)
    output = dict(schema=1, sdk_sha=info['sdk_sha'], profile_sha256=digest(a.profile),
                  catalog_sha256=digest(a.inputs / 'catalog.json'),
                  unique_test_plan_ids=len({r['test_plan_id'] for r in rows}),
                  counts=dict(Counter(r['status'] for r in rows)), cases=rows)
    # One row per line keeps the complete catalog reviewable without a many-
    # thousand-line indentation-only diff on each acceptance pass.
    header = json.dumps({k: v for k, v in output.items() if k != 'cases'}, indent=2)
    a.output.write_text(header[:-2] + ',\n  "cases": [\n' +
                        ',\n'.join('    ' + json.dumps(r) for r in rows) + '\n  ]\n}\n', encoding='utf-8')
    if a.queue:
        queue = [dict(endpoint=r['endpoint'], case=r['case'], timeout=1800)
                 for r in rows if r['status'] == 'PLANNED']
        a.queue.write_text(json.dumps(queue, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output['counts']))


if __name__ == '__main__':
    main()
