"""Render/check the CSA72 local review packet; never submits or runs a test."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

from csa_campaign import campaign


def identity(row):
    return row['case'], row['endpoint'], row['collection']


def render(root, packet):
    if packet.get('schema') != 1 or packet['submission_state'] != 'DRAFT_NOT_SENT':
        raise ValueError('This tool handles an unsent review packet only')
    if not re.fullmatch(r'[0-9a-f]{40}', packet['evidence_base_commit']):
        raise ValueError('Evidence must be anchored to an exact Git commit')
    _, rows, _, _ = campaign(root)
    opened = {identity(r): r for r in rows if r['status'] in ('FAIL', 'BLOCKED') or
              r['status'] == 'MANUAL' and r.get('manual_result') in ('FAIL', 'BLOCKED', None)}
    represented = []
    ids = []
    for group in packet['groups']:
        ids.append(group['id'])
        if group.get('decision_state') != 'PENDING' or group.get('rerun_authorized_by_this_packet') is not False:
            raise ValueError('Packet records pending decisions and grants no execution authorization')
        for key in ('recorded_observation', 'requested_decision', 'rerun_gate', 'evidence'):
            if not group.get(key):
                raise ValueError(f'Missing {key} in {group["id"]}')
        for row in group['cases']:
            item = identity(row)
            represented.append(item)
            if item not in opened:
                raise ValueError(f'Not currently open: {item}')
            current = opened[item]
            if (row['status'], row.get('manual_result')) != (current['status'], current.get('manual_result')):
                raise ValueError(f'Stale verdict: {item}')
        for name in group['evidence']:
            path = Path(name)
            if path.name != name or not (root / 'doc/oss' / path).is_file():
                raise ValueError(f'Invalid evidence path: {name}')
    if len(ids) != len(set(ids)) or Counter(represented) != Counter(opened.keys()):
        raise ValueError('Packet must cover every open identity exactly once')
    referenced = {name for group in packet['groups'] for name in group['evidence']}
    if referenced != set(packet['evidence_git_blob_sha256']):
        raise ValueError('Every referenced evidence file must have a pinned Git blob hash')
    for name, expected in packet['evidence_git_blob_sha256'].items():
        if Path(name).name != name:
            raise ValueError('Evidence must stay in doc/oss')
        data = subprocess.check_output(['git', 'show', packet['evidence_base_commit'] + ':doc/oss/' + name], cwd=root)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'Evidence hash mismatch: {name}')
    groups = packet['groups']
    questions = [g for g in groups if g['category'].startswith('CSA_')]
    prerequisites = [g for g in groups if not g['category'].startswith('CSA_')]
    lines = ['# CSA72: consolidated questions and rerun gates', '',
             '**DRAFT — NOT SENT. No CSA answer, approved correction or new test verdict is claimed.**', '',
             packet['context'], '',
             f'Coverage: {len(opened)} exact open positions: 27 FAIL and 5 prerequisites. '
             f'{len(questions)} question groups and {len(prerequisites)} owner/laboratory prerequisite groups. '
             'Campaign total remains123 PASS/27 FAIL/5 prerequisites; manual and automatic results remain separate.', '',
             '## How to use this package', '', packet['review_workflow'], '',
             'The JSON is the source of this list. Each linked receipt retains original run IDs, source hashes, '
             'unexecuted portions and independent acceptance limits. Campaign run IDs below can be inherited '
             'checkpoint references; explicitly selected reference runs identify the later reviewed evidence. '
             'No raw credentials, certificate bytes, private traces or specification PDFs are attached.', '',
             '| Topic | Cases | Decision owner |', '| --- | --- | --- |']
    for group in groups:
        owner = 'CSA / test maintainers' if group['category'].startswith('CSA_') else 'Product / laboratory owner'
        cases = ', '.join(row['case'] for row in group['cases'])
        lines.append(f'| [{group["id"]}: {group["title"]}](#{group["id"].lower()}) | {cases} | {owner} |')
    for group in groups:
        lines += ['', f'## {group["id"]}', '', f'**{group["title"]}**', '',
                  f'Category: `{group["category"]}`. Decision state: **pending**.', '',
                  '| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |',
                  '| --- | --- | --- | --- | --- | --- |']
        for row in group['cases']:
            state = row['status'] + ('/' + row['manual_result'] if row.get('manual_result') else '')
            refs = ', '.join(str(n) for n in row['reference_runs']) or 'See linked receipt; no executed result for this prerequisite'
            lines.append(f'| {row["case"]} | {row["endpoint"]} | {row["collection"]} | {state} | {row.get("campaign_run_id") or "Not recorded in checkpoint"} | {refs} |')
        lines += ['', '**Recorded observation:** ' + group['recorded_observation'], '',
                  '**Requested decision / input:** ' + group['requested_decision'], '',
                  '**Rerun only after:** ' + group['rerun_gate'], '',
                  'Evidence: ' + ', '.join(f'[{name}]({name})' for name in group['evidence']) + '.']
    lines += ['', '## Common acceptance and rerun rules', '']
    lines.extend(f'{i}. {value}' for i, value in enumerate(packet['common_rerun_rules'], 1))
    lines += ['', '## Next action', '', packet['next_action'], '',
              'Generated from [csa72-questions.json](csa72-questions.json) by '
              '`python tools/matter/csa_review_packet.py --write`. Local rendering does not submit anything.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    folder = root / 'doc/oss'
    packet = json.loads((folder / 'csa72-questions.json').read_bytes())
    text = render(root, packet)
    output = folder / 'csa72-questions.md'
    if args.write:
        with output.open('w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
    elif output.read_text(encoding='utf-8') != text:
        raise ValueError('Stale packet Markdown; run with --write')
    print(f'PASS CSA72 packet: {sum(len(g["cases"]) for g in packet["groups"])} exact open positions, '
          f'{len(packet["groups"])} groups, evidence identity/coverage/rendering match; draft not sent.')


if __name__ == '__main__':
    main()
