"""MP03 oracle for an unmodified chip-tool, using its generic decoded DMG TLV.

The SDK has no named logger for this private schema. Parse the DMG values and
reassemble ListIndex=null chunks; do not count 'Don't know how to log' as data.
Run against a disposable --three-phase --source-registers host (no test switch).
"""
import argparse
import json
from pathlib import Path
import re
import time
from chip_tool_resources import Client
from chip_tool_energy_profile import frames, ids
from chip_tool_three_phase import inventory, values

CLUSTER = 0xfff1fc01
ATTRIBUTES = set(range(6)) | {0xfff8, 0xfff9, 0xfffb, 0xfffc, 0xfffd}


def scalar(s):
    s = s.strip().rstrip(',').strip()
    if s.lower().startswith('null'):
        return None
    if s.startswith('"'):
        return json.JSONDecoder().raw_decode(s)[0]
    if s.startswith(('true', 'false')):
        return s.startswith('true')
    m = re.match(r'-?(?:0x[0-9a-fA-F_]+|\d+)\b', s)
    assert m, s
    token = m[0].replace('_', '')
    return int(token, 16 if 'x' in token else 10)


def tree(lines, index):
    while index < len(lines) and not lines[index].strip():
        index += 1
    assert index < len(lines), 'missing generic TLV value'
    first = lines[index].strip().rstrip(',')
    if first not in ('[', '{'):
        return scalar(first), index + 1
    result = [] if first == '[' else {}
    end = ']' if first == '[' else '}'
    index += 1
    while index < len(lines):
        line = lines[index].strip().rstrip(',')
        if not line:
            index += 1
            continue
        if line == end:
            return result, index + 1
        if isinstance(result, dict):
            key, value = line.split(' = ', 1)
            key = int(key, 16)
            assert key not in result, 'duplicate struct tag'
            result[key] = scalar(value)
            index += 1
        else:
            if line.startswith(('{', '[')):
                value, index = tree(lines, index)
                result.append(value)
            else:
                result.extend(scalar(value) for value in line.split(',') if value.strip())
                index += 1
    raise AssertionError('truncated generic TLV')


def source_reports(text):
    dmg = '\n'.join(re.findall(r'\[DMG\][ \t]*([^\r\n]*)', text))
    records = []
    current = {}
    for block in dmg.split('AttributeDataIB =')[1:]:
        match = re.search(r'Cluster = (0x[\da-fA-F_]+)', block)
        if not match or int(match[1].replace('_', ''), 16) != CLUSTER:
            continue
        endpoint = scalar(re.search(r'Endpoint = ([^\n]+)', block)[1])
        attr = scalar(re.search(r'Attribute = ([^\n]+)', block)[1])
        version = scalar(re.search(r'DataVersion = ([^\n]+)', block)[1])
        data = block.split('Data = ', 1)[1].splitlines()
        value, _ = tree(data, 0)
        path = endpoint, attr
        if re.search(r'ListIndex = null', block.split('Data = ', 1)[0], re.I):
            assert path in current and current[path]['version'] == version, 'orphan/mixed-version list chunk'
            assert isinstance(current[path]['value'], list)
            current[path]['value'].append(value)
        else:
            if path in current:
                records.append(current[path])
            current[path] = dict(endpoint=endpoint, attribute=attr, version=version, value=value)
    return records + list(current.values())


def validate_source(text, dynamic=False):
    rows = source_reports(text)
    assert rows and {r['attribute'] for r in rows} == ATTRIBUTES
    seen = {a: [] for a in range(6)}
    for row in rows:
        a, data = row['attribute'], row['value']
        assert row['endpoint'] == 1
        if a == 0xfffb:
            assert set(data) == ATTRIBUTES and len(data) == len(ATTRIBUTES)
        elif a in (0xfff8, 0xfff9):
            assert data == []
        elif a == 0xfffc:
            assert data == 0
        elif a == 0xfffd:
            assert data == 1
        elif a == 1:
            assert data[0] in (0, 1, 2) and data[5] == 1 and data[8] == 0
            seen[a].append(data)
        else:
            count = {0: 10, 2: 24, 3: 27, 4: 6, 5: 4}[a]
            assert len(data) == count and {x[0] for x in data} == set(range(count)), (a, len(data))
            assert len({(x[20], x[21]) for x in data}) == 1, 'torn list snapshot'
            assert all(x[20] == 1 and x[21] >= 1 for x in data)
            d = {x[0]: x for x in data}
            if a == 0:
                assert d[0][1] == 'SIM-0001' and d[4][1] == '1.0'
            else:
                assert all(x[7] == (-6 if a == 5 else -4 if a == 3 and x[0] == 26 else -3) for x in data)
                if a == 2:
                    assert d[0][8] is None or d[0][8] >= 12345678000
                    assert d[3][8] is None or d[3][8] >= 123450000
                    assert {(d[k][4], d[k][5], d[k][3]) for k in range(12, 24)} == {(direction, q, t) for direction in (1, 2) for q in (1, 2) for t in range(3)}
                    assert all(d[k][6] == (1 if k < 6 else 2) for k in range(24))
                if a == 3:
                    assert d[16][8] in (1500000, None) and d[24][8] in (-4000, None)
                    assert d[24][9] == 2
                    if d[0][8] is not None:
                        assert 1234000 <= d[0][8] - d[4][8] <= 1238000
                if a == 4:
                    assert all(x[8] is None or x[8] == (x[0]+1)*1000000 for x in data)
                if a == 5:
                    assert d[3][6] == 0 and (d[3][8] is None or d[3][8] >= 126456789) and d[2][11] is None
                    assert all(x[10] == 'SIM-VOLUME' for x in data)
            seen[a].append(d)
    assert all(seen.values()), 'missing source group'
    if dynamic:
        assert {x[0] for x in seen[1]} >= {0, 1, 2}, 'missing offline/stale/recovery'
        assert any(x[2][8] is None and x[1][8] is not None for x in seen[2]), 'T2 missing was fabricated'
        assert len({x[0][8] for x in seen[2] if x[0][8] is not None}) >= 3
        assert len({r['version'] for r in rows}) >= 3
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True); p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True); p.add_argument('--discriminator', type=int, default=3847)
    a = p.parse_args(); out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    c = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, 'controller')
    checks = []
    def check(name, ok):
        checks.append(dict(name=name, passed=bool(ok)))
        (out/'results.json').write_text(json.dumps(checks, indent=2)+'\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True); assert ok, name
    try:
        ok, data = c.command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL', '--timeout', 60], r'Device commissioning completed with success', 65)
        check('attested-commissioning', ok and "Successfully finished commissioning step 'AttestationVerification'" in data)
        ok, data = c.command(['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', 1, '0xffff,0xffff'], r'SuppressResponse = true', 40)
        (out/'read.log').write_text(data)
        check('wildcard-chunked-read', ok and 'MoreChunkedMessages = true' in data)
        inventory(data, source_cluster=CLUSTER); validate_source(data)
        check('full-standard-and-MS-inventory-values-schema', True)
        start = len(c.text())
        ok, _ = c.command(['any', 'subscribe-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', 0, 3, 1, '0xffff,0xffff', '--keepSubscriptions', 0], r'Subscription established', 40)
        check('source-subscription-established', ok)
        time.sleep(27)
        data = c.text()[start:]; (out/'subscribe.log').write_text(data)
        validate_source(data, True)
        decoded = frames(data)
        for path in ((1, 0x90, 8), (1, 0x91, 1), (1, 0x91, 2), (3, 0x90, 4)):
            samples = [f['body'] for f in decoded if f['kind'] == 'Attribute' and f['path'] == path]
            assert any(re.search(r'\bnull\b', s, re.I) for s in samples), 'standard measurement did not follow source loss'
            assert any(not re.search(r'\bnull\b', s, re.I) for s in samples), 'standard measurement never recovered'
        check('coherent-chunks-nulls-offline-stale-recovery-and-updates', 'Run command failure' not in data and 'CHIP Error' not in data)
        c.command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        ok, data = c.command(['any', 'write-by-id', hex(CLUSTER), 2, '[]', 1, 1], r'UNSUPPORTED_WRITE|UnsupportedWrite|0x0*88\b', failure=True)
        check('source-read-only', ok)
        ok, data = c.command(['any', 'read-by-id', '0xfff2fc01', 2, 1, 1], r'UNSUPPORTED_CLUSTER|UnsupportedCluster|0x0*c3\b', failure=True)
        check('vendor-namespace-isolated', ok)
        restricted = json.dumps([dict(privilege=5, authMode=2, subjects=None, targets=[dict(cluster=31, endpoint=0, deviceType=None)])])
        ok, _ = c.command(['accesscontrol', 'write', 'acl', restricted, 1, 0], r'status = 0x00', 15)
        check('restrict-disposable-fabric-ACL', ok)
        ok, _ = c.command(['any', 'read-by-id', hex(CLUSTER), 2, 1, 1], r'UNSUPPORTED_ACCESS|UnsupportedAccess|0x0*7e\b', failure=True)
        check('MS-read-obeys-ACL', ok)
        unrestricted = json.dumps([dict(privilege=5, authMode=2, subjects=None, targets=None)])
        ok, _ = c.command(['accesscontrol', 'write', 'acl', unrestricted, 1, 0], r'status = 0x00', 15)
        check('restore-disposable-fabric-ACL', ok)
    finally:
        c.close()


if __name__ == '__main__':
    main()
