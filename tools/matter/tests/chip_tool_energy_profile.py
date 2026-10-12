"""Full host-profile oracle using decoded, unmodified chip-tool reports.

Inventory comes from Descriptor/AttributeList, not the C implementation's
capacity. A successful SubscribeResponse alone is deliberately insufficient.
"""
import json
import re
import time

HEADER = re.compile(r'Endpoint: (\d+) Cluster: (0x[\dA-Fa-f_]+) (Attribute|Event) (0x[\dA-Fa-f_]+)(?: DataVersion: (\d+))?')


def frames(text):
    result = []
    for line in re.findall(r'\[TOO\]\s*([^\r\n]*)', text):
        match = HEADER.fullmatch(line.strip())
        if match:
            ep, cluster, kind, identifier, version = match.groups()
            result.append({'path': (int(ep), int(cluster.replace('_', ''), 16), int(identifier.replace('_', ''), 16)),
                           'kind': kind, 'version': int(version) if version else None, 'body': ''})
        elif result:
            result[-1]['body'] += line.strip() + '\n'
    return result


def integer(body, name):
    match = re.search(r'^' + re.escape(name) + r': (-?\d+)\b', body, re.M)
    if not match:
        raise ValueError('Missing numeric ' + name)
    return int(match[1])


def ids(body, name):
    count = integer(body, name)
    values = [int(x) for x in re.findall(r'^\[\d+\]: (\d+)\b', body, re.M)]
    if len(values) != count or len(set(values)) != count:
        raise ValueError('Incomplete/duplicate ' + name)
    return values


def catalog(data, test_switch=False):
    attributes = {f['path']: f['body'] for f in frames(data) if f['kind'] == 'Attribute'}
    endpoints = [0, *ids(attributes[0, 0x1d, 3], 'PartsList')]
    if set(endpoints) != ({0, 1, 2} if test_switch else {0, 1}):
        raise ValueError('Expected Root and electrical sensor endpoints')
    if integer(attributes[0, 0x1d, 0], 'DeviceType') != 0x16 or integer(attributes[1, 0x1d, 0], 'DeviceType') != 0x510:
        raise ValueError('Wrong device types')
    if test_switch and (integer(attributes[2, 0x1d, 0], 'DeviceType') != 0x10a or (2, 6, 0) not in attributes):
        raise ValueError('Missing test switch')
    expected = set()
    for ep in endpoints:
        clusters = ids(attributes[ep, 0x1d, 1], 'ServerList')
        if ep == 1 and not {0x1d, 0x90, 0x91, 0x9c}.issubset(clusters):
            raise ValueError('Missing electrical clusters')
        for cluster in clusters:
            expected.update((ep, cluster, attr) for attr in ids(attributes[ep, cluster, 0xfffb], 'AttributeList'))
    if set(attributes) != expected or len(expected) <= 120:
        raise ValueError(f'Incomplete wildcard: expected {len(expected)}, received {len(attributes)} attributes')
    if integer(attributes[1, 0x90, 0xfffc], 'FeatureMap') != 6 or integer(attributes[1, 0x91, 0xfffc], 'FeatureMap') != 7:
        raise ValueError('Unexpected AC/import/export/cumulative features')
    return expected


def measurements(data, updates=False):
    decoded = frames(data)
    result = {}
    power = [integer(f['body'], 'ActivePower') for f in decoded if f['kind'] == 'Attribute' and f['path'] == (1, 0x90, 8)]
    if not power or not set(power).issubset({3600000, -1800000}) or (updates and len(set(power)) != 2):
        raise ValueError('Missing/invalid signed AC power, or no sign transition')
    result['power_W'] = [p / 1000 for p in power]
    series = []
    for attr, name in ((1, 'import'), (2, 'export')):
        samples = []
        for f in decoded:
            if f['kind'] == 'Attribute' and f['path'] == (1, 0x91, attr):
                sample = (integer(f['body'], 'Energy'), integer(f['body'], 'EndSystime'), f['version'])
                if sample[0] < 0 or sample[2] is None:
                    raise ValueError('Invalid energy/version')
                if samples and (sample[0] < samples[-1][0] or sample[1] < samples[-1][1]):
                    raise ValueError('Energy/time moved backwards')
                if samples and sample[0] != samples[-1][0] and sample[2] == samples[-1][2]:
                    raise ValueError('Energy changed without DataVersion')
                samples.append(sample)
        if not samples or (updates and len({x[0] for x in samples}) < 3):
            raise ValueError('Missing/dormant ' + name + ' register')
        result[name + '_mWh'] = [x[0] for x in samples]
        result[name + '_kWh'] = samples[-1][0] / 1_000_000
        series.append({t: e for e, t, _ in samples})
    if updates:
        events = [f for f in decoded if f['kind'] == 'Event' and f['path'] == (1, 0x91, 0)]
        numbers = [integer(f['body'], 'Event number') for f in events]
        if len(numbers) < 3 or numbers != sorted(set(numbers)):
            raise ValueError('Missing/duplicated/out-of-order energy events')
        matched = [0, 0]
        for f in events:
            for i, direction in enumerate(('Imported', 'Exported')):
                match = re.search(r'Energy' + direction + r': \{(.*?)\}', f['body'], re.S)
                if not match:
                    raise ValueError('Incomplete energy event')
                energy = integer(match[1].strip(), 'Energy')
                stamp = integer(match[1].strip(), 'EndSystime')
                if stamp in series[i]:
                    if series[i][stamp] != energy:
                        raise ValueError('Event/attribute disagreement at same measurement time')
                    matched[i] += 1
        if not all(matched):
            raise ValueError('No event/attribute correlation')
        result['event_numbers'] = numbers
    return result


def run_profile(command, text, record, out, test_switch=False):
    """Run on a commissioned interactive controller with Administer access."""
    def check(name, ok, detail):
        record('full-profile-' + name, bool(ok), detail)
        if not ok:
            raise ValueError(name)

    try:
        ok, _ = command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        check('stop-old', ok, 'isolate reports from previous subscriptions')
        time.sleep(.2)
        start = len(text())
        paths = ['0xffffffff,0xffffffff', '0xffffffff', '0xffffffff']
        ok, _ = command(['any', 'read-all', *paths, 1, '0xffff,0xffff'], r'SuppressResponse = true', timeout=40)
        time.sleep(.3)  # The decoded TOO fields follow the final DMG header.
        data = text()[start:]
        (out / 'full-profile-read.log').write_text(data)
        check('read-complete', ok and 'MoreChunkedMessages = true' in data and 'CHIP Error' not in data,
              'mixed wildcard Read, multiple chunks and terminal response')
        expected = catalog(data, test_switch)
        baseline = measurements(data)
        check('inventory', True, f'{len(expected)} paths; exact agreement with Descriptor/AttributeList and electrical features')
        start = len(text())
        ok, _ = command(['any', 'subscribe-all', *paths, 0, 3, 1, '0xffff,0xffff', '--keepSubscriptions', 0],
                        r'Subscription established', timeout=40)
        check('established', ok, 'all attributes + all events in one interaction')
        prime = text()[start:].split('Subscription established', 1)[0]
        check('prime-inventory', catalog(prime, test_switch) == expected, 'all advertised readable paths survived priming/chunking')
        time.sleep(12)  # Includes a full 10-second simulated power cycle.
        data = text()[start:]
        (out / 'full-profile-subscribe.log').write_text(data)
        check('no-protocol-error', 'Run command failure' not in data and 'CHIP Error' not in data and
              not re.search(r'StatusCode = 0x(?!0+\b)[0-9a-fA-F]+', data), 'no hidden decode/status error')
        measured = measurements(data, updates=True)
        check('energy-updates', True, 'both signed power states, increasing import/export, DataVersion and event/attribute correlation')
        (out / 'energy-profile.json').write_text(json.dumps({'attribute_count': len(expected),
            'paths': sorted(expected), 'read': baseline, 'subscription': measured}, indent=2) + '\n')
        return True
    except (ValueError, KeyError) as error:
        record('full-profile-validation', False, str(error))
        return False
