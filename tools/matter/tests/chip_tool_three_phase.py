"""MP02 independent chip-tool acceptance of the opt-in x86 profile, not CSA certification.

Run against a disposable --three-phase node, without --test-switch. The source
cycles every 20 seconds, including five seconds of unavailable L3. Keep the
output/controller store for a second run with --restart-storage after DUT restart.
"""
import argparse
import json
from pathlib import Path
import re
import time

from chip_tool_resources import Client
from chip_tool_energy_profile import frames, ids, integer


def inventory(text, test_switch=False, source_cluster=None, meter_services=False):
    attrs = {f['path']: f for f in frames(text) if f['kind'] == 'Attribute'}
    endpoints = {0, 1, 3, 4, 5} | ({2} if test_switch else set())
    assert set(ids(attrs[0, 0x1d, 3]['body'], 'PartsList')) == endpoints - {0}
    assert set(ids(attrs[1, 0x1d, 3]['body'], 'PartsList')) == {3, 4, 5}
    expected = set()
    for ep in sorted(endpoints):
        clusters = ids(attrs[ep, 0x1d, 1]['body'], 'ServerList')
        if ep == 2:
            assert integer(attrs[ep, 0x1d, 0]['body'], 'DeviceType') == 0x10a
            assert 6 in clusters
        elif ep:
            assert integer(attrs[ep, 0x1d, 0]['body'], 'DeviceType') == 0x510
            assert set(clusters) == (({0x1d, 0x90, 0x91, 0x9c} | ({source_cluster} if source_cluster else set()) | ({3, 0xb06} if meter_services else set())) if ep == 1 else {0x1d, 0x90, 0x9c})
            assert integer(attrs[ep, 0x1d, 0xfffc]['body'], 'FeatureMap') == 1
            assert integer(attrs[ep, 0x9c, 0xfffc]['body'], 'FeatureMap') == 2
            assert integer(attrs[ep, 0x90, 0xfffc]['body'], 'FeatureMap') == (6 if ep == 1 else 2)
            assert integer(attrs[ep, 0x90, 1]['body'], 'NumberOfMeasurementTypes') == 4
            tag = attrs[ep, 0x1d, 4]['body']
            assert integer(tag, 'NamespaceID') == 0x0a
            assert integer(tag, 'Tag') == (1 if ep == 1 else ep - 1)
            if ep != 1:
                assert ids(attrs[ep, 0x1d, 3]['body'], 'PartsList') == []
            accuracy = attrs[ep, 0x90, 2]['body']
            types = [int(x) for x in re.findall(r'^MeasurementType: (\d+)\b', accuracy, re.M)]
            assert set(types) == ({5, 6, 7, 12} if ep == 1 else {1, 5, 6, 9})
        if meter_services:
            assert (0x38 in clusters) == (ep == 0)
        for cluster in clusters:
            keys = set(range(6)) | {0xfff8, 0xfff9, 0xfffb, 0xfffc, 0xfffd} if cluster == source_cluster else ids(attrs[ep, cluster, 0xfffb]['body'], 'AttributeList')
            expected.update((ep, cluster, attr) for attr in keys)
    assert set(attrs) == expected, (len(attrs), len(expected), expected - set(attrs))
    assert len(attrs) > 200
    return attrs


def values(text, updates=False):
    decoded = frames(text)

    def series(ep, cluster, attr, name, nullable=False):
        result = []
        for f in decoded:
            if f['kind'] == 'Attribute' and f['path'] == (ep, cluster, attr):
                if nullable and re.search(r'\bnull\b', f['body'], re.I):
                    result.append(None)
                else:
                    result.append(integer(f['body'], name))
        assert result, (ep, cluster, attr)
        return result

    p = series(1, 0x90, 8, 'ActivePower')
    assert all(1234000 <= x <= 1238000 for x in p)
    assert set(series(3, 0x90, 4, 'Voltage')) == {230125}
    assert set(series(4, 0x90, 8, 'ActivePower')) == {-750000}
    assert set(series(4, 0x90, 9, 'ReactivePower')) == {-100000}
    assert set(series(4, 0x90, 12, 'RMSCurrent')) == {-4000}
    assert set(series(1, 0x90, 17, 'PowerFactor')) == {9500}
    l3 = series(5, 0x90, 8, 'ActivePower', True)
    assert set(l3).issubset({184000, None})
    energy = [series(1, 0x91, attr, 'Energy') for attr in (1, 2)]
    assert energy[0][0] >= 12345678000 and energy[1][0] >= 123450000, 'zero baseline or lost registers'
    for readings in energy:
        assert readings == sorted(readings), 'unconfirmed register decrease'
    if updates:
        assert len(set(p)) >= 2 and set(l3) == {184000, None}, 'missing dynamic/availability reports'
        for readings in energy:
            assert len(set(readings)) >= 3, 'dormant EEM subscription'
        events = [f for f in decoded if f['kind'] == 'Event' and f['path'] == (1, 0x91, 0)]
        numbers = [integer(f['body'], 'Event number') for f in events]
        assert len(numbers) >= 3 and numbers == sorted(set(numbers))
        for attr, name in ((1, 'Imported'), (2, 'Exported')):
            samples = {integer(f['body'], 'EndSystime'): integer(f['body'], 'Energy') for f in decoded
                       if f['kind'] == 'Attribute' and f['path'] == (1, 0x91, attr)}
            matches = 0
            for event in events:
                value = re.search(r'Energy' + name + r': \{(.*?)\}', event['body'], re.S)
                assert value
                value = value[1].strip()
                stamp = integer(value, 'EndSystime')
                if stamp in samples:
                    assert samples[stamp] == integer(value, 'Energy')
                    matches += 1
            assert matches, 'no correlated attribute/event sample'
    return {'import_mWh': energy[0], 'export_mWh': energy[1], 'power_mW': p, 'L3_mW': l3}


def pair(args, out):
    """Against runtime-pair-host --three-phase: two complete runtimes, one thread."""
    clients = []
    checks = []

    def command(c, argv, pattern):
        ok, data = c.command(argv, pattern, 65)
        assert ok, argv
        return data

    def passed(name):
        checks.append(name)
        (out / 'pair-results.json').write_text(json.dumps(checks, indent=2) + '\n')
        print('PASS ' + name, flush=True)

    try:
        c = Client(Path(args.chip_tool).resolve(), Path(args.paa).resolve(), out, 'controller')
        clients.append(c)
        nodes = list(enumerate((args.discriminator, args.pair_discriminator), 1))
        if args.pair_reverse:
            nodes.reverse()
        for node, discriminator in nodes:
            if args.pair_legacy_discovery:
                # Diagnostic reproduction only: the pinned MinMDNS onnetwork-long
                # path can accept an unrelated unsolicited startup announcement.
                argv = ['pairing', 'onnetwork-long', node, 20202021, discriminator]
            else:
                data = command(c, ['payload', 'generate-qrcode', '--discriminator', discriminator,
                                   '--setup-pin-code', 20202021, '--rendezvous', 4], r'QR Code: MT:')
                payload = re.search(r'QR Code: (MT:[A-Z0-9.\-]+)', data)[1]
                # SetUpCodePairer checks the returned TXT discriminator as well
                # as browsing the subtype. Keep the upstream executable intact.
                argv = ['pairing', 'code', node, payload, '--use-only-onnetwork-discovery', 1]
            data = command(c, [*argv, '--country-code', 'PL', '--timeout', 60],
                           'Device commissioning completed with success')
            assert "Successfully finished commissioning step 'AttestationVerification'" in data
            if args.pair_legacy_discovery:
                ports = re.findall(r'Discovered Device: .*:(\d+)\b', data)
            else:
                assert f'Discovered device with discriminator {discriminator} matches' in data
                ports = re.findall(r'Attempting PASE connection to UDP:.*:(\d+)\b', data)
            assert ports and set(ports) == {str(5540 + node)}, ('wrong discovered instance port', ports)
            start = len(c.text())
            command(c, ['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', node, '0xffff,0xffff'],
                    'SuppressResponse = true')
            time.sleep(.4)
            data = c.text()[start:]
            inventory(data, True, 0xfff1fc01 if args.source_registers else None, args.meter_services)
            if args.source_registers:
                from chip_tool_meter_source import validate_source
                validate_source(data)
            if not args.source_registers:
                values(data)
            command(c, ['onoff', 'subscribe', 'on-off', 0, 2, node, 2, '--keepSubscriptions', 1], 'Subscription established')
        a = b = c
        passed('two-full-three-phase-instances-with-attestation-and-CASE-subscriptions')
        command(a, ['onoff', 'on', 1, 2], 'Received Command Response Status')
        command(a, ['onoff', 'read', 'on-off', 1, 2], r'OnOff: TRUE')
        command(b, ['onoff', 'read', 'on-off', 2, 2], r'OnOff: FALSE')
        passed('independent-application-state')
        if args.meter_services:
            command(a, ['identify', 'identify', 60, 1, 1], r'status = 0x00')
            command(b, ['identify', 'read', 'identify-time', 2, 1], r'IdentifyTime: 0\b')
            shifted = time.time_ns()//1000 - 946684800000000 + 30000000
            command(a, ['timesynchronization', 'set-utctime', shifted, 3, 1, 0], r'status = 0x00')
            data = command(b, ['timesynchronization', 'read', 'utctime', 2, 0], r'UTCTime: (\d+)')
            assert int(re.search(r'UTCTime: (\d+)', data)[1]) < shifted - 10000000
            command(a, ['identify', 'read', 'identify-time', 1, 1], r'IdentifyTime: [1-9][0-9]\b')
            passed('independent-Identify-and-UTC-anchors')
        # Decode through the existing TOO frame parser, not timestamps/prefixes.
        data = command(a, ['operationalcredentials', 'read', 'current-fabric-index', 1, 0], r'CurrentFabricIndex:')
        own = integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex')
        command(a, ['operationalcredentials', 'remove-fabric', own, 1, 0], r'statusCode: 0\b')
        time.sleep(3)
        start = len(b.text())
        command(b, ['onoff', 'on', 2, 2], 'Received Command Response Status')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not re.search(r'OnOff: TRUE', b.text()[start:]):
            time.sleep(.1)
        assert 'OnOff: TRUE' in b.text()[start:], 'B subscription lost during A teardown'
        command(b, ['electricalpowermeasurement', 'read', 'active-power', 2, 4], r'ActivePower: (?:-750000|null)' if args.source_registers else r'ActivePower: -750000')
        if args.source_registers:
            data = command(b, ['any', 'read-by-id', '0xfff1fc01', '0xffffffff', 2, 1], r'SuppressResponse = true')
            validate_source(data)
        if args.meter_services:
            command(b, ['identify', 'identify', 3, 2, 1], r'status = 0x00')
            command(b, ['identify', 'read', 'identify-time', 2, 1], r'IdentifyTime: [123]\b')
            command(b, ['timesynchronization', 'read', 'utctime', 2, 0], r'UTCTime: (\d+)')
            passed('B-meter-services-survive-active-A-Identify-teardown')
        passed('B-subscription-and-phase-read-survive-A-deletion')
        data = command(b, ['operationalcredentials', 'read', 'current-fabric-index', 2, 0], r'CurrentFabricIndex:')
        own = integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex')
        command(b, ['operationalcredentials', 'remove-fabric', own, 2, 0], r'statusCode: 0\b')
        passed('both-last-fabric-responses')
    finally:
        for c in clients:
            c.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chip-tool', required=True)
    parser.add_argument('--paa', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--discriminator', type=int, default=3847)
    parser.add_argument('--restart-storage')
    parser.add_argument('--pair-discriminator', type=int, help='Second runtime-pair-host discriminator; enables pair scenario')
    parser.add_argument('--pair-reverse', action='store_true', help='Commission B before A; keep logical node/port identities')
    parser.add_argument('--pair-legacy-discovery', action='store_true',
                        help='Diagnostic only: reproduce upstream onnetwork-long startup filtering failure')
    parser.add_argument('--source-registers', action='store_true', help='Pair fixture includes MP03 extension')
    parser.add_argument('--meter-services', action='store_true', help='Pair fixture includes MP04 services')
    args = parser.parse_args()
    if (args.pair_reverse or args.pair_legacy_discovery) and args.pair_discriminator is None:
        parser.error('--pair-reverse/--pair-legacy-discovery require --pair-discriminator')
    if args.meter_services and (not args.source_registers or args.pair_discriminator is None):
        parser.error('--meter-services requires --source-registers and --pair-discriminator')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    if args.pair_discriminator is not None:
        pair(args, out)
        return
    client = Client(Path(args.chip_tool).resolve(), Path(args.paa).resolve(), out, 'controller',
                    source=Path(args.restart_storage).resolve() if args.restart_storage else None)
    checks = []

    def check(name, ok):
        checks.append({'check': name, 'passed': bool(ok)})
        (out / 'results.json').write_text(json.dumps(checks, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        assert ok, name

    try:
        if not args.restart_storage:
            ok, text = client.command(['pairing', 'onnetwork-long', 1, 20202021, args.discriminator,
                                       '--country-code', 'PL', '--timeout', 60],
                                      r'Device commissioning completed with success', 65)
            check('commissioning-with-attestation', ok and "Successfully finished commissioning step 'AttestationVerification'" in text)
        paths = ['0xffffffff,0xffffffff', '0xffffffff', '0xffffffff']
        start = len(client.text())
        ok, _ = client.command(['any', 'read-all', *paths, 1, '0xffff,0xffff'], r'SuppressResponse = true', 45)
        time.sleep(.4)
        text = client.text()[start:]
        (out / 'read.log').write_text(text)
        check('chunked-wildcard-read', ok and 'MoreChunkedMessages = true' in text and 'CHIP Error' not in text)
        attrs = inventory(text)
        check('exact-inventory-topology-tags-accuracy', True)
        baseline = values(text)
        (out / 'baseline.json').write_text(json.dumps(baseline, indent=2) + '\n')
        check('registers-and-independent-phase-values', True)
        version = attrs[3, 0x1d, 4]['version']
        ok, data = client.command(['descriptor', 'subscribe', 'tag-list', 0, 3, 1, 3,
                                   '--data-version', version, '--keepSubscriptions', 0], r'Subscription established', 30)
        check('descriptor-data-version-filter', ok and not any(f['path'] == (3, 0x1d, 4) for f in frames(data)))
        client.command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        start = len(client.text())
        ok, _ = client.command(['any', 'subscribe-all', *paths, 0, 3, 1, '0xffff,0xffff', '--keepSubscriptions', 0],
                               r'Subscription established', 45)
        check('mixed-attribute-event-subscription', ok)
        time.sleep(.4)
        prime = client.text()[start:].split('Subscription established', 1)[0]
        check('complete-subscription-prime', set(inventory(prime)) == set(attrs))
        time.sleep(23)
        text = client.text()[start:]
        (out / 'subscribe.log').write_text(text)
        check('no-hidden-protocol-error', 'CHIP Error' not in text and 'Run command failure' not in text)
        measured = values(text, True)
        (out / 'measurements.json').write_text(json.dumps(measured, indent=2) + '\n')
        check('updates-L3-null-recovery-and-energy-events', True)
        client.command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        ok, data = client.command(['electricalenergymeasurement', 'read', 'cumulative-energy-imported', 1, 3],
                                  r'UNSUPPORTED_CLUSTER|UnsupportedCluster|0x0*0?c3\b', failure=True)
        check('no-fabricated-phase-energy', ok)
    finally:
        client.close()


if __name__ == '__main__':
    main()
