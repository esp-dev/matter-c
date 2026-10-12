"""M13i wildcard event acceptance using unmodified chip-tool on a disposable node.
Exercises all six valid selectors, mixed reports, empty prime, urgency and ACL
revocation. Not a CSA certification suite. Requires the M13g/M13h helper modules.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
from chip_tool_resources import Client
from chip_tool_multi_events import numbers, ordered


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--discriminator', type=int, default=3842)
    a = p.parse_args()
    tool, paa, out = Path(a.chip_tool).resolve(), Path(a.paa).resolve(), Path(a.output).resolve()
    if not tool.is_file() or not list(paa.glob('*.der')):
        p.error('chip-tool and development PAA required')
    out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'M13i event wildcard paths on CASE/x86; not certification',
              'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(), 'checks': []}
    c = Client(tool, paa, out, 'controller')

    def check(name, ok, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def command(args, pattern, failure=False):
        offset = len(c.text())
        ok, _ = c.command(args, pattern, timeout=50 if args[0] == 'pairing' else 20, failure=failure)
        # Include remaining decoded fields from the last report, not only its
        # first matching line. No concurrent commands/subscriptions during Read.
        time.sleep(.15)
        return ok, c.text()[offset:]

    def stop():
        c.command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        time.sleep(.15)

    def read(cluster, event, endpoint, extra=None):
        return command(['any', 'read-event-by-id', cluster, event, 1, endpoint] + (extra or []), r'SuppressResponse = true')

    try:
        ok, data = command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator,
                            '--country-code', 'PL', '--timeout', 45], r'Device commissioning completed with success')
        check('commission', ok and "Successfully finished commissioning step 'AttestationVerification'" in data,
              'verified development attestation, CASE and CommissioningComplete')
        forms = [
            ('all-node', '0xffffffff', '0xffffffff', '0xffff', ['StartUp:', 'BootReason:', 'AccessControlEntryChanged:', 'CumulativeEnergyMeasured:']),
            ('all-root', '0xffffffff', '0xffffffff', '0', ['StartUp:', 'BootReason:', 'AccessControlEntryChanged:']),
            ('cluster-all-endpoints', '0x28', '0xffffffff', '0xffff', ['StartUp:']),
            ('cluster-root', '0x28', '0xffffffff', '0', ['StartUp:']),
            ('event-all-endpoints', '0x28', '0', '0xffff', ['StartUp:']),
            ('concrete-control', '0x28', '0', '0', ['StartUp:']),
        ]
        root_history = []
        for name, cluster, event, ep, expected in forms:
            ok, data = read(cluster, event, ep)
            check('read-' + name, ok and ordered(data) and 'EventStatusIB =' not in data and
                  all(x in data for x in expected) and (name != 'all-root' or 'CumulativeEnergyMeasured:' not in data),
                  'Core 8.9.3.3 valid selector, concrete decoded paths and increasing event numbers')
            if name == 'all-root':
                root_history = numbers(data)
        ok, data = read('0xffffffff,0x28', '0xffffffff,0', '0,0')
        check('overlap-wildcard-concrete', ok and numbers(data) == root_history and data.count('StartUp:') == 1,
              'union across overlapping selectors, one record per event')
        ok, data = read('0xffffffff', '0xffffffff', '0', ['--event-min', root_history[1]])
        check('wildcard-event-min', ok and numbers(data) == root_history[1:], 'inclusive EventMin after expansion')
        ok, data = read('0xffffffff', '0xffffffff', '9')
        check('empty-wildcard-read', ok and not numbers(data) and 'EventStatusIB =' not in data, 'nonexistent wildcard endpoint returns an empty report')
        ok, data = command(['any', 'read-all', '0x28,0x90,0xffffffff', '5,8', '0xffffffff', 1, '0,1,0xffff'], r'SuppressResponse = true')
        check('mixed-read', ok and ordered(data) and 'ActivePower:' in data and 'NodeLabel:' in data and
              'CumulativeEnergyMeasured:' in data and data.count('AttributeDataIB =') == 2,
              'two concrete attributes followed by expanded wildcard events across chunks')
        ok, data = command(['any', 'read-event-by-id', '0xffffffff', '0', 1, 0], r'CHIP Error 0x000000B6: Malformed Interacton Model Event Path IB', True)
        check('invalid-selector-controller-gate', ok and 'Msg TX' not in data,
              'chip-tool rejects malformed selector before transmission; DUT INVALID_ACTION covered by C tests')
        ok, data = command(['any', 'subscribe-event-by-id', '0xffffffff', '0xffffffff', 1, 3, 1, 9,
                            '--keepSubscriptions', 0], r'(?:status|Status)\s*=\s*0x80', True)
        check('empty-wildcard-subscribe-rejected', ok and 'Subscription established' not in data,
              'no existent paths, cannot activate an event-only subscription')
        ok, data = command(['any', 'subscribe-event-by-id', '0xffffffff', '0xffffffff', 1, 3, 1, '0xffff',
                            '--event-min', '0xffffffffffffffff', '--is-urgent', 'true', '--keepSubscriptions', 0], r'Subscription established')
        check('empty-prime-activates-metadata', ok and not numbers(data), 'future EventMin suppresses prime history, model metadata still activates subscription')
        offset = len(c.text()); time.sleep(4); data = c.text()[offset:]
        check('wildcard-events-after-empty-prime', ordered(data) and data.count('CumulativeEnergyMeasured:') >= 2 and
              'Run command failure' not in data, 'new EEM events after a one-time EventMin and an empty prime')
        stop()
        ok, data = command(['any', 'subscribe-all', '0x90,0xffffffff', '8', '0xffffffff', 1, 3, 1, '1,0xffff',
                            '--keepSubscriptions', 0], r'Subscription established')
        check('mixed-wildcard-subscribe', ok and ordered(data) and all(x in data for x in
              ['ActivePower:', 'StartUp:', 'BootReason:', 'CumulativeEnergyMeasured:', 'AccessControlEntryChanged:']),
              'one attribute plus all event metadata, acknowledged chunked prime')
        watermark = numbers(data)[-1]
        acl = json.dumps([{'privilege': 5, 'authMode': 2, 'subjects': None, 'targets': None}])
        offset = len(c.text())
        ok, _ = command(['accesscontrol', 'write', 'acl', acl, 1, 0], r'ChangeType: 0')
        time.sleep(4); data = c.text()[offset:]
        check('mixed-wildcard-updates', ok and ordered(data) and min(numbers(data)) > watermark and
              'ActivePower:' in data and 'CumulativeEnergyMeasured:' in data and 'AdminNodeID:' in data,
              'new ACL/EEM and attribute updates, without replay of prime history')
        # Preserve our ability to restore ACL, and a changing EPM attribute.
        restricted = json.dumps([
            {'privilege': 5, 'authMode': 2, 'subjects': None, 'targets': [{'cluster': 0x1f, 'endpoint': 0, 'deviceType': None}]},
            {'privilege': 1, 'authMode': 2, 'subjects': None, 'targets': [{'cluster': 0x90, 'endpoint': 1, 'deviceType': None}]},
        ])
        ok, _ = command(['accesscontrol', 'write', 'acl', restricted, 1, 0], r'ChangeType: 0')
        offset = len(c.text()); time.sleep(4); data = c.text()[offset:]
        check('wildcard-revoke-keeps-survivors', ok and data.count('ActivePower:') >= 2 and
              'CumulativeEnergyMeasured:' not in data and 'EventStatusIB =' not in data and 'Run command failure' not in data,
              'revoked event paths disappear, surviving attribute/ACL paths remain on the same subscription')
        stop()
        ok, data = read('0xffffffff', '0xffffffff', '0xffff')
        check('wildcard-acl-omission', ok and ordered(data) and 'AccessControlEntryChanged:' in data and
              not any(x in data for x in ['CumulativeEnergyMeasured:', 'StartUp:', 'BootReason:', 'EventStatusIB =']),
              'new wildcard Read omits inaccessible events instead of returning statuses')
        ok, data = command(['electricalenergymeasurement', 'read-event', 'cumulative-energy-measured', 1, 1],
                           r'(?:status|Status)\s*=\s*0x7e', True)
        check('concrete-acl-status', ok and 'EventStatusIB =' in data and 'CumulativeEnergyMeasured:' not in data,
              'explicit denied path still returns UNSUPPORTED_ACCESS')
        ok, _ = command(['accesscontrol', 'write', 'acl', acl, 1, 0], r'status = 0x00')
        check('restore-test-acl', ok, 'restore disposable controller access before final confirmation')
        ok, data = read('0xffffffff', '0xffffffff', '0xffff')
        check('new-read-after-grant', ok and ordered(data) and all(x in data for x in
              ['StartUp:', 'BootReason:', 'CumulativeEnergyMeasured:']), 'fresh wildcard request observes restored grants')
        return 0
    finally:
        c.close()


if __name__ == '__main__':
    raise SystemExit(main())
