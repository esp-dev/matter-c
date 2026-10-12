"""M13h: multiple and mixed event/attribute paths on a disposable x86 node.
Uses an unmodified chip-tool; not a CSA certification suite. See result.json
and the exact commands/decoded interactive log in the fresh output directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from chip_tool_resources import Client


def numbers(data):
    return [int(n) for n in re.findall(r"Event number: (\d+)", data)]


def ordered(data):
    values = numbers(data)
    return bool(values) and values == sorted(set(values))


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
    report = {'scope': 'M13h multiple/mixed paths on CASE/x86; not certification',
              'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(), 'checks': []}
    c = Client(tool, paa, out, 'controller')

    def check(name, ok, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def command(args, pattern):
        offset = len(c.text())
        ok, _ = c.command(args, pattern, timeout=50 if args[0] == 'pairing' else 20)
        # Include remaining decoded fields from the last report, not only its
        # first matching line. No concurrent commands/subscriptions during Read.
        time.sleep(.15)
        return ok, c.text()[offset:]

    def stop():
        c.command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        time.sleep(.15)

    try:
        ok, data = command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator,
                            '--country-code', 'PL', '--timeout', 45], r'Device commissioning completed with success')
        check('commission', ok and "Successfully finished commissioning step 'AttestationVerification'" in data,
              'fresh fabric, development attestation, CASE and CommissioningComplete')
        # Select reverse history order; decoded results must still be global EventNumber order.
        clusters, events = '0x1f,0x33,0x28', '0,3,0'
        ok, data = command(['any', 'read-event-by-id', clusters, events, 1, '0,0,0'], r'AdminPasscodeID: 0')
        check('read-three-events', ok and ordered(data) and len(numbers(data)) == 3 and
              all(x in data for x in ['StartUp:', 'BootReason:', 'AccessControlEntryChanged:']), 'three concrete paths, sorted across clusters')
        history = numbers(data)
        ok, data = command(['any', 'read-event-by-id', ','.join([clusters]*3), ','.join([events]*3), 1, ','.join(['0']*9)], r'AdminPasscodeID: 0')
        check('read-nine-events-deduplicated', ok and numbers(data) == history,
              'nine raw selectors with overlaps, exactly one record per event')
        ok, data = command(['any', 'read-event-by-id', clusters, events, 1, '0,0,0', '--event-min', history[1]], r'AdminPasscodeID: 0')
        check('read-event-min', ok and numbers(data) == history[1:], 'inclusive EventMin applies to all selected paths')
        # Attribute endpoints/clusters precede the event endpoints/clusters in read-all.
        ok, data = command(['any', 'read-all', ','.join(['0x28']*6+[clusters]), '0,1,2,3,4,9', events, 1, ','.join(['0']*9)], r'AdminPasscodeID: 0')
        check('read-nine-mixed', ok and numbers(data) == history and data.count('AttributeDataIB =') == 6 and
              'MoreChunkedMessages = true' in data, 'six decoded attributes then three events across acknowledged report chunks')
        ok, data = command(['any', 'read-all', '0x28,0x33,0x28', '9,0xfffd', '0', 1, '0,0,0'], r'StartUp:')
        check('read-three-mixed', ok and data.count('AttributeDataIB =') == 2 and numbers(data) == history[:1], 'two attributes and one event')
        ok, data = command(['any', 'subscribe-event-by-id', '0x91,0x28,0x1f', '0,0,0', 1, 3, 1, '1,0,0',
                            '--keepSubscriptions', 0, '--is-urgent', 'true,true,true'], r'Subscription established')
        check('subscribe-three-events', ok and ordered(data) and all(x in data for x in
              ['CumulativeEnergyMeasured:', 'StartUp:', 'AccessControlEntryChanged:']), 'prime event union and established subscription')
        before = numbers(data)[-1]
        offset = len(c.text())
        acl = json.dumps([{'privilege': 5, 'authMode': 2, 'subjects': None, 'targets': None}])
        ok, _ = command(['accesscontrol', 'write', 'acl', acl, 1, 0], r'ChangeType: 0')
        time.sleep(4)
        data = c.text()[offset:]
        check('subscribe-event-updates', ok and ordered(data) and min(numbers(data)) > before and
              'CumulativeEnergyMeasured:' in data and 'AdminNodeID:' in data and 'Run command failure' not in data,
              'new ACL and EEM events, monotonic watermark without repeating priming history')
        stop()
        ok, data = command(['any', 'subscribe-all', '0x90,0x28,0x33', '8', '0,3', 1, 3, 1, '1,0,0', '--keepSubscriptions', 0], r'Subscription established')
        check('subscribe-three-mixed', ok and ordered(data) and all(x in data for x in ['ActivePower:', 'StartUp:', 'BootReason:']),
              'one attribute plus two events, mixed acknowledged prime')
        offset = len(c.text()); time.sleep(4); data = c.text()[offset:]
        check('mixed-attribute-updates', len(re.findall(r'ActivePower: (?:3600000|-1800000)\b', data)) >= 2 and not numbers(data) and
              'Run command failure' not in data, 'attribute changes continue without replaying event history')
        stop()
        ok, data = command(['any', 'subscribe-all', '0x90,0x91,0x28,0x33,0x91,0x1f', '8,1', '0,3,0,0', 1, 3, 1, '1,1,0,0,1,0', '--keepSubscriptions', 0], r'Subscription established')
        check('subscribe-six-mixed', ok and ordered(data) and all(x in data for x in
              ['ActivePower:', 'CumulativeEnergyImported:', 'CumulativeEnergyMeasured:', 'StartUp:', 'BootReason:', 'AccessControlEntryChanged:']),
              'two attributes and four distinct event paths, including structured EEM data')
        before = numbers(data)[-1]; offset = len(c.text()); time.sleep(4); data = c.text()[offset:]
        check('mixed-attribute-event-updates', ordered(data) and min(numbers(data)) > before and
              'ActivePower:' in data and 'CumulativeEnergyMeasured:' in data and 'Run command failure' not in data,
              'same subscription delivers subsequent attributes and events across chunks')
        stop()
        ok, data = command(['basicinformation', 'read', 'capability-minima', 1, 0], r'SubscribePathsSupported: 3')
        check('capability-minima', ok and 'ReadPathsSupported: 9' in data, 'advertised 9/3 budgets retain their values')
        return 0
    finally:
        c.close()


if __name__ == '__main__':
    raise SystemExit(main())
