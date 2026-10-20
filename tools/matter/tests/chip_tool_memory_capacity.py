"""Live five-fabric capacity workload for heap/stack profiling, not certification.

Run against one disposable three-phase host. Controller credentials/state stay
in the caller's output directory; result.json contains no provisioning secrets.
Uses the existing independent chip-tool client, with no DUT-private API.
"""
import argparse
import json
from pathlib import Path
import re
import time

from chip_tool_resources import Client
from chip_tool_energy_profile import frames
from test_im_event_fabric_chip import reports


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--discriminator', type=int, default=3860)
    p.add_argument('--max-interval', type=int, default=3,
                   help='Use 30 with slow instruction-level stack profiling; normal capacity regression uses 3')
    a = p.parse_args()
    if not 1 <= a.max_interval <= 180:
        p.error('--max-interval must be 1..180 seconds')
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    clients, primaries, subscriptions, report = [], [], {}, {'scope': 'One host, five fabrics, fifteen CASE sessions and three-path subscriptions; observed workload, not a worst-case RAM bound or certification', 'checks': []}
    report['maximum_interval_seconds'] = a.max_interval

    def check(name, ok):
        report['checks'].append({'name': name, 'passed': bool(ok)})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def client(name, source=None):
        c = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, name, source)
        clients.append(c)
        return c

    try:
        for fabric in range(5):
            primary = client(f'fabric-{fabric}-0')
            if not fabric:
                args = ['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL', '--timeout', 60]
            else:
                ok, text = primaries[0].command(['pairing', 'open-commissioning-window', 1, 1, 180, 1000, a.discriminator + fabric], r'Manual pairing code: \[\d+\]', 45)
                code = re.search(r'Manual pairing code: \[(\d+)\]', text)
                check(f'window-{fabric}', ok and bool(code))
                args = ['pairing', 'code', 1, code.group(1), '--country-code', 'PL', '--timeout', 60]
            ok, text = primary.command(args, r'Device commissioning completed with success', 70)
            check(f'commission-{fabric}', ok and "Successfully finished commissioning step 'AttestationVerification'" in text)
            primaries.append(primary)
            members = [primary] + [client(f'fabric-{fabric}-{i}', primary.storage) for i in (1, 2)]
            for index, c in enumerate(members):
                ok, text = c.command(['any', 'subscribe-by-id', '0x28', '2,4,5', 1, a.max_interval, 1, 0, '--keepSubscriptions', 1], r'Subscription established[^\n]*SubscriptionID = 0x[0-9a-fA-F]+', 40)
                paths = {f['path'] for f in frames(text) if f['kind'] == 'Attribute'}
                check(f'session-three-path-subscription-{fabric}-{index}', ok and {(0, 0x28, x) for x in (2, 4, 5)} <= paths)
                subscriptions[c] = int(re.search(r'Subscription established[^\n]*SubscriptionID = (0x[0-9a-fA-F]+)', text)[1], 16)
            ok, text = primary.command(['any', 'read-by-id', '0x28', '0,1,2,3,4,5,6,7,8', 1, 0], r'SuppressResponse = true', 40)
            paths = {f['path'] for f in frames(text) if f['kind'] == 'Attribute'}
            check(f'nine-path-read-at-subscription-limit-{fabric}', ok and {(0, 0x28, x) for x in range(9)} <= paths)
        offsets = [len(c.text()) for c in clients]
        def heartbeats(index, c):
            # Unchanged data can legally be omitted. Check complete reports
            # for the decoded ID and their IM response, using the existing oracle.
            return sum(x['id'] == subscriptions[c] and 'SuppressResponse = false' in x['text'] and
                       'IM:StatusResponse' in x['text'] for x in reports(c.text()[offsets[index]:]))
        until = time.monotonic() + 2 * a.max_interval + 20
        while time.monotonic() < until and not all(heartbeats(i, c) >= 2 for i, c in enumerate(clients)):
            time.sleep(.5)
        for index, c in enumerate(clients):
            check(f'concurrent-heartbeats-{index}', heartbeats(index, c) >= 2)
        extra = client('fourth-protected-case', primaries[0].storage)
        ok, text = extra.command(['basicinformation', 'read', 'vendor-id', 1, 0, '--timeout', 8], r'Received error \(protocol code 4\) during pairing process', 15, failure=True)
        check('fourth-case-busy-with-all-fabrics-live', ok and 'Received busy status report' in text)
        for fabric, c in enumerate(primaries):
            ok, _ = c.command(['basicinformation', 'write', 'node-label', 'memory-capacity', 1, 0], r'status = 0x00', 30)
            check(f'write-with-fifteen-live-subscriptions-{fabric}', ok)
    except (RuntimeError, OSError, AssertionError) as e:
        report['error'] = str(e)
        return 1
    finally:
        for c in reversed(clients):
            c.close()
        report['process_exits'] = {c.directory.name: c.child.returncode for c in clients}
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if all(c.child.returncode == 0 for c in clients) else 1


if __name__ == '__main__':
    raise SystemExit(main())
