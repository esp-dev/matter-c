"""M13j: CASE/EEM/events across separate DUT processes on a disposable x86 node.

Run first with --commission, then --previous pointing at the preceding output.
The owner restarts/kills the DUT between runs. --remove-fabric resets commissioned
data; next run uses --previous plus --commission to verify retained node counters.
No attestation bypass; simulation data, not a metrology or CSA certification test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from chip_tool_resources import Client
from chip_tool_multi_events import numbers, ordered


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--previous')
    p.add_argument('--commission', action='store_true')
    p.add_argument('--remove-fabric', action='store_true')
    p.add_argument('--discriminator', type=int, default=3842)
    a = p.parse_args()
    tool, paa, out = Path(a.chip_tool).resolve(), Path(a.paa).resolve(), Path(a.output).resolve()
    previous = Path(a.previous).resolve() if a.previous else None
    if not tool.is_file() or not list(paa.glob('*.der')) or (not previous and not a.commission):
        p.error('chip-tool, development PAA and --commission or --previous required')
    old = json.loads((previous / 'result.json').read_text()) if previous else None
    out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'M13j CASE metering restart; not certification',
              'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(), 'checks': []}
    c = Client(tool, paa, out, 'controller', previous / 'controller' / 'storage' if previous and not a.commission else None)

    def check(name, ok, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def command(args, pattern):
        offset = len(c.text())
        ok, _ = c.command(args, pattern, timeout=50 if args[0] == 'pairing' else 20)
        time.sleep(.2)
        return ok, c.text()[offset:]

    def energies(label):
        values = []
        for direction in ('imported', 'exported'):
            ok, data = command(['electricalenergymeasurement', 'read', 'cumulative-energy-' + direction, 1, 1], r'Energy: \d+\b')
            found = re.search(r'Energy: (\d+)\b', data)
            check(label + '-' + direction, ok and found is not None, 'decoded EEM structure over CASE')
            values.append(int(found[1]))
        return values

    try:
        if a.commission:
            ok, data = command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL', '--timeout', 45],
                               r'Device commissioning completed with success')
            check('commission', ok and "Successfully finished commissioning step 'AttestationVerification'" in data,
                  'verified development attestation and CommissioningComplete')
        first = energies('read')
        check('fresh-case', 'Sent Sigma3 msg' in c.text() and 'Session was established' in c.text(),
              'new controller process, operational discovery and CASE')
        if old:
            check('energy-survives-restart', all(n >= o for n, o in zip(first, old['energy'])),
                  {'previous': old['energy'], 'current': first})
        ok, data = command(['any', 'read-event-by-id', '0xffffffff', '0xffffffff', 1, '0xffff'], r'SuppressResponse = true')
        seen = numbers(data)
        report['event_numbers'] = seen
        check('events-ordered', ok and ordered(data) and 'CumulativeEnergyMeasured:' in data and 'EventStatusIB =' not in data,
              'RAM history recreated; retained events strictly ordered')
        if old:
            check('event-numbers-never-reused', bool(seen) and min(seen) > max(old['event_numbers']),
                  {'previous_max': max(old['event_numbers']), 'current_min': min(seen) if seen else None})
        time.sleep(2.2)
        report['energy'] = energies('later')
        check('both-directions-continue', all(n > o for n, o in zip(report['energy'], first)),
              {'first': first, 'later': report['energy']})
        if a.remove_fabric:
            # Core1.6.1 11.18.6.12 outcome1: no response is expected after
            # removal of the last fabric/session. Timeout alone is not proof of
            # reset: the owner checks RESET/exit, then the next run commissions.
            ok, data = c.command(['operationalcredentials', 'remove-fabric', 1, 1, 0],
                                 r'CHIP Error 0x00000032: Timeout', timeout=20, failure=True)
            check('self-removal-sent', ok and 'IM:InvokeCommandRequest' in data and 'Msg TX' in data,
                  'no response on erased session; reset requires host RESET/exit and subsequent fresh commissioning')
        return 0
    finally:
        c.close()


if __name__ == '__main__':
    raise SystemExit(main())
