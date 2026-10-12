"""M13g resource acceptance on a disposable x86 node; not CSA certification.

Two independent commissioned fabrics, three live CASE processes per fabric.
Controller credential copies are isolated temporary stores, never production
credentials. Requires the same unmodified chip-tool/PAA as chip_tool_acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class Client:
    def __init__(self, tool, paa, root, name, source=None, advertise=True):
        self.directory = root / name
        self.directory.mkdir()
        self.storage = self.directory / 'storage'
        if source:
            shutil.copytree(source, self.storage)
        else:
            self.storage.mkdir()
        self.path = self.directory / 'interactive.log'
        self.log = self.path.open('w')
        self.commands = []
        self.child = subprocess.Popen(
            [str(tool), 'interactive', 'start', '--storage-directory', str(self.storage),
             '--paa-trust-store-path', str(paa), *([] if advertise else ['--advertise-operational', '0'])], stdin=subprocess.PIPE, stdout=self.log,
            stderr=subprocess.STDOUT, text=True, env=dict(os.environ, TMPDIR=str(self.directory)))

    def text(self):
        return ANSI.sub('', self.path.read_text(errors='replace'))

    def command(self, args, pattern, timeout=20, failure=False):
        offset = len(self.text())
        line = shlex.join([str(x) for x in args])
        self.commands.append(line)
        (self.directory / 'commands.txt').write_text('\n'.join(self.commands) + '\n')
        self.child.stdin.write(line + '\n')
        self.child.stdin.flush()
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            data = self.text()[offset:]
            if re.search(pattern, data):
                return (failure or 'Run command failure' not in data), data
            if self.child.poll() is not None or 'Run command failure' in data:
                return False, data
            time.sleep(.05)
        return False, self.text()[offset:]

    def close(self):
        if self.child.poll() is None:
            try:
                self.child.stdin.write('quit()\n')
                self.child.stdin.flush()
                self.child.wait(timeout=10)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.child.kill()
                self.child.wait()
        self.child.stdin.close()
        self.log.close()


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
    report = {'scope': 'M13g x86 resources, two fabrics, six concurrent CASE sessions; not certification',
              'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(), 'checks': []}
    clients = []

    def client(name, source=None):
        c = Client(tool, paa, out, name, source)
        clients.append(c)
        return c

    def check(name, passed, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed:
            raise RuntimeError(name)

    def subscribe(c, keep, expected=r'Subscription established', failure=False):
        return c.command(['electricalpowermeasurement', 'subscribe', 'active-power', 1, 3, 1, 1,
                          '--keepSubscriptions', int(keep)], expected, failure=failure)

    try:
        alpha = client('alpha-0')
        ok, data = alpha.command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator,
                                  '--country-code', 'PL', '--timeout', 45],
                                 r'Device commissioning completed with success', timeout=50)
        check('commission-alpha', ok and "Successfully finished commissioning step 'AttestationVerification'" in data,
              'fresh fabric with verified development attestation')
        ok, data = alpha.command(['basicinformation', 'read', 'capability-minima', 1, 0], r'SubscribePathsSupported: 3\b')
        check('capability-minima', ok and all(re.search(k + ': ' + str(v) + r'\b', data) for k, v in
              [('CaseSessionsPerFabric', 3), ('SubscriptionsPerFabric', 3), ('SimultaneousInvocationsSupported', 1),
               ('SimultaneousWritesSupported', 1), ('ReadPathsSupported', 9)]), 'decoded six fields; path-shape conformance remains separate')
        aa = [alpha, client('alpha-1', alpha.storage), client('alpha-2', alpha.storage)]
        for i, c in enumerate(aa):
            ok, data = subscribe(c, True)
            check(f'alpha-session-sub-{i}', ok and 'ActivePower:' in data and
                  (not i or 'Sent Sigma3 msg' in data), 'live CASE session and decoded subscription on separate process')
        ok, _ = subscribe(alpha, True, r'(?:status|Status)\s*=\s*0x89', True)
        check('alpha-fourth-sub-rejected', ok, 'explicit IM RESOURCE_EXHAUSTED, existing subscriptions retained')
        ok, data = alpha.command(['electricalpowermeasurement', 'read', 'active-power', 1, 1], r'ActivePower:')
        check('alpha-read-at-sub-limit', ok, 'Read remains available with all three subscription slots occupied')
        # Enhanced window is a timed Invoke, so this also exercises Invoke while
        # the same fabric has all of its CASE/subscription guarantees occupied.
        ok, data = alpha.command(['pairing', 'open-commissioning-window', 1, 1, 180, 1000, 3850],
                                 r'Manual pairing code: \[\d+\]')
        code = re.search(r'Manual pairing code: \[(\d+)\]', data)
        check('window-at-session-limit', ok and bool(code), 'timed Invoke while three CASE sessions remain protected')
        beta = client('beta-0')
        ok, data = beta.command(['pairing', 'code', 1, code.group(1), '--country-code', 'PL', '--timeout', 45],
                                r'Device commissioning completed with success', timeout=50)
        check('commission-beta-at-alpha-limit', ok and "Successfully finished commissioning step 'AttestationVerification'" in data,
              'new independent root/fabric despite first fabric occupying its full quota')
        bb = [beta, client('beta-1', beta.storage), client('beta-2', beta.storage)]
        for i, c in enumerate(bb):
            ok, data = subscribe(c, True)
            check(f'beta-session-sub-{i}', ok and 'ActivePower:' in data and
                  (not i or 'Sent Sigma3 msg' in data), 'second fabric independently reaches three protected CASE sessions/subscriptions')
        offsets = [len(c.text()) for c in aa + bb]
        time.sleep(7)
        for i, c in enumerate(aa + bb):
            data = c.text()[offsets[i]:]
            check(f'concurrent-reports-{i}', len(re.findall(r'ActivePower: (?:3600000|-1800000)\b', data)) >= 2,
                  'decoded periodic reports on all six simultaneous sessions over seven seconds')
        # No session is idle in alpha, so a fourth authenticated CASE must get
        # SC BUSY. This is different from the IM subscription quota above.
        extra = client('alpha-extra', alpha.storage)
        ok, data = extra.command(['electricalpowermeasurement', 'read', 'active-power', 1, 1, '--timeout', 8],
                                 r'Received error \(protocol code 4\) during pairing process', timeout=12, failure=True)
        check('fourth-protected-case-busy', ok and 'Received busy status report with minimum wait time: 500 ms' in data,
              'explicit Secure Channel BUSY after Sigma3, no session from another fabric evicted')
        extra.close()
        clients.remove(extra)
        ok, _ = subscribe(alpha, False)
        check('replace-across-case-sessions', ok, 'KeepSubscriptions=false replaces own-node subscriptions across its three sessions')
        renewed = client('alpha-renewed', alpha.storage)
        ok, data = subscribe(renewed, True)
        check('case-reclaimed-after-replace', ok and 'Sent Sigma3 msg' in data, 'idle same-fabric CASE slot reused after CloseSession/drain')
        ok, _ = beta.command(['electricalpowermeasurement', 'read', 'active-power', 1, 1], r'ActivePower:')
        check('beta-survives-alpha-reclaim', ok, 'other fabric still reads over its existing CASE session')
        ok, _ = beta.command(['basicinformation', 'write', 'node-label', 'M13g resources', 1, 0], r'status = 0x00')
        check('write-at-session-limit', ok, 'Write available while six subscriptions/sessions have been exercised')
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
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
