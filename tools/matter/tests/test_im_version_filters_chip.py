"""CHIP regression for large DataVersionFilters and fresh-CASE resubscription.

Uses a disposable full-profile x86 host; never a production controller store.
Run once with --memcheck, then separately with an ASan/UBSan/LSan host binary.
This is an interoperability regression, not a CSA test or certification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from chip_tool_resources import Client
from chip_tool_energy_profile import frames, integer
from chip_tool_three_phase import inventory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'interface', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--memcheck', action='store_true')
    a = p.parse_args()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe, tool, paa = Path(a.exe).resolve(), Path(a.chip_tool).resolve(), Path(a.paa).resolve()
    report = {'scope': 'full host regression, not CSA certification', 'checks': [],
              'host_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest()}

    def check(name, condition):
        report['checks'].append({'name': name, 'passed': bool(condition)})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if condition else 'FAIL ') + name, flush=True)
        if not condition:
            raise RuntimeError(name)

    def command(c, argv, pattern, timeout=45):
        ok, data = c.command(argv, pattern, timeout)
        check('command-' + '-'.join(map(str, argv[:2])), ok)
        return data

    argv = [str(exe), '--interface', a.interface, '--seconds', '240', '--port', '5543',
            '--credentials', str(Path(a.credentials).resolve()), '--state', str(out / 'node.bin'),
            '--pin', '20202021', '--discriminator', '3846', '--three-phase',
            '--source-registers', '--meter-services', '--test-switch']
    if a.memcheck:
        argv = ['valgrind', '--error-exitcode=99', '--leak-check=full', '--show-leak-kinds=all',
                '--errors-for-leak-kinds=all', '--log-file=' + str(out / 'memcheck.log'), *argv]
    (out / 'host-command.json').write_text(json.dumps(argv, indent=2) + '\n')
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    client = None
    with (out / 'host.stdout.log').open('w') as log, (out / 'host.stderr.log').open('w') as err:
        host = subprocess.Popen(argv, stdout=log, stderr=err, env=env)
        try:
            end = time.monotonic() + 30
            while time.monotonic() < end and host.poll() is None:
                if 'PUBLISHED' in (out / 'host.stdout.log').read_text():
                    break
                time.sleep(.1)
            check('host-published', host.poll() is None and 'PUBLISHED' in (out / 'host.stdout.log').read_text())
            client = Client(tool, paa, out, 'initial', advertise=False)
            data = command(client, ['payload', 'generate-qrcode', '--discriminator', 3846,
                                   '--setup-pin-code', 20202021, '--rendezvous', 4], r'QR Code: MT:')
            code = re.search(r'QR Code: (MT:[A-Z0-9.\-]+)', data)[1]
            data = command(client, ['pairing', 'code', 1, code, '--use-only-onnetwork-discovery', 1,
                                   '--country-code', 'PL', '--timeout', 60],
                           'Device commissioning completed with success', 70)
            check('attestation-verified', "Successfully finished commissioning step 'AttestationVerification'" in data)
            storage = client.storage
            for attempt in range(2):
                if attempt:
                    client.close()
                    client = Client(tool, paa, out, 'fresh-controller', source=storage, advertise=False)
                start = len(client.text())
                data = command(client, ['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff',
                                       '0xffffffff', 1, '0xffff,0xffff'], 'SuppressResponse = true')
                time.sleep(.3)
                data = client.text()[start:]
                attrs = inventory(data, True, 0xfff1fc01, True, metered_switch=True)
                check('complete-inventory-' + str(attempt), len(attrs) > 256)
                if attempt:
                    check('fresh-CASE-and-discovery', 'Sent Sigma3 msg' in data and 'Session was established' in data)
                versions = {}
                for (ep, cluster, _), frame in attrs.items():
                    version = frame['version']
                    if version is None:
                        raise ValueError('Missing cluster DataVersion')
                    # Chunked Read does not promise an atomic cluster snapshot;
                    # diagnostics can change while later attributes are read.
                    versions[ep, cluster] = version
                # Concrete selectors give unmodified chip-tool explicit filter
                # paths. Include the switch and stable Descriptor instances.
                pairs = [(2, 6), *sorted(pair for pair in versions if pair != (2, 6))[:16]]
                check('seventeen-cluster-filters-' + str(attempt), len(set(pairs)) == 17)
                data = command(client, ['any', 'subscribe-by-id', ','.join(hex(c) for _, c in pairs),
                                       ','.join('0xffffffff' for _ in pairs), 0, 3, 1, ','.join(str(ep) for ep, _ in pairs),
                                       '--data-version', ','.join(str(versions[pair]) for pair in pairs),
                                       '--keepSubscriptions', 0], 'Subscription established')
                prime = frames(data.split('Subscription established', 1)[0])
                check('unchanged-priming-suppressed-' + str(attempt),
                      not any(f['kind'] == 'Attribute' and (f['path'][:2] == (2, 6) or f['path'][1] == 0x1d)
                              for f in prime))
                start = len(client.text())
                command(client, ['onoff', 'on' if not attempt else 'off', 1, 2], 'Received Command Response Status')
                value = 'TRUE' if not attempt else 'FALSE'
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    updates = [f for f in frames(client.text()[start:]) if f['kind'] == 'Attribute' and f['path'] == (2, 6, 0)]
                    if any('OnOff: ' + value in f['body'] for f in updates):
                        break
                    time.sleep(.1)
                check('filtered-switch-still-reports-' + str(attempt), any('OnOff: ' + value in f['body'] for f in updates))
                command(client, ['subscriptions', 'shutdown-all'], 'Command: subscriptions shutdown-all')
            data = command(client, ['operationalcredentials', 'read', 'current-fabric-index', 1, 0], 'CurrentFabricIndex:')
            index = integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex')
            command(client, ['operationalcredentials', 'remove-fabric', index, 1, 0], r'statusCode: 0\b')
        finally:
            if client:
                client.close()
            if host.poll() is None:
                host.send_signal(signal.SIGTERM)
            try:
                host.wait(timeout=30)
            except subprocess.TimeoutExpired:
                host.kill()
                host.wait()
                raise RuntimeError('Host required forced termination')
        check('host-clean-exit', host.returncode == 0 and not (out / 'host.stderr.log').read_text())
        if a.memcheck:
            data = (out / 'memcheck.log').read_text()
            check('memcheck-clean', 'ERROR SUMMARY: 0 errors' in data and 'All heap blocks were freed -- no leaks are possible' in data)


if __name__ == '__main__':
    main()
