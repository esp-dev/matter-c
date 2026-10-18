"""Identify command/write/countdown observation on a disposable x86 node.

Unmodified chip-tool, live presentation callback and real 10/15-second waits.
IdentifyType0 has no physical indication. This is not official CSA acceptance.
Run Memcheck and sanitizers separately; credentials and state stay outside Git.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from chip_tool_resources import Client


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--valgrind', action='store_true')
    a = p.parse_args()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {'scope': 'Identify x86 callbacks/CASE/countdown, no physical indication or CSA certification',
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(Path(a.exe).read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(Path(a.chip_tool).read_bytes()).hexdigest(),
              'valgrind': a.valgrind, 'checks': []}
    node = client = None
    logs = []
    phase = 0

    def check(name, passed, detail=None):
        result['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed:
            raise AssertionError(name + ': ' + str(detail))

    def launch():
        nonlocal node, phase
        phase += 1
        argv = [a.exe, '--interface', str(a.interface), '--port', '5581', '--seconds', '240',
                '--discriminator', '3916', '--credentials', a.credentials, '--state', str(out / 'state.tlv'),
                '--three-phase', '--source-registers', '--meter-services']
        if a.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=definite,indirect,possible', '--track-origins=yes',
                    '--error-exitcode=99', '--log-file=' + str(out / f'valgrind-{phase}.log'), *argv]
        handles = [(out / f'node-{phase}.{ext}').open('w') for ext in ('log', 'err')]
        logs.extend(handles)
        node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1], env=dict(os.environ,
                                ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',
                                UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if node.poll() is not None:
                raise AssertionError('Node startup failed')
            if 'PUBLISHED' in (out / f'node-{phase}.log').read_text():
                return
            time.sleep(.05)
        raise AssertionError('Node publication timeout')

    def command(args, pattern='SuppressResponse = true'):
        ok, text = client.command(args, pattern, timeout=45)
        if not ok:
            raise AssertionError(str(args) + ': ' + text[-800:])
        return text

    def value(attribute, label):
        text = command(['identify', 'read', attribute, 1, 1])
        match = re.search(r'\b' + label + r': (\d+)\b', text)
        if not match:
            raise AssertionError('Missing ' + label)
        return int(match[1])

    def callbacks():
        text = (out / f'node-{phase}.log').read_text()
        return [int(n) for n in re.findall(r'^IDENTIFY seconds=(\d+) presentation=simulation$', text, re.M)]

    def stop():
        node.terminate()
        check(f'clean-stop-{phase}', node.wait(timeout=40) == 0)

    try:
        launch()
        client = Client(Path(a.chip_tool), Path(a.paa), out, 'controller')
        text = command(['pairing', 'onnetwork-long', 1, 20202021, 3916, '--country-code', 'PL', '--timeout', 60],
                       'Device commissioning completed with success')
        check('attested-commissioning', "Successfully finished commissioning step 'AttestationVerification'" in text)
        check('identify-type-none', value('identify-type', 'IdentifyType') == 0)
        check('initial-time-zero', value('identify-time', 'IdentifyTime') == 0)
        command(['identify', 'subscribe', 'identify-time', 0, 30, 1, 1], 'Subscription established')
        command(['identify', 'identify', 60, 1, 1], r'Received Command Response Status for Endpoint=1 Cluster=0x0000_0003 Command=0x0000_0000 Status=0x0\b')
        check('command60-callback', callbacks() == [60], callbacks())
        initial = value('identify-time', 'IdentifyTime')
        check('immediate-time-51-to-60', 51 <= initial <= 60, initial)
        started = time.monotonic()
        time.sleep(10)
        later = value('identify-time', 'IdentifyTime')
        check('real10s-countdown-42-to-58', 42 <= later <= 58 and later < initial,
              {'seconds': time.monotonic() - started, 'value': later})
        command(['identify', 'identify', 0, 1, 1], r'Received Command Response Status for Endpoint=1 Cluster=0x0000_0003 Command=0x0000_0000 Status=0x0\b')
        check('command0-callback-and-time', callbacks() == [60, 0] and value('identify-time', 'IdentifyTime') == 0, callbacks())
        offset = len(client.text())
        started = time.monotonic()
        command(['identify', 'write', 'identify-time', 15, 1, 1], r'status = 0x00')
        check('write15-callback', callbacks() == [60, 0, 15], callbacks())
        deadline = started + 20
        while time.monotonic() < deadline and callbacks() != [60, 0, 15, 0]:
            time.sleep(.05)
        elapsed = time.monotonic() - started
        check('natural-expiry-at15s', callbacks() == [60, 0, 15, 0] and 14.9 <= elapsed < 20,
              {'seconds': elapsed, 'callbacks': callbacks()})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            reports = [int(n) for n in re.findall(r'IdentifyTime: (\d+)', client.text()[offset:])]
            if 15 in reports and 0 in reports[reports.index(15) + 1:]:
                break
            time.sleep(.05)
        check('quiet-countdown-subscription-reports15-and0', 15 in reports and
              0 in reports[reports.index(15) + 1:] and all(n in (0, 15) for n in reports), reports)
        check('time-zero-after-expiry', value('identify-time', 'IdentifyTime') == 0)
        storage = client.storage
        client.close()
        client = None
        stop()
        launch()
        client = Client(Path(a.chip_tool), Path(a.paa), out, 'restart', source=storage)
        check('fresh-case-read-after-restart', value('identify-type', 'IdentifyType') == 0 and
              value('identify-time', 'IdentifyTime') == 0)
        client.close()
        client = None
        stop()
        for i in range(1, phase + 1):
            check(f'empty-host-stderr-{i}', not (out / f'node-{i}.err').read_bytes())
            if a.valgrind:
                text = (out / f'valgrind-{i}.log').read_text()
                check(f'memcheck-clean-{i}', 'ERROR SUMMARY: 0 errors' in text and
                      'in use at exit: 0 bytes in 0 blocks' in text)
        result['result'] = 'PASS'
        return 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        result['result'] = 'FAIL'
        result['error'] = str(error)
        print('FAIL', error, flush=True)
        return 1
    finally:
        if client is not None:
            client.close()
        if node is not None and node.poll() is None:
            node.terminate()
            try:
                node.wait(timeout=40)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()
        for log in logs:
            log.close()
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
