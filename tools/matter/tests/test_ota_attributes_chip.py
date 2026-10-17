"""Two-fabric OTA attribute acceptance using unmodified chip-tool.

Local protocol evidence, not a replacement for TC_SU_4_1 or certification.
Run on disposable state, separately under Memcheck and ASan/UBSan/LSan.
Checks every list-operation status, partial writes, fabric isolation and restart.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from chip_tool_resources import ANSI
from chip_tool_energy_profile import frames

CLUSTER = 'otasoftwareupdaterequestor'


def write_statuses(text):
    return [int(n, 16) for n in re.findall(r'\bstatus = 0x([0-9a-fA-F]{2})\b', text)]


def provider_values(text):
    reports = [f for f in frames(text) if f['kind'] == 'Attribute' and f['path'] == (0, 0x2a, 0)]
    if len(reports) != 1:
        raise ValueError('Expected one DefaultOTAProviders report')
    body = reports[0]['body']
    count = re.search(r'^DefaultOTAProviders: (\d+) entries$', body, re.M)
    result = re.findall(r'ProviderNodeID: (\d+)\s+Endpoint: (\d+)\s+FabricIndex: (\d+)', body)
    if not count or int(count[1]) != len(result) or body.count('ProviderNodeID:') != len(result):
        raise ValueError('Malformed provider report')
    return [tuple(map(int, item)) for item in result]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'ota-key', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--discriminator', type=int, default=3913)
    p.add_argument('--valgrind', action='store_true')
    a = p.parse_args()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'Local two-fabric OTA attributes; not official CSA PASS',
              'node_sha256': hashlib.sha256(Path(a.exe).read_bytes()).hexdigest(),
              'controller_sha256': hashlib.sha256(Path(a.chip_tool).read_bytes()).hexdigest(),
              'valgrind': a.valgrind, 'checks': []}
    node = None
    logs = []
    phase = serial = 0
    env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    stores = {fabric: out / fabric for fabric in ('alpha', 'beta')}
    for path in stores.values():
        path.mkdir()

    def check(name, condition, detail=None):
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'detail': detail})
        print(('PASS ' if condition else 'FAIL ') + name, flush=True)
        if not condition:
            raise AssertionError(name + ': ' + str(detail))

    def launch():
        nonlocal node, phase
        phase += 1
        argv = [a.exe, '--interface', str(a.interface), '--port', '5581', '--seconds', '900',
                '--discriminator', str(a.discriminator), '--credentials', a.credentials,
                '--state', str(out / 'state.tlv'), '--three-phase', '--source-registers', '--meter-services',
                '--ota-file', str(out / 'download.ota'), '--ota-sim-key', a.ota_key]
        if a.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=definite,indirect,possible', '--track-origins=yes',
                    '--error-exitcode=99', '--log-file=' + str(out / f'valgrind-{phase}.log'), *argv]
        handles = [(out / f'node-{phase}.{ext}').open('w') for ext in ('log', 'err')]
        logs.extend(handles)
        node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1], env=env)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if node.poll() is not None:
                raise AssertionError('Node exited during startup')
            if 'NODE instance=' in (out / f'node-{phase}.log').read_text():
                return
            time.sleep(.05)
        raise AssertionError('Node startup timeout')

    def stop():
        node.terminate()
        check(f'clean-stop-{phase}', node.wait(timeout=40) == 0)

    def command(fabric, args, failure=False):
        nonlocal serial
        serial += 1
        argv = [a.chip_tool, *map(str, args), '--storage-directory', str(stores[fabric]),
                '--paa-trust-store-path', a.paa, '--timeout', '50']
        with (out / f'command-{serial}.log').open('w') as log:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT,
                                    env=dict(env, TMPDIR=str(stores[fabric])), timeout=65)
        text = ANSI.sub('', (out / f'command-{serial}.log').read_text(errors='replace'))
        if not failure and result.returncode:
            raise AssertionError('Controller failed: ' + text[-700:])
        return text

    def providers(fabric, expected, label):
        text = command(fabric, [CLUSTER, 'read', 'default-otaproviders', 1, 0])
        actual = provider_values(text)
        check(label, actual == expected, actual)
        return actual

    def write(fabric, values, expected, label):
        text = command(fabric, [CLUSTER, 'write', 'default-otaproviders', json.dumps(values), 1, 0],
                       failure=any(expected))
        actual = write_statuses(text)
        check(label, actual == expected, actual)

    def provider(node_id):
        # A supplied fabric index cannot move a write to that other fabric.
        return {'providerNodeID': node_id, 'endpoint': 0, 'fabricIndex': 5}

    try:
        launch()
        text = command('alpha', ['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL'])
        check('commission-alpha', 'Device commissioning completed with success' in text and
              "Successfully finished commissioning step 'AttestationVerification'" in text)
        providers('alpha', [], 'initial-default-empty')
        write('alpha', [provider(1)], [0, 0], 'fabric1-write-statuses')
        first = provider_values(command('alpha', [CLUSTER, 'read', 'default-otaproviders', 1, 0]))
        check('fabric1-provider-and-index', len(first) == 1 and first[0][:2] == (1, 0) and
              0 < first[0][2] < 255 and first[0][2] != 5, first)
        f1 = first[0][2]
        text = command('alpha', ['pairing', 'open-commissioning-window', 1, 1, 180, 1000, 3914])
        code = re.search(r'Manual pairing code: \[(\d+)\]', text)
        check('enhanced-window', bool(code))
        text = command('beta', ['pairing', 'code', 1, code[1], '--country-code', 'PL'])
        check('commission-beta', 'Device commissioning completed with success' in text and
              "Successfully finished commissioning step 'AttestationVerification'" in text)
        providers('beta', [], 'fabric2-default-empty')
        write('beta', [provider(3)], [0, 0], 'fabric2-write-statuses')
        second = provider_values(command('beta', [CLUSTER, 'read', 'default-otaproviders', 1, 0]))
        check('fabric2-provider-and-index', len(second) == 1 and second[0][:2] == (3, 0) and
              0 < second[0][2] < 255 and second[0][2] not in (f1, 5), second)
        f2 = second[0][2]
        providers('alpha', [(1, 0, f1)], 'fabric1-unaffected-by-fabric2')
        write('alpha', [provider(4), provider(1)], [0, 0, 0x87], 'two-provider-full-status-vector')
        providers('alpha', [(4, 0, f1)], 'partial-write-retains-first-provider')
        providers('beta', [(3, 0, f2)], 'constraint-error-isolated-to-fabric1')
        write('beta', [], [0], 'clear-fabric2-status')
        providers('beta', [], 'fabric2-cleared')
        providers('alpha', [(4, 0, f1)], 'fabric1-survives-fabric2-clear')
        text = command('alpha', [CLUSTER, 'read', 'update-possible', 1, 0])
        check('update-possible', bool(re.search(r'UpdatePossible: TRUE\b', text)))
        text = command('alpha', [CLUSTER, 'read', 'update-state', 1, 0])
        state = re.search(r'UpdateState: (\d+)\b', text)
        check('update-state-enum', bool(state) and int(state[1]) in range(9), int(state[1]) if state else None)
        text = command('alpha', [CLUSTER, 'read', 'update-state-progress', 1, 0])
        check('no-download-progress-null', 'UpdateStateProgress: null' in text)
        text = command('alpha', [CLUSTER, 'announce-otaprovider', 9, 0xfff1, 0, 0, 1, 0])
        check('announcement-status', write_statuses(text) == [0], write_statuses(text))
        providers('alpha', [(4, 0, f1)], 'announcement-does-not-replace-default')
        stop()
        launch()
        providers('alpha', [(4, 0, f1)], 'fabric1-default-persists-after-restart')
        providers('beta', [], 'fabric2-clear-persists-after-restart')
        stop()
        for index in range(1, phase + 1):
            check(f'empty-host-stderr-{index}', not (out / f'node-{index}.err').read_text())
            if a.valgrind:
                text = (out / f'valgrind-{index}.log').read_text()
                check(f'memcheck-clean-{index}', 'ERROR SUMMARY: 0 errors' in text and
                      'in use at exit: 0 bytes in 0 blocks' in text)
        report['result'] = 'PASS'
        return 0
    except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
        report['result'] = 'FAIL'
        report['error'] = str(error)
        print('FAIL', error, flush=True)
        return 1
    finally:
        if node is not None and node.poll() is None:
            node.terminate()
            try:
                node.wait(timeout=40)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()
        for handle in logs:
            handle.close()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
