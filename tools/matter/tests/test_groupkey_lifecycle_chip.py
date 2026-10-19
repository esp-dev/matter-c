"""Independent GroupKey capacity/persistence acceptance with real chip-tool.

Disposable Linux state only. Original TH results remain separate. Supply public
development credentials/PAA; raw controller stores and traces must stay private.
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
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--valgrind', action='store_true')
    a = parser.parse_args()
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'result': 'RUNNING', 'checks': [], 'boots': [],
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(a.exe.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(a.chip_tool.read_bytes()).hexdigest()}
    clients = []; node = None; handles = []; boot = None

    def save():
        temp = out / 'result.tmp'; temp.write_text(json.dumps(report, indent=2))
        temp.replace(out / 'result.json')

    def check(name, ok, detail=None):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        save(); print('PASS' if ok else 'FAIL', name, flush=True)
        if not ok:
            raise AssertionError(name)

    def start():
        nonlocal node, boot, handles
        boot = out / ('boot-' + str(len(report['boots']) + 1)); boot.mkdir()
        report['boots'].append({'name': boot.name})
        argv = [str(a.exe), '--interface', str(a.interface), '--port', '5592',
                '--seconds', '600', '--credentials', str(a.credentials),
                '--state', str(out / 'state.tlv'), '--pin', '20202021',
                '--discriminator', '3920', '--wifi-sim-connected']
        if a.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=all', '--track-origins=yes',
                    '--error-exitcode=99', '--log-file=' + str(boot / 'memcheck.log'), *argv]
        handles = [(boot / ('node.' + suffix)).open('w') for suffix in ('log', 'err')]
        node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1],
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                         UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        end = time.monotonic() + 40
        while time.monotonic() < end and node.poll() is None and 'PUBLISHED' not in (boot / 'node.log').read_text():
            time.sleep(.05)
        check('published-' + boot.name, node.poll() is None and 'PUBLISHED' in (boot / 'node.log').read_text())

    def stop():
        nonlocal node, handles
        if node is None:
            return
        if node.poll() is None:
            node.terminate()
        try:
            node.wait(timeout=35)
        except subprocess.TimeoutExpired:
            node.kill(); node.wait()
        row = report['boots'][-1]; row['exit'] = node.returncode
        row['stderr_empty'] = not (boot / 'node.err').read_bytes()
        for handle in handles:
            handle.close()
        handles = []; node = None
        if a.valgrind:
            text = (boot / 'memcheck.log').read_text()
            match = re.search(r'total heap usage: ([\d,]+) allocs, ([\d,]+) frees', text)
            row['memory'] = {'zero_errors': 'ERROR SUMMARY: 0 errors' in text,
                             'zero_live': 'in use at exit: 0 bytes in 0 blocks' in text,
                             'allocations': int(match[1].replace(',', '')) if match else None,
                             'frees': int(match[2].replace(',', '')) if match else None}
        check('clean-' + boot.name, row['exit'] == 0 and row['stderr_empty'] and
              (not a.valgrind or all(row['memory'][x] for x in ('zero_errors', 'zero_live'))))

    def client(name, source=None):
        value = Client(a.chip_tool, a.paa, out, name, source, advertise=False)
        clients.append(value); return value

    def command(c, args, expected=None, status=None):
        if status is not None:
            expected = r'Run command failure:.*0x000005' + format(status, '02X')
        elif expected is None:
            expected = r'InvokeResponseMessage =[\s\S]*[Ss]tatus = 0x00\b[\s\S]*Flushed pending ack for MessageCounter:'
        ok, text = c.command(args, expected, timeout=55, failure=status is not None)
        check('command-' + '-'.join(map(str, args[:2])), ok)
        return text

    def commission(c):
        return command(c, ['pairing', 'already-discovered', 1, 20202021,
                          a.ipv6 + '%' + str(a.interface), 5592, '--country-code', 'PL', '--timeout', 45],
                       r'Device commissioning completed with success')

    def indices(c):
        text = command(c, ['groupkeymanagement', 'key-set-read-all-indices', 1, 0],
                       r'groupKeySetIDs: \d+ entries[\s\S]*Flushed pending ack for MessageCounter:')
        count = int(re.search(r'groupKeySetIDs: (\d+) entries', text)[1])
        ids = [int(x) for x in re.findall(r'\[\d+\]: (\d+)\b', text)]
        check('indices-decode', len(ids) == count and len(set(ids)) == count)
        return ids

    def write(c, key, start=1, status=None):
        fields = dict(groupKeySetID=key, groupKeySecurityPolicy=0,
                      epochKey0='000102030405060708090a0b0c0d0e0f', epochStartTime0=start,
                      epochKey1=None, epochStartTime1=None, epochKey2=None, epochStartTime2=None)
        command(c, ['groupkeymanagement', 'key-set-write', json.dumps(fields), 1, 0], status=status)

    def read(c, key, start):
        text = command(c, ['groupkeymanagement', 'key-set-read', key, 1, 0],
                       r'KeySetReadResponse:[\s\S]*Flushed pending ack for MessageCounter:')
        check('read-key-' + str(key), bool(re.search(r'GroupKeySetID: ' + str(key) + r'\b', text)) and
              bool(re.search(r'EpochStartTime0: ' + str(start) + r'\b', text)) and
              all(re.search(r'EpochKey' + str(i) + r': null\b', text) for i in range(3)))

    try:
        start(); c = client('original'); commission(c)
        text = command(c, ['groupkeymanagement', 'read', 'max-group-keys-per-fabric', 1, 0],
                       r'MaxGroupKeysPerFabric: \d+[\s\S]*Flushed pending ack for MessageCounter:')
        maximum = int(re.search(r'MaxGroupKeysPerFabric: (\d+)', text)[1])
        check('advertised-capacity', 3 <= maximum < 200, maximum)
        report['maximum'] = maximum
        check('initial-IPK-only', indices(c) == [0])
        for key in range(1, maximum):
            write(c, key)
        full = list(range(maximum)); check('actual-capacity-filled', indices(c) == full)
        write(c, maximum - 1, 2); read(c, maximum - 1, 2)
        check('overwrite-at-capacity-preserves-indices', indices(c) == full)
        write(c, 200, status=0x89)
        command(c, ['groupkeymanagement', 'key-set-read', 200, 1, 0], status=0x8b)
        check('overflow-atomic', indices(c) == full)
        store = c.storage; c.close(); clients.remove(c)
        stop(); start(); c = client('restarted', store)
        check('same-fabric-survives-restart', indices(c) == full)
        read(c, maximum - 1, 2)
        for key in range(1, maximum):
            command(c, ['groupkeymanagement', 'key-set-remove', key, 1, 0])
        check('removed-only-added-keys', indices(c) == [0])
        c.close(); clients.remove(c); stop()
        state = out / 'state.tlv'
        check('own-state-exists', state.is_file())
        state.unlink(); start(); c = client('after-reset'); commission(c)
        check('new-fabric-after-factory-reset', indices(c) == [0])
        report['result'] = 'PASS'
    except (AssertionError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        report['result'] = 'FAIL'; report['error'] = str(error)
    finally:
        for c in reversed(clients):
            c.close()
            if c.child.returncode:
                report['result'] = 'FAIL'; report['controller_cleanup_error'] = c.child.returncode
        try:
            stop()
        except (AssertionError, OSError) as error:
            report['result'] = 'FAIL'; report['cleanup_error'] = str(error)
        save()
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
