"""General Diagnostics on a disposable x86 node, using unmodified chip-tool.

Process lifetime is the simulated Node lifetime. Checks real elapsed time,
restart/persistence, factory reset and the declared simulated interface.
Run Memcheck and ASan/UBSan/LSan separately. Not official CSA acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

from chip_tool_resources import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--valgrind', action='store_true')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    state = out / 'state.tlv'
    result = {'scope': __doc__, 'checks': [], 'valgrind': args.valgrind,
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(Path(args.exe).read_bytes()).hexdigest()}
    node = client = None
    logs = []
    boot = 0
    launched = 0

    def check(name, passed, detail=None):
        result['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed:
            raise AssertionError(name + ': ' + str(detail))

    def launch():
        nonlocal node, boot, launched
        boot += 1
        argv = [args.exe, '--interface', str(args.interface), '--port', '5582', '--seconds', '240',
                '--discriminator', '3918', '--credentials', args.credentials, '--state', str(state),
                '--three-phase', '--source-registers', '--meter-services', '--wifi-sim-connected']
        if args.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=definite,indirect,possible', '--track-origins=yes',
                    '--error-exitcode=99', '--log-file=' + str(out / f'valgrind-{boot}.log'), *argv]
        handles = [(out / f'node-{boot}.{ext}').open('w') for ext in ('log', 'err')]
        logs.extend(handles)
        launched = time.monotonic()
        node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1], env=dict(os.environ,
                                ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',
                                UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        deadline = launched + 40
        while time.monotonic() < deadline:
            if node.poll() is not None:
                raise AssertionError('Node startup failed')
            if 'PUBLISHED' in (out / f'node-{boot}.log').read_text():
                return
            time.sleep(.05)
        raise AssertionError('Node publication timeout')

    def command(argv, pattern='SuppressResponse = true'):
        ok, data = client.command(argv, pattern, timeout=60)
        if not ok:
            raise AssertionError(str(argv) + ': ' + data[-800:])
        return data

    def read(attribute, label):
        text = command(['generaldiagnostics', 'read', attribute, 1, 0])
        match = re.search(r'\b' + label + r': (\d+)\b', text)
        if not match:
            raise AssertionError('Missing ' + label)
        return int(match[1])

    def stop():
        nonlocal client
        if client is not None:
            client.close()
            client = None
        node.terminate()
        check(f'clean-stop-{boot}', node.wait(timeout=40) == 0)

    def commission(name):
        nonlocal client
        client = Client(Path(args.chip_tool), Path(args.paa), out, name)
        data = command(['pairing', 'onnetwork-long', 1, 20202021, 3918, '--country-code', 'PL', '--timeout', 45],
                       'Device commissioning completed with success')
        check(name + '-attestation', "Successfully finished commissioning step 'AttestationVerification'" in data)

    def bounded_uptime(name):
        value = read('up-time', 'UpTime')
        elapsed = time.monotonic() - launched
        check(name, max(0, int(elapsed) - 3) <= value <= elapsed + 1,
              {'uptime_s': value, 'process_elapsed_s': elapsed})
        return value

    try:
        launch()
        commission('first')
        check('fresh-reboot-count', read('reboot-count', 'RebootCount') == 1)
        first = bounded_uptime('fresh-node-uptime-not-os-uptime')
        check('fresh-operational-hours-zero', read('total-operational-hours', 'TotalOperationalHours') == 0)
        check('power-on-boot-reason', read('boot-reason', 'BootReason') == 1)
        interface = socket.if_indextoname(args.interface)
        os_interface = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show', 'dev', interface]))[0]
        addresses = {family: [socket.inet_pton(af, item['local']).hex().upper()
                     for item in os_interface['addr_info'] if item['family'] == family]
                     for family, af in (('inet', socket.AF_INET), ('inet6', socket.AF_INET6))}
        deadline = time.monotonic() + 10
        while True:
            network = command(['generaldiagnostics', 'read', 'network-interfaces', 1, 0])
            if 'IsOperational: TRUE' in network or time.monotonic() >= deadline:
                break
            time.sleep(.1)
        mac = '0000' + os_interface['address'].replace(':', '').upper()
        check('actual-selected-interface', all(token in network for token in (
            'NetworkInterfaces: 1 entries', f'Name: host-interface-{args.interface}', 'IsOperational: TRUE',
            'OffPremiseServicesReachableIPv4: null', 'OffPremiseServicesReachableIPv6: null',
            'HardwareAddress: ' + mac, 'Type: 0')))
        check('actual-ipv4-addresses', f"IPv4Addresses: {len(addresses['inet'])} entries" in network and
              all(address in network for address in addresses['inet']))
        check('actual-ipv6-including-link-local', f"IPv6Addresses: {len(addresses['inet6'])} entries" in network and
              bool(addresses['inet6']) and all(address in network for address in addresses['inet6']))
        result['network_capture_sha256'] = hashlib.sha256(network.encode()).hexdigest()
        for attribute, label in (('active-hardware-faults', 'ActiveHardwareFaults'),
                                 ('active-radio-faults', 'ActiveRadioFaults'),
                                 ('active-network-faults', 'ActiveNetworkFaults')):
            text = command(['generaldiagnostics', 'read', attribute, 1, 0])
            check(attribute + '-empty-list', label + ': 0 entries' in text)
        text = command(['generaldiagnostics', 'read', 'test-event-triggers-enabled', 1, 0])
        check('test-event-triggers-disabled', 'TestEventTriggersEnabled: FALSE' in text)
        before = time.monotonic()
        time.sleep(10)
        later = bounded_uptime('uptime-after-real10s')
        check('uptime-increments-with-elapsed-time', 9 <= later - first <= time.monotonic() - before + 4)
        storage = client.storage
        stop()
        launch()
        client = Client(Path(args.chip_tool), Path(args.paa), out, 'restart', source=storage)
        check('reboot-count-increments-after-restart', read('reboot-count', 'RebootCount') == 2)
        rebooted = bounded_uptime('uptime-resets-after-restart')
        check('restart-uptime-below-pre-restart-value', rebooted < later)
        check('hours-retained-after-restart', read('total-operational-hours', 'TotalOperationalHours') == 0)
        stop()
        # Only the explicitly owned, stopped disposable node store is reset.
        assert state.parent == out and state.is_file()
        state.unlink()
        launch()
        commission('factory-reset')
        check('factory-reset-reboot-count', read('reboot-count', 'RebootCount') == 1)
        check('factory-reset-hours-zero', read('total-operational-hours', 'TotalOperationalHours') == 0)
        bounded_uptime('factory-reset-uptime')
        stop()
        for index in range(1, boot + 1):
            check(f'empty-host-stderr-{index}', not (out / f'node-{index}.err').read_bytes())
            if args.valgrind:
                text = (out / f'valgrind-{index}.log').read_text()
                check(f'memcheck-clean-{index}', 'ERROR SUMMARY: 0 errors' in text and
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
