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
from chip_tool_energy_profile import frames, ids, integer


def commissioning_profile(client, check):
    """Related manual network/group-key checks on the disposable simulator.

    This exercises CASE and the Wi-Fi backend, not BLE or physical radio faults.
    Keep each case's failure independent so one does not hide the other.
    """
    result = {}

    def command(args, expected_error=None):
        ok, text = client.command(args, r'(?:ReportDataMessage|InvokeResponseMessage) =[\s\S]*Flushed pending ack for MessageCounter:', timeout=60,
                                  failure=expected_error is not None)
        assert ok, 'No complete command response: ' + ' '.join(map(str, args[:2]))
        if expected_error is not None:
            assert re.search(r'status\s*=\s*0x' + format(expected_error, '02x') + r'\b', text, re.I), 'Wrong IM error'
        return text

    def read(cluster, attribute, label):
        text = command(['any', 'read-by-id', cluster, attribute, 1, 0])
        body = next(f['body'] for f in frames(text) if f['kind'] == 'Attribute' and f['path'] == (0, cluster, attribute))
        return integer(body, label)

    try:
        check('groupkey-cache-sync-feature-absent', read(0x3f, 0xfffc, 'FeatureMap') == 0)
        fields = dict(groupKeySetID=0x1a3, groupKeySecurityPolicy=1,
                      epochKey0='d0d1d2d3d4d5d6d7d8d9dadbdcdddedf', epochStartTime0=1,
                      epochKey1='d1d1d2d3d4d5d6d7d8d9dadbdcdddedf', epochStartTime1=2220001,
                      epochKey2='d2d1d2d3d4d5d6d7d8d9dadbdcdddedf', epochStartTime2=2220002)
        command(['groupkeymanagement', 'key-set-write', json.dumps(fields), 1, 0], 0x85)
        check('groupkey-cache-sync-invalid-command', True)
        command(['groupkeymanagement', 'key-set-read', 0x1a3, 1, 0], 0x8b)
        check('groupkey-rejected-set-not-created', True)
        result['TC_GRPKEY_5_4'] = {'result': 'PASS', 'CacheAndSync': False, 'write_status': 0x85, 'read_status': 0x8b}
    except (AssertionError, StopIteration, ValueError) as error:
        result['TC_GRPKEY_5_4'] = {'result': 'FAIL', 'error': str(error)}

    def arm(seconds):
        data = command(['generalcommissioning', 'arm-fail-safe', seconds, 0, 1, 0])
        assert re.search(r'errorCode:\s*0\b', data), 'ArmFailSafe rejected'

    def network(operation, args, status=0, breadcrumb=None):
        data = command(['networkcommissioning', operation, *args, 1, 0] +
                       ([] if breadcrumb is None else ['--Breadcrumb', breadcrumb]))
        assert re.search(r'networkingStatus:\s*' + str(status) + r'\b', data), operation + ' status mismatch'
        return data

    def networks():
        text = command(['networkcommissioning', 'read', 'networks', 1, 0])
        body = next(f['body'] for f in frames(text) if f['path'] == (0, 0x31, 1))
        values = [bytes.fromhex(x) for x in re.findall(r'^NetworkID: ([0-9A-Fa-f]+)\s*$', body, re.M)]
        assert len(values) == integer(body, 'Networks') and len(values) == len(set(values)), 'Incomplete network list'
        return values

    encode = lambda value: 'hex:' + value.hex()
    primary = b'testharness'; additions = []
    try:
        text = command(['descriptor', 'read', 'server-list', 1, 0])
        body = next(f['body'] for f in frames(text) if f['path'] == (0, 0x1d, 1))
        check('reorder-wifi-cluster-feature', 0x31 in ids(body, 'ServerList') and read(0x31, 0xfffc, 'FeatureMap') == 1)
        maximum = read(0x31, 0, 'MaxNetworks')
        assert maximum >= 2, 'Procedure requires at least two network slots'
        arm(900)
        network('add-or-update-wi-fi-network', [encode(primary), encode(b'wifi-password')])
        network('connect-network', [encode(primary)])
        data = command(['generalcommissioning', 'commissioning-complete', 1, 0])
        assert re.search(r'errorCode:\s*0\b', data), 'Baseline CommissioningComplete rejected'
        baseline = networks(); assert primary in baseline and len(baseline) < maximum
        midpoint = (maximum + 1) // 2
        additions = [b'csa-reorder-' + str(i).encode() for i in range(maximum - len(baseline))]

        def fill():
            for name in additions:
                network('add-or-update-wi-fi-network', [encode(name), encode(b'wifi-password')], breadcrumb=1)
            assert len(networks()) == maximum, 'Network list not filled'

        arm(900)
        check('reorder-original-network-count', networks() == baseline)
        network('add-or-update-wi-fi-network', [encode(additions[0]), encode(b'wifi-password')], breadcrumb=1)
        arm(900)
        for name in additions[1:]:
            network('add-or-update-wi-fi-network', [encode(name), encode(b'wifi-password')], breadcrumb=1)
        original = networks()
        check('reorder-full-network-list', len(original) == maximum)
        network('reorder-network', [encode(primary), maximum], status=1, breadcrumb=2)
        check('reorder-out-of-range-preserves-breadcrumb', read(0x30, 0, 'Breadcrumb') == 1 and networks() == original)
        network('reorder-network', [encode(b'csa-absent'), midpoint], status=3, breadcrumb=2)
        check('reorder-absent-id-preserves-breadcrumb', read(0x30, 0, 'Breadcrumb') == 1 and networks() == original)
        network('reorder-network', [encode(primary), midpoint], breadcrumb=2)
        expected = [n for n in original if n != primary]; expected.insert(midpoint, primary)
        check('reorder-moves-network-and-breadcrumb', networks() == expected and read(0x30, 0, 'Breadcrumb') == 2)
        arm(0)
        check('reorder-disarm-rolls-back-added-networks', networks() == baseline)
        arm(900); fill()
        network('reorder-network', [encode(primary), midpoint], breadcrumb=2)
        committed = networks()
        data = command(['generalcommissioning', 'commissioning-complete', 1, 0])
        assert re.search(r'errorCode:\s*0\b', data), 'Final CommissioningComplete rejected'
        arm(0)
        check('reorder-complete-persists-after-disarm', networks() == committed and committed[midpoint] == primary)
        result['TC_CNET_4_13'] = {'functional_result': 'PASS', 'BLE_precondition': 'NOT_PERFORMED',
                                 'backend': 'simulated Wi-Fi over real CASE/IPv6', 'max_networks': maximum,
                                 'midpoint': midpoint, 'rollback': True, 'commit': True}
    except (AssertionError, StopIteration, ValueError) as error:
        result['TC_CNET_4_13'] = {'functional_result': 'FAIL', 'error': str(error), 'BLE_precondition': 'NOT_PERFORMED'}
    finally:
        try:
            arm(0)
        except (AssertionError, StopIteration, ValueError):
            result['network_cleanup'] = 'FAIL'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--valgrind', action='store_true')
    parser.add_argument('--csa-profile', action='store_true', help='Also collect BootReason events, Wi-Fi reorder/rollback and CacheAndSync rejection; no physical BLE/radio claim.')
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

    def command(argv, pattern=None):
        if pattern is None:
            pattern = r'ReportDataMessage =[\s\S]*Flushed pending ack for MessageCounter:' if args.csa_profile else 'SuppressResponse = true'
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

    def boot_event(name):
        text = command(['generaldiagnostics', 'read-event', 'boot-reason', 1, 0], r'ReportDataMessage =[\s\S]*Flushed pending ack for MessageCounter:')
        events = [f for f in frames(text) if f['kind'] == 'Event' and f['path'] == (0, 0x33, 3)]
        check(name + '-boot-event-present', bool(events))
        event = events[-1]
        value = integer(event['body'], 'BootReason'); number = integer(event['body'], 'Event number')
        check(name + '-boot-event-matches-attribute', value == read('boot-reason', 'BootReason') == 1 and number > 0)
        return {'event_number': number, 'boot_reason': value, 'scope': 'Restart of simulated Node process, not hardware reboot.'}

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
        if args.csa_profile:
            result['application_profile'] = commissioning_profile(client, check)
            result['boot_events'] = [boot_event('first')]
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
        if args.csa_profile:
            result['boot_events'].append(boot_event('restart'))
            check('restart-emits-new-boot-event-number', result['boot_events'][1]['event_number'] > result['boot_events'][0]['event_number'])
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
        if args.csa_profile:
            result['boot_events'].append(boot_event('factory-reset'))
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
        if args.csa_profile:
            profile = result['application_profile']
            check('csa-related-functionality', all(v.get('result', v.get('functional_result')) == 'PASS'
                  for v in profile.values() if isinstance(v, dict)) and profile.get('network_cleanup') != 'FAIL', profile)
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
