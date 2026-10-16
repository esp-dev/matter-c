"""Metered On/Off host experiment with unmodified chip-tool; not CSA/UI proof.

Uses disposable state and controller credentials. Run under Memcheck, then
separately with an ASan/UBSan/LSan host. Never use a paired household node.
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
from chip_tool_energy_profile import frames, integer, ids
from chip_tool_three_phase import inventory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'interface', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--memcheck', action='store_true')
    profile = p.add_mutually_exclusive_group()
    profile.add_argument('--power-only', action='store_true', help='Also verify the independent 123 W endpoint 6, without On/Off or EEM.')
    profile.add_argument('--sensor-only', action='store_true', help='Verify Root plus a 123 W Electrical Sensor on endpoint 1, without any socket; EEM is optional with --sensor-energy.')
    p.add_argument('--sensor-energy', action='store_true', help='With --sensor-only, add cumulative import/export energy on endpoint 1.')
    a = p.parse_args()
    if a.sensor_energy and not a.sensor_only:
        p.error('--sensor-energy requires --sensor-only')
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'scope': ('synthetic Root and power/energy sensor' if a.sensor_energy else 'synthetic Root and power sensor only' if a.sensor_only else 'synthetic metered plug') + '; not CSA certification or Apple UI acceptance', 'checks': [],
              'host_sha256': hashlib.sha256(Path(a.exe).read_bytes()).hexdigest()}
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    node = client = None; boot = 0; logs = []

    def check(name, ok, detail=None):
        report['checks'].append(dict(name=name, passed=bool(ok), detail=detail))
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        assert ok, name

    def wait(test, timeout=30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if test():
                return
            assert node.poll() is None, 'host exited early'
            time.sleep(.05)
        raise AssertionError('condition timed out')

    def start():
        nonlocal boot, node
        boot += 1
        argv = [a.exe, '--interface', a.interface, '--seconds', '180', '--port', '5543',
                '--credentials', a.credentials, '--state', str(out / 'node.tlv'),
                '--pin', '20202021', '--discriminator', '3846']
        argv += ['--power-sensor-only'] if a.sensor_only else ['--test-switch', '--three-phase', '--source-registers', '--meter-services']
        if a.sensor_energy:
            argv += ['--sensor-energy']
        if a.power_only:
            argv += ['--test-power-only']
        if a.memcheck:
            argv = ['valgrind', '--error-exitcode=99', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=all', '--track-origins=yes', '--log-file=' + str(out / f'memcheck-{boot}.log'), *argv]
        stdout = (out / f'node-{boot}.log').open('w'); stderr = (out / f'node-{boot}.err').open('w')
        logs.extend([stdout, stderr]); node = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env)
        wait(lambda: 'NODE instance=' in (out / f'node-{boot}.log').read_text())

    def stop():
        if node.poll() is None:
            node.send_signal(signal.SIGTERM)
        check('clean-stop-' + str(boot), node.wait(timeout=30) == 0)
        check('stderr-empty-' + str(boot), not (out / f'node-{boot}.err').read_text())
        if a.memcheck:
            data = (out / f'memcheck-{boot}.log').read_text()
            check('memcheck-clean-' + str(boot), 'ERROR SUMMARY: 0 errors' in data and 'in use at exit: 0 bytes in 0 blocks' in data)

    def command(argv, pattern=r'SuppressResponse = true'):
        ok, data = client.command(argv, pattern, timeout=45)
        assert ok, (argv[:3], data[-500:])
        return data

    def read_energy():
        data = command(['electricalenergymeasurement', 'read', 'cumulative-energy-imported', 1, 2])
        return integer(next(f['body'] for f in frames(data) if f['path'] == (2, 0x91, 1)), 'Energy')

    def independent_power(label):
        if a.power_only or a.sensor_only:
            endpoint = 1 if a.sensor_only else 6
            data = command(['electricalpowermeasurement', 'read', 'active-power', 1, endpoint])
            check('independent-123W-' + label, integer(next(f['body'] for f in frames(data) if f['path'] == (endpoint, 0x90, 8)), 'ActivePower') == 123000)

    def minimal_inventory(data):
        attrs = {f['path']: f for f in frames(data) if f['kind'] == 'Attribute'}
        assert {p[0] for p in attrs} == {0, 1}
        assert ids(attrs[0, 0x1d, 3]['body'], 'PartsList') == [1]
        assert ids(attrs[1, 0x1d, 3]['body'], 'PartsList') == []
        assert [int(x) for x in re.findall(r'^DeviceType: (\d+)\b', attrs[1, 0x1d, 0]['body'], re.M)] == [0x510]
        assert set(ids(attrs[1, 0x1d, 1]['body'], 'ServerList')) == {0x1d, 0x90, 0x9c} | ({0x91} if a.sensor_energy else set())
        assert not any(p[1] == 6 or (p[1] == 0x91 and not a.sensor_energy) for p in attrs)
        if a.sensor_energy:
            assert integer(attrs[1, 0x91, 0xfffc]['body'], 'FeatureMap') == 7
        assert integer(attrs[1, 0x90, 0xfffc]['body'], 'FeatureMap') == 2
        assert integer(attrs[1, 0x90, 8]['body'], 'ActivePower') == 123000
        expected = set()
        for ep in (0, 1):
            for cluster in ids(attrs[ep, 0x1d, 1]['body'], 'ServerList'):
                expected.update((ep, cluster, attr) for attr in ids(attrs[ep, cluster, 0xfffb]['body'], 'AttributeList'))
        assert set(attrs) == expected
        check('root-and-one-sensor-no-onoff' if a.sensor_energy else 'root-and-one-power-sensor-no-onoff-no-eem', True)

    def sensor_registers():
        result = []
        for attr, name in ((1, 'cumulative-energy-imported'), (2, 'cumulative-energy-exported')):
            data = command(['electricalenergymeasurement', 'read', name, 1, 1])
            result.append(integer(next(f['body'] for f in frames(data) if f['path'] == (1, 0x91, attr)), 'Energy'))
        return result

    try:
        if a.sensor_only:
            bad = subprocess.run([a.exe, '--sensor-energy'], capture_output=True, env=env, timeout=10)
            check('energy-option-requires-minimal-profile', bad.returncode == 2 and b'requires --power-sensor-only' in bad.stderr)
            for flag in ('--test-switch', '--test-power-only', '--three-phase', '--source-registers', '--meter-services'):
                bad = subprocess.run([a.exe, '--power-sensor-only', flag], capture_output=True, env=env, timeout=10)
                check('conflicting-profile-rejected-' + flag[2:], bad.returncode == 2 and b'excludes other' in bad.stderr and not bad.stdout)
        start()
        tool, paa = Path(a.chip_tool).resolve(), Path(a.paa).resolve()
        client = Client(tool, paa, out, 'controller', advertise=False)
        data = command(['payload', 'generate-qrcode', '--discriminator', 3846, '--setup-pin-code', 20202021, '--rendezvous', 4], r'QR Code: MT:')
        code = re.search(r'QR Code: (MT:[A-Z0-9.\-]+)', data)[1]
        data = command(['pairing', 'code', 1, code, '--use-only-onnetwork-discovery', 1, '--country-code', 'PL', '--timeout', 60], 'Device commissioning completed with success')
        check('verified-attestation', "Successfully finished commissioning step 'AttestationVerification'" in data)
        data = command(['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', 1, '0xffff,0xffff'])
        if a.sensor_only:
            minimal_inventory(data)
            independent_power('initial')
            if a.sensor_energy:
                initial_energy = sensor_registers()
                check('distinct-import-export-baselines', initial_energy[0] >= 12345000 and initial_energy[1] == 2345000, {'mWh': initial_energy})
            sensor_offset = len(client.text())
            if a.sensor_energy:
                command(['any', 'subscribe-all', '0x90,0x91,0x91,0x91', '8,1,2', '0', 0, 2, 1, '1,1,1,1', '--keepSubscriptions', 1], 'Subscription established')
            else:
                command(['electricalpowermeasurement', 'subscribe', 'active-power', 0, 2, 1, 1, '--keepSubscriptions', 1], 'Subscription established')
            wait(lambda: any(f['path'] == (1, 0x90, 8) and integer(f['body'], 'ActivePower') == 123000 for f in frames(client.text()[sensor_offset:]) if f['kind'] == 'Attribute'))
            check('sensor-only-subscription', True)
            if a.sensor_energy:
                def energy_reports(attr):
                    return [integer(f['body'], 'Energy') for f in frames(client.text()[sensor_offset:]) if f['kind'] == 'Attribute' and f['path'] == (1, 0x91, attr)]
                wait(lambda: energy_reports(1) and energy_reports(1)[-1] > initial_energy[0] and energy_reports(2))
                check('import-grows-export-history-unchanged', set(energy_reports(2)) == {2345000})
                events = [f for f in frames(client.text()[sensor_offset:]) if f['kind'] == 'Event' and f['path'] == (1, 0x91, 0)]
                check('energy-event-has-both-directions', bool(events) and all('EnergyImported:' in f['body'] and 'EnergyExported:' in f['body'] for f in events))
                saved_energy = sensor_registers()
            command(['subscriptions', 'shutdown-all'], 'Command: subscriptions shutdown-all')
            storage = client.storage; client.close(); client = None; stop()
            start(); client = Client(tool, paa, out, 'fresh-controller', storage, advertise=False)
            independent_power('restart')
            minimal_inventory(command(['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', 1, '0xffff,0xffff']))
            if a.sensor_energy:
                after_restart = sensor_registers()
                check('both-registers-retained-after-restart', after_restart[0] >= saved_energy[0] and after_restart[1] == saved_energy[1], {'before_mWh': saved_energy, 'after_mWh': after_restart})
            data = command(['operationalcredentials', 'read', 'current-fabric-index', 1, 0])
            index = integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex')
            command(['operationalcredentials', 'remove-fabric', index, 1, 0], r'statusCode: 0\b')
            node.wait(timeout=30); stop()
            report['result'] = 'PASS'
            return
        attrs = inventory(data, True, 0xfff1fc01, True, metered_switch=True, power_only=a.power_only)
        check('descriptor-and-whole-meter-preserved', bool(attrs))
        independent_power('initial')
        if a.power_only:
            sensor_offset = len(client.text())
            command(['electricalpowermeasurement', 'subscribe', 'active-power', 0, 2, 1, 6, '--keepSubscriptions', 1], 'Subscription established')
            wait(lambda: any(f['path'] == (6, 0x90, 8) and integer(f['body'], 'ActivePower') == 123000 for f in frames(client.text()[sensor_offset:]) if f['kind'] == 'Attribute'))
            check('independent-power-subscription', True)
        baseline = read_energy(); check('new-plug-energy-zero', baseline == 0)
        offset = len(client.text())
        command(['any', 'subscribe-all', '0x90,0x91,0x91', '8,1', '0', 0, 2, 1, '2,2,2', '--keepSubscriptions', 1], 'Subscription established')
        command(['onoff', 'on', 1, 2], r'Received Command Response Status')
        def powers():
            return [integer(f['body'], 'ActivePower') for f in frames(client.text()[offset:]) if f['kind'] == 'Attribute' and f['path'] == (2, 0x90, 8)]
        wait(lambda: 600000 in powers())
        time.sleep(4)
        on_energy = read_energy(); check('on-integrates-600W', on_energy > baseline)
        independent_power('plug-on')
        command(['onoff', 'off', 1, 2], r'Received Command Response Status')
        wait(lambda: powers() and powers()[-1] == 0)
        paused = read_energy(); time.sleep(3)
        check('off-freezes-import', read_energy() == paused)
        independent_power('plug-off')
        data = command(['electricalenergymeasurement', 'read', 'cumulative-energy-exported', 1, 2])
        check('no-invented-export', integer(next(f['body'] for f in frames(data) if f['path'] == (2, 0x91, 2)), 'Energy') == 0)
        events = [f for f in frames(client.text()[offset:]) if f['kind'] == 'Event' and f['path'] == (2, 0x91, 0)]
        check('energy-events-at-plug-endpoint', len(events) >= 2 and all('EnergyImported:' in f['body'] and 'EnergyExported:' in f['body'] for f in events))
        command(['subscriptions', 'shutdown-all'], 'Command: subscriptions shutdown-all')
        storage = client.storage; client.close(); client = None; stop()
        start(); client = Client(tool, paa, out, 'fresh-controller', storage, advertise=False)
        check('persistent-plug-register-after-fresh-CASE', read_energy() == paused, {'import_mWh': paused})
        independent_power('restart')
        data = command(['electricalpowermeasurement', 'read', 'active-power', 1, 2])
        check('restart-off-zero-power', integer(next(f['body'] for f in frames(data) if f['path'] == (2, 0x90, 8)), 'ActivePower') == 0)
        data = command(['operationalcredentials', 'read', 'current-fabric-index', 1, 0])
        index = integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex')
        command(['operationalcredentials', 'remove-fabric', index, 1, 0], r'statusCode: 0\b')
        node.wait(timeout=30); stop()
        report['result'] = 'PASS'
    finally:
        if client:
            client.close()
        if node is not None and node.poll() is None:
            node.terminate(); node.wait(timeout=30)
        for log in logs:
            log.close()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
