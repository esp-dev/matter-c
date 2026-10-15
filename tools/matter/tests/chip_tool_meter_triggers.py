"""CSA17 local regression: MTRID change/reset triggers on a disposable node.

Not an official CSA test. The DUT is matter-node --three-phase --source-registers
--meter-services [--test-event-key ...]. Modes:
  --mode run:      valid SET/CLEAR, wrong/zero/short key, unknown event, reports;
  --mode disabled: key absent on DUT, TestEventTriggersEnabled false and rejects;
  --mode restart:  after a run, restart without the key: identity is base,
                   TestEventTriggersEnabled false and the test identity never persisted.
Use a fresh --output per mode. Requires the same unmodified chip-tool/PAA.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from chip_tool_resources import Client

MTRID_SET = 0x0B06000000000000
MTRID_CLEAR = 0x0B06000000000001
KEY = '000102030405060708090a0b0c0d0e0f'  # Public laboratory fixture key only.


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--discriminator', type=int, default=3844)
    p.add_argument('--mode', choices=('run', 'disabled', 'restart'), required=True)
    p.add_argument('--previous', help='Previous controller output for CASE after DUT restart')
    p.add_argument('--leave-set', action='store_true', help='Leave fake identity active for restart checks')
    p.add_argument('--remove-fabric', action='store_true', help='Remove last fabric while fake identity is active')
    a = p.parse_args()
    tool, paa = Path(a.chip_tool).resolve(), Path(a.paa).resolve()
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    if not tool.is_file() or not list(paa.glob('*.der')):
        p.error('chip-tool and development PAA required')
    report = {'scope': 'CSA17 MTRID trigger regression; not certification',
              'mode': a.mode, 'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(), 'checks': []}
    previous = Path(a.previous).resolve() if a.previous else None
    c = Client(tool, paa, out, 'controller', previous/'controller'/'storage' if previous else None)
    reader = None

    def check(name, ok, detail=None):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name)

    def command(args, pattern, timeout=20, failure=False):
        offset = len(c.text())
        ok, _ = c.command(args, pattern, timeout, failure)
        return ok, c.text()[offset:]

    def trigger(node, event, key_hex=KEY, expected=None):
        argv = ['generaldiagnostics', 'test-event-trigger', 'hex:'+key_hex, event, node, 0]
        return command(argv, expected or r'status = 0x00', 30, failure=expected is not None)

    def enabled(node):
        ok, data = command(['generaldiagnostics', 'read', 'test-event-triggers-enabled', node, 0],
                          r'TestEventTriggersEnabled: (?:TRUE|true|1|FALSE|false|0)\b')
        assert ok, data[-800:]
        return bool(re.search(r'TestEventTriggersEnabled: (?:TRUE|true|1)\b', data))

    def identity(node):
        # This process has no subscriptions: don't mix reports with readback.
        ok, data = reader.command(['any', 'read-by-id', '0xb06', '0,1,2,3', node, 1], r'SuppressResponse = true')
        from chip_tool_energy_profile import frames
        attrs = {f['path'][2]: f['body'] for f in frames(data) if f['kind'] == 'Attribute' and f['path'][:2] == (1, 0xb06)}
        assert set(attrs) == {0, 1, 2, 3}, attrs.keys()
        values = {}
        for identifier, name in ((0, 'MeterType'), (1, 'PointOfDelivery'), (2, 'MeterSerialNumber'), (3, 'ProtocolVersion')):
            match = re.search(r'^' + name + r': (.*)$', attrs[identifier], re.M)
            values[name] = None if match is None else match[1].strip()
        return values

    base = {'MeterType': '2', 'PointOfDelivery': 'null', 'MeterSerialNumber': 'SIM-0001', 'ProtocolVersion': '1.0'}

    def await_reports(offset, expected):
        from chip_tool_energy_profile import frames
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            reported = {f['path'][2]: f for f in frames(c.text()[offset:])
                        if f['kind'] == 'Attribute' and f['path'][:2] == (1, 0xb06)}
            if all(i in reported and re.search(r'^'+name+': '+re.escape(value)+r'$', reported[i]['body'], re.M)
                   for i, (name, value) in enumerate(expected.items())):
                return reported
            time.sleep(.1)
        raise AssertionError('Missing subscription reports: '+str(expected))

    try:
        if not previous:
            ok, data = command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL', '--timeout', 45],
                               r'Device commissioning completed with success', 65)
            check('commission', ok and "Successfully finished commissioning step 'AttestationVerification'" in data)
        reader = Client(tool, paa, out, 'identity-reader', c.storage, advertise=False)
        check('test-event-triggers-enabled-state', enabled(1) == (a.mode == 'run'), a.mode)
        if a.mode == 'disabled':
            ok, _ = trigger(1, MTRID_SET, expected=r'status = 0x0*87 \(CONSTRAINT_ERROR\)')
            check('disabled-trigger-rejected', ok)
            check('identity-unchanged', identity(1) == base)
        elif a.mode == 'restart':
            check('identity-base-after-restart', identity(1) == base,
                  'test identity must not survive restart')
            ok, _ = trigger(1, MTRID_SET, expected=r'status = 0x0*87 \(CONSTRAINT_ERROR\)')
            check('restart-triggers-disabled', ok, 'restart without --test-event-key must reject')
        else:
            ok, _ = trigger(1, MTRID_SET, 'ff'*16, expected=r'status = 0x0*87 \(CONSTRAINT_ERROR\)')
            check('wrong-key-rejected', ok)
            ok, _ = trigger(1, MTRID_SET, '00'*16, expected=r'status = 0x0*87 \(CONSTRAINT_ERROR\)')
            check('zero-key-rejected', ok)
            ok, _ = trigger(1, MTRID_SET, '000102030405060708090a0b0c0d0e', expected=r'status = 0x0*87 \(CONSTRAINT_ERROR\)')
            check('short-key-rejected', ok)
            ok, _ = trigger(1, MTRID_SET+2, expected=r'status = 0x0*85 \(INVALID_COMMAND\)')
            check('unknown-event-rejected', ok)
            check('identity-base-before-set', identity(1) == base)
            ok, _ = command(['meteridentification', 'subscribe-by-id', '0xffffffff', 0, 10, 1, 1,
                             '--keepSubscriptions', 1], 'Subscription established')
            check('subscription-established', ok)
            # The host refreshes unrelated energy measurements every second.
            # They must not publish unchanged identification before SET.
            offset = len(c.text())
            time.sleep(2)
            from chip_tool_energy_profile import frames
            unchanged = [f['path'][2] for f in frames(c.text()[offset:])
                         if f['kind'] == 'Attribute' and f['path'][:2] == (1, 0xb06)
                         and f['path'][2] in range(4)]
            check('unrelated-samples-do-not-report-identity', not unchanged, unchanged)
            offset = len(c.text())
            ok, _ = trigger(1, MTRID_SET)
            check('set-accepted', ok)
            changed_values = dict(zip(base, ('0', 'CSA17-POD', 'CSA17-00000042', '9.9')))
            set_reports = await_reports(offset, changed_values)
            check('subscription-reported-all-four-changes', True)
            changed = identity(1)
            report['changed'] = changed
            check('set-changed-all-attributes',
                  all(changed[k] != base[k] for k in base) and changed['MeterType'] == '0'
                  and changed['PointOfDelivery'] == 'CSA17-POD' and changed['MeterSerialNumber'] == 'CSA17-00000042'
                  and changed['ProtocolVersion'] == '9.9', changed)
            offset = len(c.text())
            ok, _ = trigger(1, MTRID_CLEAR)
            check('clear-accepted', ok)
            clear_reports = await_reports(offset, base)
            check('subscription-reported-all-four-restored-values',
                  all(set_reports[i]['version'] != clear_reports[i]['version'] for i in range(4)))
            check('clear-restored-base', identity(1) == base)
            if a.leave_set or a.remove_fabric:
                offset = len(c.text())
                ok, _ = trigger(1, MTRID_SET)
                check('set-active-before-restart-or-reset', ok)
                await_reports(offset, changed_values)
                check('active-identity-confirmed', identity(1) == changed_values)
            command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
            if a.remove_fabric:
                ok, data = command(['operationalcredentials', 'read', 'current-fabric-index', 1, 0], r'CurrentFabricIndex:')
                assert ok
                fabric = int(re.search(r'CurrentFabricIndex: (\d+)', data)[1])
                ok, _ = command(['operationalcredentials', 'remove-fabric', fabric, 1, 0], r'statusCode: 0\b')
                check('last-fabric-removed-with-test-active', ok)
        return 0
    finally:
        if reader is not None:
            reader.close()
        c.close()


if __name__ == '__main__':
    raise SystemExit(main())
