"""Optional host UI switch: actual CASE commands and decoded subscription updates."""
import re
import time
from chip_tool_energy_profile import frames


def run_switch(command, text, record, out):
    def check(name, ok):
        record('test-switch-' + name, bool(ok), 'endpoint 2, basic On/Off host simulation')
        if not ok:
            raise ValueError(name)

    def value(data):
        values = [f for f in frames(data) if f['kind'] == 'Attribute' and f['path'] == (2, 6, 0)]
        if not values:
            raise ValueError('missing OnOff report')
        v = values[-1]
        match = re.search(r'^OnOff: (TRUE|FALSE)$', v['body'], re.M)
        if not match or v['version'] is None:
            raise ValueError('invalid OnOff report')
        return match[1] == 'TRUE', v['version']

    start = len(text())
    try:
        ok, _ = command(['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        check('isolate', ok)
        time.sleep(.2)
        ok, data = command(['onoff', 'read', 'on-off', 1, 2], r'OnOff: (TRUE|FALSE)')
        state, version = value(data)
        check('boot-off', ok and not state)
        ok, data = command(['onoff', 'subscribe', 'on-off', 0, 3, 1, 2, '--keepSubscriptions', 0], r'Subscription established')
        check('subscribe', ok and value(data)[0] is False)
        for action, expected in [('on', True), ('on', True), ('toggle', False), ('off', False), ('toggle', True)]:
            offset = len(text())
            ok, _ = command(['onoff', action, 1, 2], r'Received Command Response Status for Endpoint=2 Cluster=0x0000_0006 Command=0x0000_000[012] Status=0x0\b')
            check('command-' + action, ok)
            if state == expected:
                # An unchanged attribute need not be repeated in a heartbeat.
                ok, data = command(['onoff', 'read', 'on-off', 1, 2], r'OnOff: (TRUE|FALSE)')
                check('idempotent-' + action, ok and value(data) == (state, version))
                continue
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    current, new_version = value(text()[offset:])
                    if current == expected:
                        break
                except ValueError:
                    pass
                time.sleep(.05)
            else:
                raise ValueError('missing subscription update/heartbeat after ' + action)
            check('report-' + action, new_version == ((version + (state != expected)) & 0xffffffff))
            state, version = current, new_version
        # Leave ON so the restart run also proves the documented volatile reset.
        return True
    except ValueError as error:
        record('test-switch-validation', False, str(error))
        return False
    finally:
        (out / 'test-switch.log').write_text(text()[start:])
