"""MP04 full x86 controller checks. Use a disposable --meter-services node.

This is an independent chip-tool oracle, not an official CSA test. It exercises
CASE, reporting and authorization; the separate CSA report records official runs.
"""
import argparse
import json
from pathlib import Path
import re
import time
from chip_tool_resources import Client
from chip_tool_energy_profile import frames, ids


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True); p.add_argument('--paa', required=True)
    p.add_argument('--output', required=True); p.add_argument('--discriminator', type=int, default=3847)
    a = p.parse_args(); out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    c = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, 'controller')
    checks = []

    def passed(name):
        checks.append(dict(name=name, passed=True)); (out/'results.json').write_text(json.dumps(checks, indent=2)+'\n')
        print('PASS '+name, flush=True)

    def command(args, pattern, timeout=20, failure=False):
        ok, data = c.command(args, pattern, timeout, failure)
        assert ok, (args, data[-2200:])
        return data

    def identify_values(data):
        return [int(m[1]) for m in re.finditer(r'IdentifyTime: (\d+)', data)]

    try:
        data = command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--country-code', 'PL', '--timeout', 60],
                       'Device commissioning completed with success', 65)
        assert "Successfully finished commissioning step 'AttestationVerification'" in data
        passed('attested-commissioning-with-TimeSync')
        data = command(['any', 'read-all', '0xffffffff,0xffffffff', '0xffffffff', '0xffffffff', 1, '0xffff,0xffff'], 'SuppressResponse = true', 40)
        (out/'inventory.log').write_text(data)
        attrs = {f['path']: f for f in frames(data) if f['kind']=='Attribute'}
        assert 0x38 in ids(attrs[0, 0x1d, 1]['body'], 'ServerList')
        assert {3, 0xb06} <= set(ids(attrs[1, 0x1d, 1]['body'], 'ServerList'))
        for ep in (1, 3, 4, 5): assert 0x38 not in ids(attrs[ep, 0x1d, 1]['body'], 'ServerList')
        data = command(['any', 'read-by-id', '0xb06', '0,1,2,3', 1, 1], 'SuppressResponse = true')
        (out/'identity.log').write_text(data)
        assert 'SIM-0001' in data and '1.0' in data and re.search(r'\bnull\b', data, re.I)
        passed('Descriptor-and-meter-identity-null-delivery')
        command(['identify', 'subscribe', 'identify-time', 0, 30, 1, 1], 'Subscription established')
        start = len(c.text())
        command(['identify', 'identify', 7, 1, 1], 'Received Command Response Status')
        time.sleep(2.3)
        values = identify_values(c.text()[start:]); assert values and all(x==7 for x in values), values
        command(['identify', 'read', 'identify-time', 1, 1], r'IdentifyTime: [45]\b')
        passed('countdown-readable-but-not-reported-every-tick')
        start = len(c.text())
        command(['identify', 'write', 'identify-time', 2, 1, 1], r'status = 0x00')
        end=time.monotonic()+5
        while time.monotonic()<end and 0 not in identify_values(c.text()[start:]): time.sleep(.1)
        values=identify_values(c.text()[start:]); assert 2 in values and 0 in values and 1 not in values, values
        (out/'identify.log').write_text(c.text()[start:])
        passed('write-rearms-and-expiry-reports-zero')
        command(['subscriptions', 'shutdown-all'], 'Command: subscriptions shutdown-all')
        utc = (time.time_ns()//1000)-946684800000000
        command(['timesynchronization', 'set-utctime', utc, 3, 1, 0], r'status = 0x00')
        first=command(['timesynchronization', 'read', 'utctime', 1, 0], r'UTCTime: (\d+)')
        x=int(re.search(r'UTCTime: (\d+)',first)[1]); time.sleep(.2)
        second=command(['timesynchronization', 'read', 'utctime', 1, 0], r'UTCTime: (\d+)')
        y=int(re.search(r'UTCTime: (\d+)',second)[1]); assert utc<=x<y<utc+10000000
        command(['timesynchronization', 'read', 'time-source', 1, 0], r'TimeSource: 2\b')
        command(['timesynchronization', 'set-utctime', utc, 5, 1, 0], r'CONSTRAINT_ERROR|ConstraintError|0x0*87\b', failure=True)
        passed('SetUTCTime-advances-Admin-source-and-rejects-invalid-granularity')
        command(['any', 'write-by-id', '0xb06', 2, '"changed"', 1, 1], r'UNSUPPORTED_WRITE|UnsupportedWrite|0x0*88\b', failure=True)
        command(['any', 'write-by-id', '0x38', 0, 1, 1, 0], r'UNSUPPORTED_WRITE|UnsupportedWrite|0x0*88\b', failure=True)
        passed('identity-and-UTC-attributes-read-only')
        # Keep Administer on the ACL so this disposable fabric can restore itself.
        acl=[dict(privilege=5,authMode=2,subjects=None,targets=[dict(cluster=31,endpoint=0,deviceType=None)]),
             dict(privilege=3,authMode=2,subjects=None,targets=None)]
        command(['accesscontrol','write','acl',json.dumps(acl),1,0], r'status = 0x00')
        command(['identify','write','identify-time',0,1,1],r'status = 0x00')
        command(['identify','identify',1,1,1],r'UNSUPPORTED_ACCESS|UnsupportedAccess|0x0*7e\b',failure=True)
        command(['timesynchronization','set-utctime',utc,3,1,0],r'UNSUPPORTED_ACCESS|UnsupportedAccess|0x0*7e\b',failure=True)
        command(['accesscontrol','write','acl',json.dumps([dict(privilege=5,authMode=2,subjects=None,targets=None)]),1,0],r'status = 0x00')
        passed('Operate-write-Manage-Identify-and-Administer-time-ACL')
    finally:
        c.close()


if __name__ == '__main__':
    main()
