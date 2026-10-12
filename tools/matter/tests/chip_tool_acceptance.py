"""Bounded chip-tool acceptance against an already running x86 node (Linux/macOS).

Uses an unmodified chip-tool and a fresh controller store (or --restart-read).
Every check inspects
decoded reports, not just interactive-process exit status. No attestation bypass.
This is a smoke acceptance, NOT the CSA certification suite or full PICS check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from chip_tool_energy_profile import run_profile
from chip_tool_resources import Client
from chip_tool_switch import run_switch


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--vendor-name', default='Matter C', help='Expected build-time host VendorName')
    p.add_argument('--product-name', default='Matter C host simulation', help='Expected build-time host ProductName')
    p.add_argument('--paa', required=True, help='Directory of development PAA DER certificates')
    p.add_argument('--output', required=True, help='New directory for logs/results; must not already exist')
    p.add_argument('--discriminator', type=int, default=3840)
    p.add_argument('--pin', type=int, default=20202021)
    p.add_argument('--restart-read', help='Existing controller storage: cold discovery/CASE and full profile after DUT restart')
    p.add_argument('--ota-requestor', action='store_true', help='OTA defaults/announcement/ACL; disposable node, limits OTA to View')
    p.add_argument('--test-switch', action='store_true', help='Expect optional volatile On/Off UI endpoint 2')
    p.add_argument('--root-events', action='store_true', help='Also check mandatory Root events and ACL changes (disposable test node)')
    p.add_argument('--vid-verification', action='store_true', help='Exercise OPCREDS rev2 Set/Sign/Read on a disposable fabric')
    p.add_argument('--list-subscriptions', action='store_true', help='Subscribe Fabrics/NOCs, change VID and subscribe again through fresh CASE')
    p.add_argument('--selector-subscriptions', action='store_true', help='Subscribe whole OPCREDS/Basic clusters and verify priming-only DataVersionFilters')
    p.add_argument('--no-controller-advertising', action='store_true', help='For a colocated DUT: disable interactive server advertising, keep discovery and outgoing CASE')
    p.add_argument('--case-resumption', action='store_true', help='Expire local sessions twice in the same controller and require Sigma2Resume + Read')
    p.add_argument('--expect-case', choices=('either', 'full', 'resume'), default='either', help='Required handshake for fresh-process Read/Subscribe')
    a = p.parse_args()
    tool, paa, out = Path(a.chip_tool).resolve(), Path(a.paa).resolve(), Path(a.output).resolve()
    if not tool.is_file() or not paa.is_dir() or not list(paa.glob('*.der')):
        p.error('chip-tool executable and PAA DER directory are required')
    if a.restart_read and not Path(a.restart_read).is_dir():
        p.error('restart-read requires existing commissioned controller storage')
    out.mkdir(parents=True, exist_ok=False)
    storage = Path(a.restart_read).resolve() if a.restart_read else out / 'storage'
    if not a.restart_read:
        storage.mkdir()
    env = dict(os.environ, TMPDIR=str(out))
    # This option belongs to interactive start, not one-shot Read/Subscribe.
    controller_args = ['--advertise-operational', '0'] if a.no_controller_advertising else []
    report = {'tool': str(tool), 'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
              'scope': 'host smoke plus full electrical profile Read/Subscribe; not certification', 'interactive_controller_advertising': not a.no_controller_advertising, 'checks': []}
    logpath = out / 'interactive.log'
    transcript = []

    def record(name, passed, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)

    def case_mode(data):
        resumed = 'Received Sigma2Resume msg' in data
        full = 'Sent Sigma3 msg' in data
        if resumed == full:
            return None
        mode = 'resume' if resumed else 'full'
        return mode if a.expect_case in ('either', mode) else None

    def cold_read():
        # A new process has neither a cached address nor an active CASE session.
        argv = [str(tool), 'electricalpowermeasurement', 'read', 'active-power', '1', '1',
                '--storage-directory', str(storage), '--timeout', '15']
        (out / 'rediscovery-command.txt').write_text(shlex.join(argv) + '\n')
        with (out / 'rediscovery.log').open('w') as log:
            try:
                r = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=20)
                data = ANSI.sub('', (out / 'rediscovery.log').read_text(errors='replace'))
                ok = (r.returncode == 0 and case_mode(data) and ('Session was established' in data or 'Received Sigma2Resume msg' in data) and
                      re.search(r'ActivePower: (3600000|-1800000)\b', data) is not None)
            except subprocess.TimeoutExpired:
                ok = False
        record('restart-rediscovery' if a.restart_read else 'fresh-process-rediscovery', ok,
               'rediscovery.log; expected CASE=' + a.expect_case + '; decoded Read required, no address injected')
        return ok

    if a.restart_read:
        ok = cold_read()
        if ok and a.vid_verification:
            argv = [str(tool), 'operationalcredentials', 'read', 'fabrics', '1', '0',
                    '--storage-directory', str(storage), '--timeout', '15']
            (out / 'vid-restart-command.txt').write_text(shlex.join(argv) + '\n')
            with (out / 'vid-restart.log').open('w') as log:
                r = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=20)
            data = ANSI.sub('', (out / 'vid-restart.log').read_text(errors='replace'))
            ok = r.returncode == 0 and 'VendorID: 27138' in data and re.search(r'VIDVerificationStatement: (?:5A){85}\b', data) is not None
            record('vid-restart', ok, 'persisted VendorID and exact 85-byte statement after host restart')
        if ok and a.ota_requestor:
            argv = [str(tool), 'otasoftwareupdaterequestor', 'read', 'default-otaproviders', '1', '0',
                    '--storage-directory', str(storage), '--timeout', '15']
            with (out / 'ota-restart.log').open('w') as log:
                r = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=20)
            data = ANSI.sub('', (out / 'ota-restart.log').read_text(errors='replace'))
            ok = r.returncode == 0 and 'ProviderNodeID: 112233' in data and 'FabricIndex: 1' in data
            record('ota-restart', ok, 'default provider persisted; announcement did not replace it')
        # OTA acceptance deliberately removes Administer access to other
        # clusters. Its fabric cannot serve as the complete-inventory oracle.
        if ok and not a.ota_requestor:
            client = Client(tool, paa, out, 'restart-profile', source=storage, advertise=not a.no_controller_advertising)
            try:
                ok = not a.test_switch or run_switch(client.command, client.text, record, out)
                if ok:
                    ok = run_profile(client.command, client.text, record, out, a.test_switch)
                previous = storage.parent / 'energy-profile.json'
                if ok and previous.exists():
                    before = json.loads(previous.read_text())['subscription']
                    after = json.loads((out / 'energy-profile.json').read_text())['read']
                    ok = all(after[key][0] >= before[key][-1] for key in ('import_mWh', 'export_mWh'))
                    record('energy-persists-after-restart', ok, 'both cumulative registers at least the last values before restart')
            finally:
                client.close()
            ok = ok and client.child.returncode == 0
        return 0 if ok else 1

    with logpath.open('w') as log:
        child = subprocess.Popen([str(tool), 'interactive', 'start', '--storage-directory', str(storage),
                                  '--paa-trust-store-path', str(paa), *controller_args], stdin=subprocess.PIPE,
                                 stdout=log, stderr=subprocess.STDOUT, text=True, env=env)

        def text():
            return ANSI.sub('', logpath.read_text(errors='replace'))

        def send(args):
            line = shlex.join([str(x) for x in args])
            transcript.append(line)
            (out / 'commands.txt').write_text('\n'.join(transcript) + '\n')
            child.stdin.write(line + '\n')
            child.stdin.flush()

        def command(args, pattern, timeout=20, expected_failure=False):
            offset = len(text())
            send(args)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                segment = text()[offset:]
                if expected_failure and re.search(pattern, segment):
                    return True, segment
                if 'Run command failure' in segment or child.poll() is not None:
                    return False, segment
                if re.search(pattern, segment):
                    return True, segment
                time.sleep(.05)
            return False, text()[offset:]

        try:
            ok, data = command(['pairing', 'onnetwork-long', 1, a.pin, a.discriminator,
                                '--country-code', 'PL', '--timeout', 45],
                               r'Device commissioning completed with success', 50)
            ok = ok and "Successfully finished commissioning step 'AttestationVerification'" in data
            ok = ok and 'Received CommissioningComplete response, errorCode=0' in data
            record('commissioning', ok, 'mDNS + PASE + attestation + NOC + CASE + Complete; interactive.log')
            if not ok:
                return 1
            if a.case_resumption:
                for iteration in range(2):
                    ok, data = command(['sessionmanagement', 'expire-case-sessions', 1], r'Expiring all sessions for node')
                    record('expire-case-' + str(iteration+1), ok, 'local eviction without restarting controller')
                    if not ok:
                        return 1
                    ok, data = command(['electricalpowermeasurement', 'read', 'active-power', 1, 1],
                                       r'ActivePower: (3600000|-1800000)\b')
                    ok = ok and 'Received Sigma2Resume msg' in data and 'Sent Sigma3 msg' not in data
                    record('resumed-read-' + str(iteration+1), ok, 'Sigma2Resume and decoded secure Read; interactive.log')
                    if not ok:
                        return 1
            if a.vid_verification:
                cluster = 'operationalcredentials'
                nonce = 'hex:' + bytes(range(32)).hex()
                checks = [
                    ('vid-sign-plain', [cluster, 'sign-vidverification-request', 1, nonce, 1, 0], r'signature: [0-9A-F]{128}\b', False),
                    ('vid-empty-rejected', [cluster, 'set-vidverification-statement', 1, 0], r'status = 0x85', True),
                    ('vid-vendor-rejected', [cluster, 'set-vidverification-statement', 1, 0, '--VendorID', '0xfff5'], r'status = 0x87', True),
                    ('vid-length-rejected', [cluster, 'set-vidverification-statement', 1, 0, '--VIDVerificationStatement', 'hex:' + '5a'*84], r'status = 0x87', True),
                    ('vid-set', [cluster, 'set-vidverification-statement', 1, 0, '--VendorID', '0x6a01', '--VIDVerificationStatement', 'hex:' + '5a'*85], r'status = 0x00', False),
                    ('vid-read', [cluster, 'read', 'fabrics', 1, 0], r'VIDVerificationStatement: (?:5A){85}\b', False),
                    ('vid-sign-statement', [cluster, 'sign-vidverification-request', 1, nonce, 1, 0], r'signature: [0-9A-F]{128}\b', False),
                ]
                for name, args, pattern, failure in checks:
                    ok, data = command(args, pattern, expected_failure=failure)
                    if name.startswith('vid-sign'):
                        ok = ok and 'fabricIndex: 1' in data and 'fabricBindingVersion: 1' in data
                    if name == 'vid-read':
                        ok = ok and 'VendorID: 27137' in data
                    record(name, ok, pattern)
                    if not ok:
                        return 1
                ok, data = command([cluster, 'set-vidverification-statement', 1, 0, '--VendorID', '0x6a02'], r'status = 0x00')
                record('vid-update-vendor', ok, 'VendorID-only update preserves statement')
                if not ok:
                    return 1
                ok, data = command([cluster, 'read', 'fabrics', 1, 0], r'VIDVerificationStatement: (?:5A){85}\b')
                ok = ok and 'VendorID: 27138' in data
                record('vid-read-updated', ok, 'updated VID and unchanged exact statement')
                if not ok:
                    return 1
                # Keep the statement for the independent restart read.
            if a.list_subscriptions:
                cluster = 'operationalcredentials'
                for attr, pattern in [('fabrics', r'FabricIndex: 1\b'), ('nocs', r'Noc: [0-9A-F]+\b')]:
                    ok, data = command([cluster, 'subscribe', attr, 1, 3, 1, 0, '--keepSubscriptions', 1],
                                       r'Subscription established')
                    ok = ok and re.search(pattern, data) is not None
                    record(attr + '-subscribe', ok, 'decoded list and established CASE subscription')
                    if not ok:
                        return 1
                for vendor in (0x6a03, 0x6a02):
                    ok, data = command([cluster, 'set-vidverification-statement', 1, 0, '--VendorID', hex(vendor)],
                                       rf'VendorID: {vendor}\b')
                    if a.vid_verification:
                        ok = ok and re.search(r'VIDVerificationStatement: (?:5A){85}\b', data) is not None
                    record(f'fabrics-notify-{vendor}', ok, 'SetVID followed by decoded report on existing subscription; no Read command')
                    if not ok:
                        return 1
                send(['subscriptions', 'shutdown-all'])
            if a.selector_subscriptions:
                send(['subscriptions', 'shutdown-all'])
                ok, data = command(['operationalcredentials', 'subscribe-by-id', '0xffffffff', 2, 5, 1, 0],
                                   r'Subscription established')
                ok = ok and all(re.search(pattern, data) for pattern in
                                [r'Noc: [0-9A-F]+\b', r'Fabrics:', r'SupportedFabrics: 5\b', r'ClusterRevision: 2\b'])
                record('opcreds-wildcard-subscribe', ok, 'all OPCREDS attributes including lists and global metadata')
                if not ok:
                    return 1
                send(['subscriptions', 'shutdown-all'])
                ok, data = command(['operationalcredentials', 'read', 'fabrics', 1, 0], r'Fabrics:')
                versions = re.findall(r'DataVersion = (0x[0-9a-fA-F]+)', data)
                if not ok or not versions:
                    record('opcreds-version-read', False, 'missing cluster version in decoded Read')
                    return 1
                ok, data = command(['operationalcredentials', 'subscribe-by-id', '0xffffffff', 2, 5, 1, 0,
                                    '--data-version', versions[-1]], r'Subscription established')
                prime = data.split('Subscription established')[0]
                ok = ok and 'AttributeDataIB' not in prime and 'Fabrics:' not in prime
                record('opcreds-filtered-prime', ok, 'matching DataVersion suppresses initial data but establishes subscription')
                if not ok:
                    return 1
                for vendor in (0x6a04, 0x6a02):
                    ok, data = command(['operationalcredentials', 'set-vidverification-statement', 1, 0, '--VendorID', hex(vendor)],
                                       rf'VendorID: {vendor}\b')
                    record(f'opcreds-filtered-notify-{vendor}', ok, 'version-filtered attributes remain subscribed after priming')
                    if not ok:
                        return 1
                send(['subscriptions', 'shutdown-all'])
                ok, data = command(['basicinformation', 'subscribe-by-id', '0xffffffff', 2, 5, 1, 0],
                                   r'Subscription established')
                ok = ok and ('VendorName: ' + a.vendor_name) in data and ('ProductName: ' + a.product_name) in data
                record('basic-wildcard-text', ok, 'whole Basic Information cluster, decoded UTF8 values and chunk completion')
                if not ok:
                    return 1
                send(['subscriptions', 'shutdown-all'])
            if a.root_events:
                for name, cluster, event, pattern in [
                    ('startup-event', 'basicinformation', 'start-up', r'SoftwareVersion: 1\b'),
                    ('boot-event', 'generaldiagnostics', 'boot-reason', r'BootReason: 1\b'),
                    ('bootstrap-acl-event', 'accesscontrol', 'access-control-entry-changed', r'AdminPasscodeID: 0\b'),
                ]:
                    ok, data = command([cluster, 'read-event', event, 1, 0], pattern)
                    record(name, ok, pattern)
                    if not ok:
                        return 1
                    ok, data = command([cluster, 'subscribe-event', event, 1, 3, 1, 0,
                                        '--keepSubscriptions', 0, '--is-urgent', 'true'], r'Subscription established')
                    ok = ok and re.search(pattern, data) is not None
                    record(name + '-subscribe', ok, 'decoded prime event and established subscription')
                    if not ok:
                        return 1
                    if cluster != 'accesscontrol':
                        send(['subscriptions', 'shutdown-all'])
                # Keep the last ACL subscription active. Empty subjects grants all
                # CASE nodes on this disposable fabric and preserves our access.
                acl = json.dumps([{'privilege': 5, 'authMode': 2, 'subjects': None, 'targets': None}])
                ok, data = command(['accesscontrol', 'write', 'acl', acl, 1, 0], r'ChangeType: 0\b')
                ok = ok and re.search(r'AdminNodeID: \d+', data) is not None and 'LatestValue:' in data
                record('acl-change-subscribe', ok, 'CASE writer identity and Changed event delivered on existing subscription')
                if not ok:
                    return 1
                send(['subscriptions', 'shutdown-all'])
            if a.ota_requestor:
                cluster = 'otasoftwareupdaterequestor'
                provider = {'providerNodeID': 112233, 'endpoint': 0, 'fabricIndex': 5}
                for name, args, pattern, failure in [
                    ('ota-revision', [cluster, 'read', 'cluster-revision', 1, 0], r'ClusterRevision: 1\b', False),
                    ('ota-idle', [cluster, 'read', 'update-state', 1, 0], r'UpdateState: 1\b', False),
                    ('ota-progress', [cluster, 'read', 'update-state-progress', 1, 0], r'UpdateStateProgress: null', False),
                    ('ota-not-installable', [cluster, 'read', 'update-possible', 1, 0], r'UpdatePossible: FALSE', False),
                    ('ota-default-write', [cluster, 'write', 'default-otaproviders', json.dumps([provider]), 1, 0], r'status = 0x00', False),
                    ('ota-default-read', [cluster, 'read', 'default-otaproviders', 1, 0], r'FabricIndex: 1\b', False),
                    ('ota-default-duplicate', [cluster, 'write', 'default-otaproviders', json.dumps([provider,provider]), 1, 0], r'status = 0x87', True),
                    ('ota-announcement', [cluster, 'announce-otaprovider', 222333, 0x1234, 2, 1, 1, 0, '--MetadataForNode', 'hex:1718'], r'status = 0x00', False),
                    ('ota-metadata-invalid', [cluster, 'announce-otaprovider', 222333, 0x1234, 0, 1, 1, 0, '--MetadataForNode', 'hex:1518'], r'status = 0x85', True),
                    ('ota-default-preserved', [cluster, 'read', 'default-otaproviders', 1, 0], r'ProviderNodeID: 112233\b', False),
                    ('ota-querying-or-delayed', [cluster, 'read', 'update-state', 1, 0], r'UpdateState: [23]\b', False),
                ]:
                    ok, data = command(args, pattern, expected_failure=failure)
                    record(name, ok, pattern)
                    if not ok: return 1
                acl = json.dumps([
                    {'privilege': 1, 'authMode': 2, 'subjects': None, 'targets': None},
                    {'privilege': 5, 'authMode': 2, 'subjects': None, 'targets': [{'cluster': 0x3e, 'endpoint': 0, 'deviceType': None}]},
                ])
                ok, data = command(['accesscontrol', 'write', 'acl', acl, 1, 0], r'status = 0x00')
                record('ota-view-only-acl', ok, 'OTA View-only; preserve OPCREDS Administer for existing NOCs regression')
                if not ok: return 1
                for name, args in [
                    ('ota-invoke-denied', [cluster, 'announce-otaprovider', 222333, 0x1234, 0, 1, 1, 0]),
                    ('ota-write-denied', [cluster, 'write', 'default-otaproviders', '[]', 1, 0]),
                ]:
                    ok, data = command(args, r'status = 0x7e', expected_failure=True)
                    record(name, ok, 'View cannot Administer OTA')
                    if not ok: return 1
            reads = [
                ('root-revision', 'basicinformation', 'cluster-revision', 0, r'ClusterRevision: 6\b'),
                ('root-spec', 'basicinformation', 'specification-version', 0, r'SpecificationVersion: 17170688\b'),
                ('root-descriptor', 'descriptor', 'device-type-list', 0, r'DeviceType: 22\b'),
                ('sensor-descriptor', 'descriptor', 'device-type-list', 1, r'DeviceType: 1296\b'),
                ('topology', 'powertopology', 'feature-map', 1, r'FeatureMap: 2\b'),
                ('epm-feature', 'electricalpowermeasurement', 'feature-map', 1, r'FeatureMap: 6\b'),
                ('epm-power', 'electricalpowermeasurement', 'active-power', 1, r'ActivePower: (3600000|-1800000)\b'),
                ('eem-feature', 'electricalenergymeasurement', 'feature-map', 1, r'FeatureMap: 7\b'),
                ('eem-import', 'electricalenergymeasurement', 'cumulative-energy-imported', 1, r'Energy: \d+\b'),
                ('eem-export', 'electricalenergymeasurement', 'cumulative-energy-exported', 1, r'Energy: \d+\b'),
            ]
            for name, cluster, attr, ep, pattern in reads:
                ok, _ = command([cluster, 'read', attr, 1, ep], pattern)
                record(name, ok, pattern)
                if not ok:
                    return 1
            for name, cluster, attr, ep, value in [
                ('root-subscribe', 'basicinformation', 'software-version', 0, r'SoftwareVersion: 1\b'),
                ('epm-subscribe', 'electricalpowermeasurement', 'active-power', 1, r'ActivePower: (?:3600000|-1800000)\b'),
                ('eem-subscribe', 'electricalenergymeasurement', 'cumulative-energy-imported', 1, r'Energy: \d+\b'),
            ]:
                offset = len(text())
                ok, _ = command([cluster, 'subscribe', attr, 1, 3, 1, ep, '--keepSubscriptions', 0],
                                r'Subscription established')
                if ok:
                    time.sleep(7)
                segment = text()[offset:]
                values = re.findall(value, segment)
                ok = ok and len(values) >= 3 and 'Run command failure' not in segment
                record(name, ok, f'{len(values)} decoded values in prime + 7 second observation')
                if not ok:
                    return 1
            if a.test_switch and not run_switch(command, text, record, out):
                return 1
            if not a.ota_requestor and not run_profile(command, text, record, out, a.test_switch):
                return 1
        finally:
            if child.poll() is None:
                try:
                    child.stdin.write('quit()\n')
                    child.stdin.flush()
                    child.wait(timeout=10)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    child.kill()
                    child.wait()
            child.stdin.close()
            report['interactive_exit'] = child.returncode
            (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    cold_read()
    if a.list_subscriptions:
        for attr, pattern in [('fabrics', r'VendorID: 27138\b'), ('nocs', r'Noc: [0-9A-F]+\b')]:
            argv = [str(tool), 'operationalcredentials', 'subscribe', attr, '1', '3', '1', '0',
                    '--storage-directory', str(storage), '--timeout', '5']
            path = out / f'cold-subscribe-{attr}.log'
            (out / f'cold-subscribe-{attr}-command.txt').write_text(shlex.join(argv) + '\n')
            with path.open('w') as log:
                try:
                    r = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=12)
                    data = ANSI.sub('', path.read_text(errors='replace'))
                    ok = (r.returncode == 0 and case_mode(data) and 'Subscription established' in data
                          and re.search(pattern, data) is not None and 'Run command failure' not in data)
                except subprocess.TimeoutExpired:
                    ok = False
            record('fresh-case-subscribe-' + attr, ok, path.name + '; expected CASE=' + a.expect_case + '; discovery and decoded list')
    # A known gap is still a failing acceptance check, never a hidden PASS.
    return 0 if all(c['status'] == 'PASS' for c in report['checks']) and child.returncode == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
