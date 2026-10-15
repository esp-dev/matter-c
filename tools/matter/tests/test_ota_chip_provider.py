"""OTA laboratory acceptance with the unmodified CHIP OTA Provider application.

busy-update observes TC-SU-2.1's two-minute Busy window before the next
announcement/query and a complete signed host-simulation update/restart.
update exercises the same download/apply/restart path without that timing
procedure, suitable for separate Memcheck and ASan/UBSan/LSan runs.
Neither mode installs executable firmware or is an automatic CSA test.
Requires Python cryptography, chip-tool and trusted development PAAs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from chip_tool_resources import ANSI, Client
from chip_tool_energy_profile import frames, integer


def image_fixture(directory):
    """Independent OpenSSL-backed signature; no private key is written to disk."""
    body = bytes((i * 17 + 3) % 256 for i in range(16387))
    key = ec.generate_private_key(ec.SECP256R1())
    manifest = b'WWOTA001' + struct.pack('<HHIQ', 0xfff1, 0x8001, 2, len(body)) + hashlib.sha256(body).digest()
    r, s = utils.decode_dss_signature(key.sign(manifest, ec.ECDSA(hashes.SHA256())))
    payload = manifest + r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + body
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    del key
    header = (b'\x15\x25\x00\xf1\xff\x25\x01\x01\x80\x24\x02\x02\x2c\x03\x02v2'
              + b'\x26\x04' + struct.pack('<I', len(payload))
              + b'\x24\x08\x01\x30\x09\x20' + hashlib.sha256(payload).digest() + b'\x18')
    image = struct.pack('<IQI', 0x1beef11e, 16 + len(header) + len(payload), len(header)) + header + payload
    for name, data in [('source.ota', image), ('public.sec1', public)]:
        with (directory / name).open('xb') as output:
            output.write(data)
    return {'format': 'Matter OTA header and WWOTA001 signed host simulation',
            'version': 2, 'image_bytes': len(image), 'image_sha256': hashlib.sha256(image).hexdigest(),
            'public_key_sha256': hashlib.sha256(public).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'provider', 'chip-tool', 'paa', 'credentials', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--mode', choices=('busy-update', 'update'), default='busy-update')
    p.add_argument('--valgrind', action='store_true')
    a = p.parse_args()
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    report = {'scope': 'CHIP Provider and C requestor, laboratory protocol/simulated restart; not certification',
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'mode': a.mode, 'valgrind': a.valgrind, 'checks': [], 'fixture': image_fixture(out),
              'binaries': {n: hashlib.sha256(Path(v).read_bytes()).hexdigest() for n, v in
                           [('requestor', a.exe), ('provider', a.provider), ('chip-tool', a.chip_tool)]}}
    provider = node = client = reader = None
    logs = []; phase = 0

    def check(name, ok, detail=None):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise AssertionError(name + ': ' + str(detail))

    def log(name):
        handle = (out / name).open('w'); logs.append(handle); return handle

    def node_text():
        return (out / f'node-{phase}.log').read_text(errors='replace')

    def provider_text():
        return ANSI.sub('', (out / 'provider.log').read_text(errors='replace'))

    def query_count():
        return provider_text().count('OTA Provider received QueryImage')

    def wait(test, timeout=60, allow_node_exit=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if test():
                return
            if provider is not None and provider.poll() is not None:
                raise AssertionError('provider exited')
            if node is not None and node.poll() is not None and not allow_node_exit:
                raise AssertionError('requestor exited: ' + node_text()[-600:])
            time.sleep(.05)
        raise AssertionError('OTA condition timed out')

    def start_node():
        nonlocal phase, node
        phase += 1
        argv = [a.exe, '--interface', str(a.interface), '--port', '5581', '--seconds', '900',
                '--discriminator', '3910', '--credentials', a.credentials, '--state', str(out / 'state.tlv'),
                '--three-phase', '--source-registers', '--meter-services',
                '--ota-file', str(out / 'download.ota'), '--ota-sim-key', str(out / 'public.sec1')]
        if a.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                    '--errors-for-leak-kinds=definite,indirect,possible', '--track-origins=yes',
                    '--error-exitcode=99', '--log-file=' + str(out / f'valgrind-{phase}.log'), *argv]
        node = subprocess.Popen(argv, stdout=log(f'node-{phase}.log'), stderr=log(f'node-{phase}.err'), env=env)
        wait(lambda: 'NODE instance=' in node_text())

    def command(c, argv, pattern=r'SuppressResponse = true', timeout=30):
        ok, data = c.command(argv, pattern, timeout)
        assert ok, (argv, data[-700:])
        return data

    def basic(c):
        data = command(c, ['any', 'read-by-id', '0x28', '2,4,9,7,6', 1, 0])
        attrs = {f['path'][2]: f['body'] for f in frames(data) if f['path'][:2] == (0, 0x28)}
        return {name: integer(attrs[identifier], name) for identifier, name in
                [(2, 'VendorID'), (4, 'ProductID'), (9, 'SoftwareVersion'), (7, 'HardwareVersion')]}

    def announce():
        command(client, ['otasoftwareupdaterequestor', 'announce-otaprovider', 2, 0xfff1, 0, 0, 1, 0], r'status = 0x00')

    try:
        provider = subprocess.Popen([a.provider, '--secured-device-port', '5561', '--discriminator', '3991',
                    '--passcode', '20202021', '--KVS', str(out / 'provider.kvs'),
                    '--filepath', str(out / 'source.ota'), '--queryImageStatus', 'busy' if a.mode == 'busy-update' else 'updateAvailable',
                    '--delayedQueryActionTimeSec', '150'], stdout=log('provider.log'), stderr=subprocess.STDOUT, env=env)
        wait(lambda: 'SetupQRCode' in provider_text() or 'SetupManualCode' in provider_text())
        start_node()
        client = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, 'controller')
        for identifier, discriminator in [(2, 3991), (1, 3910)]:
            data = command(client, ['pairing', 'onnetwork-long', identifier, 20202021, discriminator,
                                   '--country-code', 'PL', '--timeout', 45], r'Device commissioning completed with success', 65)
            check('commission-' + ('provider' if identifier == 2 else 'requestor'),
                  "Successfully finished commissioning step 'AttestationVerification'" in data)
        # Preserve the commissioner's Administer entry and grant only node 1
        # Operate on OTA Provider. A commissioned fabric alone grants no access.
        provider_acl = [dict(privilege=5, authMode=2, subjects=[112233], targets=None),
                        dict(privilege=3, authMode=2, subjects=[1],
                             targets=[dict(cluster=0x29, endpoint=0, deviceType=None)])]
        command(client, ['accesscontrol', 'write', 'acl', json.dumps(provider_acl), 2, 0], r'status = 0x00')
        check('provider-authorizes-requestor', True, 'CASE node 1, Operate, endpoint 0 cluster 0x29 only')
        identity = basic(client); report['basic_information'] = identity
        announce()
        wait(lambda: query_count() == 1)
        observed = time.monotonic()
        wait(lambda: 'RequestorCanConsent:' in provider_text())
        first = provider_text().split('OTA Provider received QueryImage', 1)[1]
        query_fields = {}
        for name in ('VendorID', 'ProductID', 'SoftwareVersion', 'HardwareVersion'):
            match = re.search(name + r':\s*(0x[0-9a-fA-F]+|\d+)', first)
            assert match, name
            query_fields[name] = int(match[1], 0) if match[1].startswith('0x') else int(match[1])
        # Inspect only the protocol list, not other numeric lines in the log.
        protocols = re.search(r'ProtocolsSupported:\s*\[\s*\n(.*?)\[ZCL\]\s+\]', first, re.S)
        protocol_ids = [int(x) for x in re.findall(r'\[ZCL\]\s+(\d+)\s*$', protocols[1], re.M)] if protocols else []
        has_bdx = 0 in protocol_ids
        consent = re.search(r'RequestorCanConsent:\s*(\d+)', first)
        report['query_fields'] = query_fields
        report['location'] = 'omitted (optional under Core 11.20.6.6.1)' if not re.search(r'\bLocation:', first) else 'present'
        check('query-image-fields', query_fields == identity and has_bdx and consent is not None and consent[1] == '0',
              {'identity': query_fields, 'bdx_synchronous': has_bdx, 'consent': consent[1] if consent else None})
        if a.mode == 'busy-update':
            wait(lambda: 'OTA_STATE state=3 reason=4' in node_text())
            announce()  # A repeated announcement must not bypass Busy's floor.
            while time.monotonic() - observed < 120.2:
                assert query_count() == 1, 'Busy retried within 120 seconds'
                assert node.poll() is None and provider.poll() is None, 'OTA process exited during Busy observation'
                time.sleep(.1)
            check('busy-single-query-for-120s', query_count() == 1, {'observed_seconds': time.monotonic() - observed})
            report['next_announcement_monotonic'] = time.monotonic()
            announce()
            wait(lambda: query_count() >= 2, 75, allow_node_exit=True)
            check('announcement-next-query', query_count() == 2,
                  {'seconds_from_first_observed': time.monotonic() - observed})
            report['provider_query_times'] = [float(x) for x in re.findall(
                r'^\[(\d+\.\d+)\].*OTA Provider received QueryImage', provider_text(), re.M)]
        wait(lambda: 'OTA_SIM_REBOOT' in node_text(), 120, allow_node_exit=True)
        check('signed-download-and-reboot', node.wait(timeout=30) == 0 and 'authenticated=1 installed=1' in node_text())
        check('download-matches-image', hashlib.sha256((out / 'download.ota').read_bytes()).hexdigest() == report['fixture']['image_sha256'])
        start_node()
        wait(lambda: 'OTA_NOTIFY_DONE' in node_text(), 90)
        check('notify-update-applied', 'OTA_NOTIFY_DONE success=1' in node_text())
        reader = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, 'fresh-reader', client.storage, advertise=False)
        restored = basic(reader)
        boot = command(reader, ['generaldiagnostics', 'read', 'boot-reason', 1, 0])
        check('fresh-case-after-restart', restored['SoftwareVersion'] == 2 and bool(re.search(r'BootReason: 5\b', boot)), restored)
        node.terminate(); check('clean-requestor-stop', node.wait(timeout=30) == 0)
        for i in range(1, phase + 1):
            assert not (out / f'node-{i}.err').read_text()
            if a.valgrind:
                text = (out / f'valgrind-{i}.log').read_text()
                assert 'ERROR SUMMARY: 0 errors' in text and 'in use at exit: 0 bytes in 0 blocks' in text
        check('memory-diagnostics-clean', True, 'both boots; Memcheck' if a.valgrind else 'both boot stderr logs empty')
        report['result'] = 'PASS'; report['restarts'] = phase - 1
        return 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        report['result'] = 'FAIL'; report['error'] = str(error); print('FAIL', error, flush=True)
        return 1
    finally:
        for c in (reader, client):
            if c is not None:
                c.close()
        for proc in (node, provider):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=20)
                except subprocess.TimeoutExpired:proc.kill(); proc.wait()
        for handle in logs:
            handle.close()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
