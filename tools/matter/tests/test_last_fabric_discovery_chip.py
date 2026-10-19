"""Last-fabric removal, wire discovery withdrawal and explicit host restart.

Disposable development state only. Run separately under Memcheck and sanitizers.
This is operator evidence, not an official CSA PASS. The CLI intentionally exits
after last-fabric reset; this fixture performs an explicit operator restart.
Use --same-controller for TC-DD-3.19 evidence, retaining the live commissioner
and its fabric credentials across removal and recommissioning.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time

from chip_tool_resources import Client
from test_mdns_linux import decode, query, read_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'chip-tool', 'payload-exe', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--interface', required=True, type=int)
    parser.add_argument('--valgrind', action='store_true')
    parser.add_argument('--same-controller', action='store_true')
    parser.add_argument('--qr-image', type=Path, help='Optional supplied QR bitmap, scanned with Pillow/zxing-cpp before each pairing')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'scope': __doc__, 'checks': [], 'node_sha256': hashlib.sha256(args.node.read_bytes()).hexdigest(),
              'same_controller': args.same_controller,
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    state = out / 'state.tlv'; nodes = []; clients = []; handles = []; packets = []
    lock = threading.Lock(); stopped = threading.Event()
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, args.interface)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    sock.bind(('::', 5353))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                    socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', args.interface))
    sock.settimeout(.1)

    def capture():
        while not stopped.is_set():
            try:
                data, _ = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                flags, records = decode(data)
            except (ValueError, IndexError, UnicodeError, struct.error):
                continue
            with lock:
                packets.append((time.monotonic(), flags, records))

    listener = threading.Thread(target=capture, daemon=True); listener.start()

    def check(name, passed, detail=None):
        report['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        if not passed:
            report['result'] = 'FAIL'
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        if not passed:
            raise AssertionError(name)

    def wait(predicate, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.05)
        raise TimeoutError('Condition timeout')

    def rows(since=0):
        with lock:
            return [row for stamp, flags, records in packets if stamp >= since and flags & 0x8000 for row in records]

    def lookup(owner, kind=255, seconds=1):
        start = time.monotonic()
        end = start + seconds
        while time.monotonic() < end:
            sock.sendto(query(owner, kind), ('ff02::fb', 5353, 0, args.interface))
            time.sleep(.2)
        return rows(start)

    def txt(owner):
        answer = None
        for name, kind, _, ttl, payload in lookup(owner, 16):
            if name != owner or kind != 16 or not ttl:
                continue
            fields = {}; pos = 0
            while pos < len(payload):
                length = payload[pos]; pos += 1
                key, value = payload[pos:pos + length].split(b'=', 1); pos += length
                fields[key.decode()] = value.decode()
            answer = fields
        return answer

    def start():
        boot = len(nodes) + 1
        log, err = out / f'node-{boot}.log', out / f'node-{boot}.err'
        streams = [log.open('w'), err.open('w')]; handles.extend(streams)
        argv = [str(args.node), '--interface', str(args.interface), '--port', '5584', '--seconds', '180',
                '--pin', '20202021', '--discriminator', '3912', '--credentials', str(args.credentials),
                '--state', str(state), '--three-phase', '--source-registers', '--meter-services', '--wifi-sim-connected']
        if args.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                    '--track-origins=yes', '--error-exitcode=99', '--log-file=' + str(out / f'memcheck-{boot}.log'), *argv]
        child = subprocess.Popen(argv, stdout=streams[0], stderr=streams[1], env=env)
        nodes.append((child, log, err))
        wait(lambda: child.poll() is not None or 'PUBLISHED' in log.read_text())
        check(f'published-{boot}', child.poll() is None and 'PUBLISHED' in log.read_text())
        instance, service = re.search(r'NODE instance=(\S+) service=(\S+)', log.read_text()).groups()
        owner = (instance + '.' + service).lower()
        check(f'fresh-basic-window-{boot}', (txt(owner) or {}).get('CM') == '1')
        return child, log, owner

    def command(client, argv, pattern):
        ok, text = client.command(argv, pattern, timeout=50 if argv[0] == 'pairing' else 15)
        if not ok:
            raise AssertionError('CHIP command failed: ' + ' '.join(map(str, argv[:3])))
        return text

    def commission(label, client=None):
        if client is None:
            client = Client(args.chip_tool, args.paa, out, label, advertise=False); clients.append(client)
        code = subprocess.check_output([str(args.payload_exe), '20202021', '3912', '65521', '32769'], text=True).strip()
        if args.qr_image:
            from PIL import Image
            import zxingcpp
            with Image.open(args.qr_image) as image:
                decoded = zxingcpp.read_barcode(image)
            check(label + '-scan-supplied-QR', decoded is not None and decoded.text == code)
            code = decoded.text
            report['supplied_qr_sha256'] = hashlib.sha256(args.qr_image.read_bytes()).hexdigest()
        text = command(client, ['pairing', 'code', 1, code, '--use-only-onnetwork-discovery', 1, '--timeout', 40],
                       'Device commissioning completed with success')
        check(label + '-attested-commissioning', "Successfully finished commissioning step 'AttestationVerification'" in text)
        if args.same_controller:
            check(label + '-commissioning-complete', "Successfully finished commissioning step 'SendComplete'" in text)
        text = command(client, ['operationalcredentials', 'read', 'commissioned-fabrics', 1, 0], 'CommissionedFabrics:')
        check(label + '-exactly-one-fabric', bool(re.search(r'CommissionedFabrics:\s*1\b', text)))
        return client

    def closed_window(owner, label):
        observed = None; end = time.monotonic() + 8
        while time.monotonic() < end and (observed or {}).get('CM') != '0':
            observed = txt(owner)
        check(label + '-commissioning-mode-zero', (observed or {}).get('CM') == '0')

    def discovered(owner, label):
        observed = txt(owner)
        report.setdefault('basic_discovery', {})[label] = observed
        check(label + '-discovery-fields', all((observed or {}).get(key) == value
              for key, value in [('D', '3912'), ('CM', '1')]), observed)

    try:
        child, log, initial_owner = start()
        if args.same_controller:
            discovered(initial_owner, 'first')
        client = commission('first-controller')
        if args.same_controller:
            closed_window(initial_owner, 'first')
        wait(lambda: 'FABRIC index=1 instance=' in log.read_text())
        old_instance = re.search(r'FABRIC index=1 instance=(\S+)', log.read_text())[1]
        old_owner = (old_instance + '._matter._tcp.local.').lower()
        # The host prints FABRIC when its separate mDNS publisher starts
        # probing, before it is ready to answer. Observe actual publication.
        before = []; end = time.monotonic() + 8
        while time.monotonic() < end and not any(name == old_owner and kind == 33 and ttl for name, kind, _, ttl, _ in before):
            before.extend(lookup(old_owner, seconds=.6))
        check('operational-record-present-before-removal', any(name == old_owner and kind == 33 and ttl for name, kind, _, ttl, _ in before),
              {'expected': old_owner, 'answers': [(name, kind, ttl) for name, kind, _, ttl, _ in before],
               'historical_operational': [(name, kind, ttl) for name, kind, _, ttl, _ in rows() if '._matter._tcp.' in name]})
        command(client, ['electricalpowermeasurement', 'subscribe', 'active-power', 0, 5, 1, 1], 'Subscription established')
        check('live-subscription-at-removal', child.poll() is None)
        removing = time.monotonic()
        text = command(client, ['operationalcredentials', 'remove-fabric', 1, 1, 0], r'NOCResponse:[\s\S]*?\}')
        check('remove-last-fabric-success-response', bool(re.search(r'statusCode:\s*0\b', text)) and bool(re.search(r'fabricIndex:\s*1\b', text)))
        check('reset-clean-exit', child.wait(timeout=30) == 0)
        check('reset-once', log.read_text().count('RESET last fabric removed') == 1)
        if args.same_controller:
            # The removed server cannot renew its old subscription. Explicitly
            # release that client object so its later timeout cannot be mistaken
            # for a failure of the next interactive pairing command.
            command(client, ['subscriptions', 'shutdown-all'], 'Command: subscriptions shutdown-all')
            check('controller-subscriptions-released-after-removal', True)
        wait(lambda: any(name == old_owner and ttl == 0 for name, _, _, ttl, _ in rows(removing)), seconds=3)
        check('operational-goodbye', True)
        quiet = lookup(old_owner, seconds=1.4)
        check('no-old-operational-replies-after-exit', not any(name == old_owner and ttl for name, _, _, ttl, _ in quiet))
        check('no-advertisements-from-stopped-host', txt(initial_owner) is None)
        reset_image = hashlib.sha256(state.read_bytes()).hexdigest()
        report['explicit_restart'] = {'reset_store_sha256': reset_image, 'store_deleted_by_fixture': False}
        second, second_log, second_owner = start()
        observed = txt(second_owner)
        report['post_restart_advertisement'] = observed
        subtype_rows = lookup('_cm._sub._matterc._udp.local.', 12)
        report['post_restart_CM_subtype_observed'] = any(kind == 12 and ttl and read_name(payload, 0)[0].lower() == second_owner for _, kind, _, ttl, payload in subtype_rows)
        # Step4's verification text literally asks for CM=0 without _CM. Preserve
        # this comparison separately; do not change the runtime to satisfy it.
        report['official_step4_literal_verification_matches'] = observed.get('CM') == '0' and not report['post_restart_CM_subtype_observed']
        check('old-operational-identity-not-restored', not any(name == old_owner and ttl for name, _, _, ttl, _ in lookup(old_owner)))
        if args.same_controller:
            discovered(second_owner, 'second')
        fresh = commission('same-controller' if args.same_controller else 'new-controller',
                           client if args.same_controller else None)
        if args.same_controller:
            closed_window(second_owner, 'second')
        wait(lambda: 'FABRIC index=1 instance=' in second_log.read_text())
        new_instance = re.search(r'FABRIC index=1 instance=(\S+)', second_log.read_text())[1]
        check('same-fabric-operational-identity' if args.same_controller else 'new-fabric-operational-identity',
              new_instance == old_instance if args.same_controller else new_instance != old_instance)
        if args.same_controller:
            ready = []; end = time.monotonic() + 8
            while time.monotonic() < end and not any(name == old_owner and kind == 33 and ttl for name, kind, _, ttl, _ in ready):
                ready.extend(lookup(old_owner, seconds=.6))
            check('same-fabric-operational-rediscovery', any(name == old_owner and kind == 33 and ttl for name, kind, _, ttl, _ in ready))
        for cluster, attribute, label, count in [('operationalcredentials', 'trusted-root-certificates', 'TrustedRootCertificates', 1),
                                                 ('accesscontrol', 'acl', 'ACL', 1),
                                                 ('groupkeymanagement', 'group-key-map', 'GroupKeyMap', 0)]:
            data = command(fresh, [cluster, 'read', attribute, 1, 0], '(?i)' + label + ':')
            check('fresh-' + attribute, bool(re.search(label + r':\s*' + str(count) + r'\b', data, re.I)))
        if args.same_controller:
            report['official_case'] = 'TC-DD-3.19'
            report['official_steps'] = {str(step): True for step in range(1, 6)}
        else:
            report['official_case'] = 'TC-OPCREDS-3.6'
            report['official_steps'] = {'1': True, '2': True, '3': True, '4': report['official_step4_literal_verification_matches']}
        report['result'] = 'PASS'
    except Exception:
        report['result'] = 'FAIL'
        raise
    finally:
        cleanup = []
        for client in clients:
            client.close()
        for boot, (child, _, err) in enumerate(nodes, 1):
            if child.poll() is None:
                child.terminate()
            try:
                clean = child.wait(timeout=30) == 0
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=5); clean = False
            cleanup.append((f'clean-stop-{boot}', clean))
            cleanup.append((f'empty-stderr-{boot}', not err.read_bytes()))
            if args.valgrind:
                path = out / f'memcheck-{boot}.log'
                memory = path.read_text() if path.exists() else ''
                cleanup.append((f'memcheck-{boot}', 'ERROR SUMMARY: 0 errors' in memory and 'in use at exit: 0 bytes in 0 blocks' in memory))
        stopped.set(); listener.join(timeout=2); sock.close()
        for handle in handles:
            handle.close()
        for name, passed in cleanup:
            check(name, passed)
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS independent last-fabric lifecycle:', len(report['checks']), 'checks')


if __name__ == '__main__':
    main()
