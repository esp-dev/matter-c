"""IPv6 announcement/discovery evidence for manual TC-DD-2.1 on a private x86 node.

Run under Memcheck and separately with a sanitizer node. Raw discovery packets,
controller credentials and setup payloads must remain outside Git. This fixture
does not convert independent checks into an automatic CSA result.
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

from chip_tool_resources import Client, ANSI
from test_mdns_linux import decode, query, read_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'chip-tool', 'payload-exe', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--interface', required=True, type=int)
    parser.add_argument('--valgrind', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'checks': [], 'conformance_checks': [], 'observations': {}, 'result': 'RUNNING',
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(args.node.read_bytes()).hexdigest()}
    packets = []; lock = threading.Lock(); stopped = threading.Event()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, args.interface)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    sock.bind(('::', 5353))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                    socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', args.interface))
    sock.settimeout(.1)
    service = '_matterc._udp.local.'; meta = '_services._dns-sd._udp.local.'
    port, disc = 5585, 3913
    child = None; controller = None

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def check(name, passed, detail=None, conformance=False, fatal=True):
        report['conformance_checks' if conformance else 'checks'].append(
            {'name': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})
        if not passed:
            report['result'] = 'FAIL'
        save(); print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed and fatal:
            raise AssertionError(name)

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
                packets.append((time.monotonic(), flags, records, data.hex()))

    listener = threading.Thread(target=capture, daemon=True); listener.start()

    def rows(since=0):
        with lock:
            return [row for stamp, flags, records, _ in packets if stamp >= since and flags & 0x8000 for row in records]

    def lookup(owner, kind=12, seconds=1.2):
        start = time.monotonic(); end = start + seconds
        while time.monotonic() < end:
            sock.sendto(query(owner, kind), ('ff02::fb', 5353, 0, args.interface))
            time.sleep(.2)
        return rows(start)

    def fields(payload):
        result = {}; pos = 0
        while pos < len(payload):
            length = payload[pos]; pos += 1
            key, value = payload[pos:pos + length].decode('ascii').split('=', 1); pos += length
            if key in result:
                raise ValueError('Duplicate TXT key')
            result[key] = value
        return result

    def wait(predicate, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.05)
        raise TimeoutError('Observation timeout')

    def command(argv, pattern):
        ok, data = controller.command(argv, pattern, timeout=50 if argv[0] == 'pairing' else 15)
        check('command-' + '-'.join(map(str, argv[:2])), ok)
        return data

    def observe(label, mode, discriminator, expected_owner=None):
        owner = None; observed = None; end = time.monotonic() + 10
        while time.monotonic() < end and owner is None:
            for name, kind, _, ttl, payload in lookup(service):
                if kind == 16 and ttl:
                    f = fields(payload)
                    if f.get('CM') == str(mode) and f.get('D') == str(discriminator) and (expected_owner is None or name == expected_owner):
                        owner, observed = name, f
        check(label + '-TXT-mode-discriminator', owner is not None, observed)
        report['observations'][label] = {'TXT': observed, 'owner': owner}
        records = lookup(owner, 255)
        check(label + '-SRV', any(name == owner and kind == 33 and ttl and struct.unpack_from('!HHH', payload) == (0, 0, port)
              and read_name(payload, 6)[0].lower() == host for name, kind, _, ttl, payload in records))
        check(label + '-IPv6-addresses', {payload for name, kind, _, ttl, payload in records if name == host and kind == 28 and ttl} == ipv6)
        expected = {service, f'_l{discriminator}._sub.{service}', f'_s{discriminator >> 8}._sub.{service}'}
        if mode:
            expected.add('_cm._sub.' + service)
        records = lookup(meta)
        targets = {read_name(payload, 0)[0].lower() for name, kind, _, ttl, payload in records if name == meta and kind == 12 and ttl}
        own = {name for name in targets if name == service or name.endswith('._sub.' + service)}
        check(label + '-enumeration', expected <= own, sorted(own))
        for subtype in sorted(expected - {service}):
            records = lookup(subtype)
            check(label + '-subtype-' + subtype.split('.')[0], any(name == subtype and kind == 12 and ttl
                  and read_name(payload, 0)[0].lower() == owner for name, kind, _, ttl, payload in records))
        if not mode:
            check(label + '-no-CM-enumeration', '_cm._sub.' + service not in own)
            records = lookup('_cm._sub.' + service)
            check(label + '-no-CM-subtype', not any(name == '_cm._sub.' + service and kind == 12 and ttl
                  and read_name(payload, 0)[0].lower() == owner for name, kind, _, ttl, payload in records))
            check(label + '-PH-required-in-extended-discovery', 'PH' in observed,
                  'Core R1.6.1 4.3.1.11 requires PH when CM=0 is advertised.', conformance=True, fatal=False)
        return owner

    def chip_discover(label, owner, mode, discriminator):
        store = out / ('discover-' + label); store.mkdir()
        cmd = [str(args.chip_tool), 'discover', 'commissionables', '--discover-once', '0',
               '--storage-directory', str(store), '--paa-trust-store-path', str(args.paa)]
        with (out / ('discover-' + label + '.log')).open('w') as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
            try:
                # Unfiltered browsing may see other nodes. Inspect complete
                # Discovered node blocks, rather than accepting another peer.
                def found():
                    text = ANSI.sub('', (out / ('discover-' + label + '.log')).read_text(errors='replace'))
                    return any(re.search(r'Instance Name:\s*' + re.escape(owner.split('.')[0]) + r'\b', block, re.I)
                               and re.search(r'Long Discriminator:\s*' + str(discriminator) + r'\b', block)
                               and re.search(r'Commissioning Mode:\s*' + str(mode) + r'\b', block)
                               and re.search(r'Port:\s*' + str(port) + r'\b', block)
                               for block in re.split(r'Discovered (?:commissionable/commissioner )?node:', text)[1:])
                wait(lambda: found() or proc.poll() is not None, 12)
                check(label + '-unmodified-chip-tool-discovery', found())
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=5)

    log_path = out / 'node.log'; err_path = out / 'node.err'
    with log_path.open('w') as log, err_path.open('w') as err:
        try:
            iface = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show', 'dev', socket.if_indextoname(args.interface)]))[0]
            ipv6 = {socket.inet_pton(socket.AF_INET6, a['local']) for a in iface['addr_info'] if a['family'] == 'inet6'
                    and 'tentative' not in a.get('flags', [])}
            before = lookup(f'_l{disc}._sub.{service}')
            check('absent-before-manufacturer-start', not any(name == f'_l{disc}._sub.{service}' and kind == 12 and ttl
                  for name, kind, _, ttl, _ in before))
            argv = [str(args.node), '--interface', str(args.interface), '--port', str(port), '--seconds', '180',
                    '--pin', '20202021', '--discriminator', str(disc), '--credentials', str(args.credentials),
                    '--state', str(out / 'state.tlv'), '--three-phase', '--source-registers', '--meter-services', '--wifi-sim-connected']
            if args.valgrind:
                argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                        '--track-origins=yes', '--error-exitcode=99', '--log-file=' + str(out / 'memcheck.log'), *argv]
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            start = time.monotonic(); child = subprocess.Popen(argv, stdout=log, stderr=err, env=env)
            wait(lambda: child.poll() is not None or 'PUBLISHED' in log_path.read_text())
            check('published', child.poll() is None and 'PUBLISHED' in log_path.read_text())
            instance, service_name, raw_host = re.search(r'NODE instance=(\S+) service=(\S+) host=(\S+)', log_path.read_text()).groups()
            check('instance-and-host-format', bool(re.fullmatch(r'[0-9A-F]{16}', instance))
                  and bool(re.fullmatch(r'[0-9A-F]{12}\.local\.', raw_host)) and service_name.lower() == service)
            host = raw_host.lower(); initial = (instance + '.' + service).lower()
            wait(lambda: any(name == service and kind == 12 and ttl and read_name(payload, 0)[0].lower() == initial
                             for name, kind, _, ttl, payload in rows(start)))
            check('unsolicited-announcement-before-post-start-queries', True)
            observe('basic', 1, disc, initial); chip_discover('basic', initial, 1, disc)
            controller = Client(args.chip_tool, args.paa, out, 'controller', advertise=False)
            code = subprocess.check_output([str(args.payload_exe), '20202021', str(disc), '65521', '32769'], text=True).strip()
            data = command(['pairing', 'code', 1, code, '--use-only-onnetwork-discovery', 1, '--timeout', 40], 'Device commissioning completed with success')
            check('attestation-and-SendComplete', all("Successfully finished commissioning step '" + step + "'" in data
                  for step in ['AttestationVerification', 'SendComplete']))
            closed = observe('closed', 0, disc, initial); chip_discover('closed', closed, 0, disc)
            opened = time.monotonic()
            command(['pairing', 'open-commissioning-window', 1, 1, 180, 1000, disc + 1], r'Manual pairing code: \[\d+\]')
            enhanced = observe('enhanced', 2, disc + 1); chip_discover('enhanced', enhanced, 2, disc + 1)
            check('new-instance-on-entering-commissioning', enhanced != initial)
            check('old-instance-withdrawn-on-reopen', any(name == initial and ttl == 0 for name, _, _, ttl, _ in rows(opened)))
            report['result'] = 'FAIL' if any(c['status'] == 'FAIL' for c in report['conformance_checks']) else 'PASS'
        except Exception as exc:
            report['result'] = 'FAIL'; report['error'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            if controller:
                controller.close()
            if child:
                if child.poll() is None:
                    child.terminate()
                try:
                    clean = child.wait(timeout=30) == 0
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5); clean = False
                check('clean-stop', clean, fatal=False)
                check('empty-host-stderr', not err_path.read_bytes(), fatal=False)
                if args.valgrind:
                    memory = (out / 'memcheck.log').read_text()
                    check('memcheck', 'ERROR SUMMARY: 0 errors' in memory and 'in use at exit: 0 bytes in 0 blocks' in memory, fatal=False)
            stopped.set(); listener.join(timeout=2); sock.close()
            with lock:
                (out / 'packets.json').write_text(json.dumps([{'time': t, 'hex': data} for t, _, _, data in packets]))
            save()
    print(report['result'], len(report['checks']), 'functional checks,', len(report['conformance_checks']), 'conformance checks')
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
