"""Private IPv6 UDP observations for original manual TC-SC-2.1.

Unmodified chip-tool commissions two independent fabrics, opening the second
window over the first fabric's live CASE session. No packets are altered. Core1.6.1 checks
and literal original-procedure discrepancies are reported separately. This is
independent operator evidence, not an automatic CSA result. Keep output private.
"""
import argparse
import copy
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


def message(data):
    """Bounded wire reader, independent of the library's C decoders."""
    def uint(offset, width):
        if offset + width > len(data):
            raise ValueError('Truncated header')
        return int.from_bytes(data[offset:offset + width], 'little')

    flags = uint(0, 1); security = uint(3, 1); session = uint(1, 2)
    if flags & 0xf8 or flags & 3 == 3:
        raise ValueError('Invalid message flags')
    pos = 8; source = destination = None
    if flags & 4:
        source = uint(pos, 8); pos += 8
    width = {0: 0, 1: 8, 2: 2}[flags & 3]
    if width:
        destination = uint(pos, width); pos += width
    if security & 0x20:
        size = uint(pos, 2); pos += 2 + size
    if pos > len(data):
        raise ValueError('Truncated message header')
    result = {'flags': flags, 'security': security, 'session': session,
              'counter': uint(4, 4), 'source': source, 'destination': destination}
    if session:
        return result
    exchange_flags = uint(pos, 1)
    result.update(exchange_flags=exchange_flags, opcode=uint(pos + 1, 1),
                  exchange=uint(pos + 2, 2))
    pos += 4
    result['vendor'] = uint(pos, 2) if exchange_flags & 16 else 0
    if exchange_flags & 16:
        pos += 2
    result['protocol'] = uint(pos, 2); pos += 2
    if exchange_flags & 2:
        result['acknowledged_counter'] = uint(pos, 4); pos += 4
    if exchange_flags & 8:
        size = uint(pos, 2); pos += 2 + size
    if pos > len(data):
        raise ValueError('Truncated protocol header')
    result['payload'] = data[pos:]
    return result


def fields(data):
    """Typed PASE TLV subset: anonymous struct, ordered context fields only."""
    pos = 0

    def take(size):
        nonlocal pos
        if pos + size > len(data):
            raise ValueError('Truncated TLV')
        value = data[pos:pos + size]; pos += size
        return value

    def container(depth=0):
        if depth > 4:
            raise ValueError('Excessive TLV depth')
        result = {}; previous = -1
        while True:
            control = take(1)[0]
            if control == 0x18:
                return result
            if control >> 5 != 1:
                raise ValueError('Expected context field')
            tag = take(1)[0]; kind = control & 31
            if tag <= previous:
                raise ValueError('Duplicate/unordered field')
            previous = tag
            width = None
            if 4 <= kind <= 7:
                width = 1 << (kind & 3)
                value = int.from_bytes(take(width), 'little')
            elif kind in (8, 9):
                value = kind == 9
            elif 16 <= kind <= 19:
                width = 1 << (kind & 3)
                value = take(int.from_bytes(take(width), 'little'))
            elif kind == 21:
                value = container(depth + 1)
            else:
                raise ValueError('Unexpected PASE TLV type')
            result[tag] = {'kind': kind, 'width': width, 'value': value}

    if take(1) != b'\x15':
        raise ValueError('Expected anonymous structure')
    result = container()
    if pos != len(data):
        raise ValueError('Trailing TLV')
    return result


def validate(exchange):
    """Raise on a Core1.6.1 violation; return no randoms/key material."""
    assert [p['opcode'] for p in exchange] == [0x20, 0x21, 0x22, 0x23, 0x24, 0x40]
    ephemeral = exchange[0]['source']; identifier = exchange[0]['exchange']
    assert ephemeral
    for packet in exchange:
        initiator = packet['direction'] == 'initiator'
        assert packet['flags'] == (4 if initiator else 1)
        assert packet['session'] == packet['security'] == packet['protocol'] == packet['vendor'] == 0
        assert packet['exchange'] == identifier
        assert bool(packet['exchange_flags'] & 1) == initiator
        assert packet['source' if initiator else 'destination'] == ephemeral
        assert packet['exchange_flags'] & 4  # All observed PASE messages use MRP.
    docs = [fields(p['payload']) for p in exchange[:5]]

    def octets(doc, tag, minimum, maximum=None):
        field = doc[tag]; value = field['value']
        assert 16 <= field['kind'] <= 19 and isinstance(value, bytes)
        assert minimum <= len(value) <= (minimum if maximum is None else maximum)
        return value

    def integer(doc, tag, bits):
        field = doc[tag]; assert 4 <= field['kind'] <= 7
        # Core Appendix A.11.1/B.5.7: schema range is not an exact TLV width.
        assert 0 <= field['value'] < 1 << bits
        return field['value']

    def intervals(doc):
        if 5 not in doc:
            return
        assert doc[5]['kind'] == 21
        for tag, bits in [(1, 32), (2, 32), (3, 16)]:
            if tag in doc[5]['value']:
                integer(doc[5]['value'], tag, bits)

    request, response, p1, p2, p3 = docs
    initiator_random = octets(request, 1, 32)
    assert any(initiator_random) and integer(request, 2, 16)
    assert integer(request, 3, 16) == 0
    assert request[4]['kind'] in (8, 9)
    known = request[4]['value']; intervals(request)
    assert octets(response, 1, 32) == initiator_random
    responder_random = octets(response, 2, 32)
    assert any(responder_random) and responder_random != initiator_random
    assert integer(response, 3, 16); intervals(response)
    params = response.get(4)
    if known:
        assert params is None or (params['kind'] == 21 and not params['value'])
    else:
        assert params and params['kind'] == 21
        assert 1000 <= integer(params['value'], 1, 32) <= 100000
        octets(params['value'], 2, 16, 32)
    assert octets(p1, 1, 65)[0] == octets(p2, 1, 65)[0] == 4
    octets(p2, 2, 32); octets(p3, 1, 32)
    status = exchange[5]['payload']
    assert len(status) == 8 and struct.unpack('<HIH', status) == (0, 0, 0)
    return {'initiator_session_id': request[2]['value'], 'responder_session_id': response[3]['value'],
            'has_PBKDF_parameters': known, 'request_random_bytes': 32, 'response_random_bytes': 32,
            'PA_bytes': 65, 'PB_bytes': 65, 'CA_bytes': 32, 'CB_bytes': 32,
            'salt_bytes': None if known else len(params['value'][2]['value']),
            'same_exchange': True, 'Core_headers_and_reliable_flags': True, 'success_status': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--valgrind', action='store_true')
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'result': 'RUNNING', 'checks': [], 'exchanges': [],
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(args.node.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(args.chip_tool.read_bytes()).hexdigest()}
    packets = []; lock = threading.Lock(); stop = threading.Event(); failures = []
    proxies = []; threads = []; clients = []; child = None
    target = (args.ipv6, 5587, 0, args.interface)

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def check(name, passed):
        report['checks'].append({'name': name, 'status': 'PASS' if passed else 'FAIL'}); save()
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed:
            raise AssertionError(name)

    def forward(sock, lane):
        peer = None
        try:
            while not stop.is_set():
                try:
                    data, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                direction = 'responder' if address[1] == target[1] else 'initiator'
                if direction == 'initiator':
                    if peer is not None and peer != address:
                        raise ValueError('Multiple peers on isolated lane')
                    peer = address
                with lock:
                    packets.append({'lane': lane, 'direction': direction, 'data': data.hex()})
                sock.sendto(data, peer if direction == 'responder' else target)
        except Exception as error:
            if not stop.is_set():
                failures.append(type(error).__name__)

    def command(client, argv, pattern, timeout=55):
        ok, data = client.command(argv, pattern, timeout=timeout)
        check('command-' + '-'.join(map(str, argv[:2])), ok)
        return data

    try:
        argv = [str(args.node), '--interface', str(args.interface), '--port', str(target[1]),
                '--seconds', '300', '--pin', '20202021', '--discriminator', '3917',
                '--credentials', str(args.credentials), '--state', str(out / 'state.tlv'),
                '--three-phase', '--source-registers', '--meter-services', '--wifi-sim-connected']
        if args.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                    '--track-origins=yes', '--error-exitcode=99', '--log-file=' + str(out / 'memcheck.log'), *argv]
        with (out / 'node.log').open('w') as log, (out / 'node.err').open('w') as err:
            child = subprocess.Popen(argv, stdout=log, stderr=err, env=dict(os.environ,
                ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        end = time.monotonic() + 20
        while time.monotonic() < end and child.poll() is None and 'PUBLISHED' not in (out / 'node.log').read_text():
            time.sleep(.05)
        check('node-published', child.poll() is None and 'PUBLISHED' in (out / 'node.log').read_text())
        for lane in range(2):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            proxies.append(sock); sock.bind((args.ipv6, 0, 0, args.interface)); sock.settimeout(.1)
            worker = threading.Thread(target=forward, args=(sock, lane)); worker.start(); threads.append(worker)
            clients.append(Client(args.chip_tool, args.paa, out, 'controller-' + str(lane), advertise=False))
        address = args.ipv6 + '%' + str(args.interface)
        pin = 20202021; case_ids = []
        for lane, client in enumerate(clients):
            data = command(client, ['pairing', 'already-discovered', lane + 1, pin, address,
                           proxies[lane].getsockname()[1], '--timeout', 50], r'Device commissioning completed with success', 60)
            check('attestation-and-completion-' + str(lane), all("Successfully finished commissioning step '" + s + "'" in data
                  for s in ('AttestationVerification', 'SendComplete')))
            command(client, ['basicinformation', 'read', 'vendor-id', lane + 1, 0], r'VendorID:\s*65521\b')
            activated = re.findall(r'New secure session activated.*?LSID:\d+ PSID:(\d+)!', client.text())
            check('CASE-session-observed-' + str(lane), bool(activated) and 'Sent Sigma3 msg' in client.text())
            case_ids.append(int(activated[-1]))
            if lane == 0:
                opened = command(client, ['pairing', 'open-commissioning-window', 1, 1, 180, 1000, 3918],
                                 r'Manual pairing code: \[\d+\]')
                code = re.search(r'Manual pairing code: \[(\d+)\]', opened)[1]
                parsed = command(client, ['payload', 'parse-setup-payload', code], r'Passcode:\s*\d+')
                pin = int(re.search(r'Passcode:\s*(\d+)', parsed)[1])
        command(clients[0], ['basicinformation', 'read', 'vendor-id', 1, 0], r'VendorID:\s*65521\b')
        time.sleep(.5)
        with lock:
            captured = copy.deepcopy(packets)
        check('proxy-forwarding', not failures)
        groups = {}; encrypted = []
        for index, row in enumerate(captured):
            p = message(bytes.fromhex(row['data'])); p.update(direction=row['direction'], index=index)
            if p['session']:
                encrypted.append((row['lane'], p)); continue
            if p['protocol'] == p['vendor'] == 0 and p['opcode'] in (0x20, 0x21, 0x22, 0x23, 0x24, 0x40):
                group = groups.setdefault((row['lane'], p['exchange']), [])
                if not any((x['direction'], x['counter']) == (p['direction'], p['counter']) for x in group):
                    group.append(p)
        check('two-complete-PASE-exchanges', len(groups) == 2)
        sessions = []
        for (lane, exchange_id), group in groups.items():
            evidence = validate(group); sessions.append(evidence)
            evidence.update(lane=lane, exchange_id=exchange_id)
            relevant = [p for l, p in encrypted if l == lane and p['session'] == evidence['responder_session_id']
                        and p['direction'] == 'initiator']
            check('no-encrypted-data-before-PakeFinished-' + str(len(sessions)),
                  all(p['index'] > group[-1]['index'] for p in relevant))
            report['exchanges'].append(evidence)
        second = next(s for s in sessions if s['lane'] == 1)
        check('second-PASE-does-not-reuse-live-first-CASE-ID', second['responder_session_id'] != case_ids[0])
        report['live_first_CASE_session_id'] = case_ids[0]
        report['initiator_ID_limit'] = 'Each independent controller starts fresh; no wraparound/exhaustion proof.'
        check('encrypted-PASE-application-data-observed', any(p['direction'] == 'initiator' and
              p['session'] in {s['responder_session_id'] for s in sessions} for _, p in encrypted))
        randoms = [fields(g[0]['payload'])[1]['value'] for g in groups.values()]
        check('sampled-request-randoms-distinct', len(set(randoms)) == 2)
        first = next(iter(groups.values())); rejected = 0
        for mode in ('addressing', 'session', 'opcode', 'payload'):
            altered = copy.deepcopy(first)
            if mode == 'addressing':
                altered[0]['flags'] = 0
            elif mode == 'session':
                altered[0]['session'] = 1
            elif mode == 'opcode':
                altered[2]['opcode'] = 0x23
            else:
                altered[3]['payload'] = altered[3]['payload'][:-2]
            try:
                validate(altered)
            except (AssertionError, ValueError, KeyError):
                rejected += 1
        check('four-mutated-capture-oracle-controls-rejected', rejected == 4)
        report['literal_procedure_discrepancies'] = [
            {'step': 1, 'field': 'S/DSIZ', 'procedure': 'S=0,DSIZ=0', 'Core1.6.1': 'Initiator S=1,DSIZ=0', 'observed': 'S=1,DSIZ=0'},
            {'step': 1, 'field': 'hasPBKDFParameters', 'procedure': 'true means unknown; false means known', 'Core1.6.1': 'true means known; false requests parameters', 'observed': 'false; parameters returned'},
            {'step': 2, 'field': 'S/DSIZ', 'procedure': 'S=0,DSIZ=0', 'Core1.6.1': 'Responder S=0,DSIZ=1', 'observed': 'S=0,DSIZ=1'},
            {'steps': [1, 2, 3, 4, 5], 'field': 'octet string sizes', 'procedure': '32-bit random,16..32-bit salt,65-bit points,32-bit confirmations', 'Core1.6.1': '32-byte random,16..32-byte salt,65-byte points,32-byte confirmations', 'observed': 'Core byte lengths; no procedure source edited'},
            {'steps': [3, 4, 5], 'field': 'S/DSIZ', 'procedure': 'S=0,DSIZ=0', 'Core1.6.1': 'Initiator S=1,DSIZ=0; responder S=0,DSIZ=1', 'observed': 'Core addressing'}]
        report['Core_result'] = 'PASS'; report['literal_procedure_result'] = 'FAIL'
        report['result'] = 'PASS'  # Independent Core evidence only, not original manual acceptance.
    except Exception as error:
        report['result'] = 'FAIL'; report['error'] = str(error)
        raise
    finally:
        for client in reversed(clients):
            client.close()
        stop.set()
        for worker in threads:
            worker.join(timeout=2)
        for sock in proxies:
            sock.close()
        if child:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=25)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(); report['result'] = 'FAIL'
            report['node_exit'] = child.returncode
            if child.returncode or (out / 'node.err').read_bytes():
                report['result'] = 'FAIL'
        with lock:
            (out / 'private-packets.json').write_text(json.dumps(packets))
        if args.valgrind and (out / 'memcheck.log').exists():
            text = (out / 'memcheck.log').read_text()
            report['Memcheck'] = {'zero_errors': 'ERROR SUMMARY: 0 errors' in text,
                                  'zero_live': 'in use at exit: 0 bytes in 0 blocks' in text}
            if not all(report['Memcheck'].values()):
                report['result'] = 'FAIL'
        save()
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
