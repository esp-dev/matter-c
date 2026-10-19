"""Private IPv6 UDP observations for original manual TC-SC-2.1.

Unmodified chip-tool commissions two independent fabrics, opening the second
window over the first fabric's live CASE session. No packets are altered. Core1.6.1 checks
and literal original-procedure discrepancies are reported separately. This is
independent operator evidence, not an automatic CSA result. --tamper-pase also
records TC-SC-2.2 bidirectional traffic: alter the first encrypted request and
response MIC, then release the original packets after a real quiet interval.
--pase-errors records TC-SC-2.3 invalid passcodeID/cA and terminal exchanges.
Keep output private.
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


def validate(exchange, success=True, allow_missing_failure_status=False):
    """Raise on a Core1.6.1 violation; return no randoms/key material."""
    status_present = exchange[-1]['opcode'] == 0x40
    assert status_present or (not success and allow_missing_failure_status)
    assert [p['opcode'] for p in exchange] == [0x20, 0x21, 0x22, 0x23, 0x24] + ([0x40] if status_present else [])
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
    if status_present:
        status = exchange[5]['payload']
        assert len(status) == 8 and struct.unpack('<HIH', status) == ((0, 0, 0) if success else (1, 0, 2))
    return {'initiator_session_id': request[2]['value'], 'responder_session_id': response[3]['value'],
            'has_PBKDF_parameters': known, 'request_random_bytes': 32, 'response_random_bytes': 32,
            'PA_bytes': 65, 'PB_bytes': 65, 'CA_bytes': 32, 'CB_bytes': 32,
            'salt_bytes': None if known else len(params['value'][2]['value']),
            'same_exchange': True, 'Core_headers_and_reliable_flags': True,
            'status_present': status_present, 'success_status': success}


def corrupt_pase_field(packet, mode):
    """Change only passcodeID0 to1, or one confirmation bit; keep TLV valid."""
    header = message(packet); payload = header['payload']; doc = fields(payload)
    wanted = 3 if mode == 'passcodeID' else 1
    assert header['opcode'] == (0x20 if mode == 'passcodeID' else 0x24)
    if mode == 'passcodeID':
        assert doc[wanted]['value'] == 0 and 4 <= doc[wanted]['kind'] <= 7
    else:
        assert isinstance(doc[wanted]['value'], bytes) and len(doc[wanted]['value']) == 32
    pos = 1
    while pos < len(payload):
        control, tag = payload[pos:pos + 2]; kind = control & 31; pos += 2
        assert control >> 5 == 1
        if 4 <= kind <= 7:
            width = 1 << (kind & 3); start = pos; pos += width
        elif 16 <= kind <= 19:
            width = 1 << (kind & 3)
            size = int.from_bytes(payload[pos:pos + width], 'little'); pos += width
            start = pos; pos += size
        else:
            raise ValueError('Unexpected field before mutation')
        if tag == wanted:
            offset = len(packet) - len(payload) + start
            return packet[:offset] + bytes([packet[offset] ^ 1]) + packet[offset + 1:]
    raise ValueError('Missing mutation field')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--valgrind', action='store_true')
    parser.add_argument('--tamper-pase', action='store_true', help='TC-SC-2.2: corrupt one MIC in each direction, then release originals')
    parser.add_argument('--pase-errors', action='store_true', help='TC-SC-2.3: invalid passcodeID/cA, terminal probes, then valid commissioning')
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    if args.tamper_pase and args.pase_errors:
        parser.error('Choose one fault-injection mode')
    report = {'result': 'RUNNING', 'checks': [], 'exchanges': [],
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(args.node.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(args.chip_tool.read_bytes()).hexdigest()}
    packets = []; lock = threading.Lock(); stop = threading.Event(); failures = []
    proxies = []; threads = []; clients = []; child = None
    tamper = []; quiet_seconds = .6
    error_case = [None]; failed_exchanges = set()
    target = (args.ipv6, 5587, 0, args.interface)

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def check(name, passed, conformance=False):
        report.setdefault('conformance_checks' if conformance else 'checks', []).append(
            {'name': name, 'status': 'PASS' if passed else 'FAIL'}); save()
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed and not conformance:
            raise AssertionError(name)

    def forward(sock, lane):
        peer = None; gate = None; changed = set(); request_counter = None
        try:
            while not stop.is_set():
                if gate and time.monotonic() >= gate['deadline']:
                    sock.sendto(gate['original'], gate['target'])
                    for held in dict.fromkeys(gate['held']):
                        if held != gate['original']:
                            sock.sendto(held, gate['target'])
                    gate['evidence']['original_released'] = True
                    gate['evidence']['quiet_elapsed_seconds'] = time.monotonic() - gate['started']
                    gate = None
                try:
                    data, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                direction = 'responder' if address[1] == target[1] else 'initiator'
                if direction == 'initiator':
                    if peer is not None and peer != address:
                        raise ValueError('Multiple peers on isolated lane')
                    peer = address
                row = {'lane': lane, 'direction': direction, 'data': data.hex()}
                if args.pase_errors and lane >= 2 and error_case[0]:
                    mode = error_case[0]; header = message(data); row['negative_case'] = mode
                    if direction == 'initiator' and header.get('opcode') == (0x20 if mode == 'passcodeID' else 0x24):
                        data = corrupt_pase_field(data, mode); row['forwarded_data'] = data.hex()
                with lock:
                    packets.append(row)
                if args.tamper_pase and lane == 0:
                    header = message(data)
                    if header['session']:
                        if direction == 'initiator' and request_counter is None:
                            request_counter = header['counter']
                        if gate:
                            if direction == gate['direction']:
                                gate['held'].append(data)
                                continue
                            if gate['direction'] == 'initiator' or header['counter'] != request_counter:
                                gate['evidence']['unexpected_peer_progress'] = True
                        if direction not in changed and gate is None:
                            changed.add(direction)
                            damaged = data[:-1] + bytes([data[-1] ^ 1])
                            evidence = {'direction': direction, 'session_id': header['session'],
                                'counter': header['counter'], 'MIC_only_one_bit_changed': True,
                                'original_sha256': hashlib.sha256(data).hexdigest(),
                                'damaged_sha256': hashlib.sha256(damaged).hexdigest(),
                                'original_released': False, 'unexpected_peer_progress': False}
                            tamper.append(evidence)
                            destination = peer if direction == 'responder' else target
                            sock.sendto(damaged, destination)
                            now = time.monotonic()
                            gate = {'original': data, 'target': destination, 'direction': direction,
                                    'held': [], 'started': now, 'deadline': now + quiet_seconds, 'evidence': evidence}
                            continue
                sock.sendto(data, peer if direction == 'responder' else target)
        except Exception as error:
            if not stop.is_set():
                failures.append(type(error).__name__)

    def command(client, argv, pattern, timeout=55):
        ok, data = client.command(argv, pattern, timeout=timeout)
        check('command-' + '-'.join(map(str, argv[:2])), ok)
        return data

    def create_client(name):
        lane = len(proxies)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        proxies.append(sock); sock.bind((args.ipv6, 0, 0, args.interface)); sock.settimeout(.1)
        worker = threading.Thread(target=forward, args=(sock, lane)); worker.start(); threads.append(worker)
        client = Client(args.chip_tool, args.paa, out, name, advertise=False)
        clients.append(client)
        return client, lane

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
            create_client('controller-' + str(lane))
        address = args.ipv6 + '%' + str(args.interface)
        if args.pase_errors:
            negative = []; late_probes = []
            for index, mode in enumerate(('passcodeID', 'cA')):
                negative_client, negative_lane = create_client('negative-' + mode)
                error_case[0] = mode
                completed, _ = negative_client.command(['pairing', 'already-discovered', 90 + index, 20202021,
                    address, proxies[negative_lane].getsockname()[1], '--timeout', 30],
                    r'Run command failure', timeout=12, failure=True)
                negative_client.close(); clients.remove(negative_client)
                time.sleep(.2)
                with lock:
                    captured = copy.deepcopy(packets)
                group = []; seen = set(); originals = {}
                for row in captured:
                    if row.get('negative_case') != mode or row['lane'] != negative_lane:
                        continue
                    packet = bytes.fromhex(row.get('forwarded_data', row['data'])); header = message(packet)
                    key = row['direction'], header['counter']
                    if header.get('protocol') != 0 or header.get('opcode') not in (0x20, 0x21, 0x22, 0x23, 0x24, 0x40) or key in seen:
                        continue
                    seen.add(key); header['direction'] = row['direction']; group.append(header)
                    originals[header['opcode']] = bytes.fromhex(row['data'])
                expected = [0x20, 0x40] if mode == 'passcodeID' else [0x20, 0x21, 0x22, 0x23, 0x24, 0x40]
                observed = [p['opcode'] for p in group]
                check('failed-exchange-sequence-' + mode, observed in (expected, expected[:-1]))
                status_ok = observed == expected and group[-1]['payload'] == struct.pack('<HIH', 1, 0, 2)
                check('failure-status-' + mode, status_ok, conformance=True)
                for p in group:
                    initiator = p['direction'] == 'initiator'
                    assert p['flags'] == (4 if initiator else 1) and p['session'] == p['security'] == p['protocol'] == p['vendor'] == 0
                    assert p['exchange'] == group[0]['exchange'] and bool(p['exchange_flags'] & 1) == initiator
                    assert p['source' if initiator else 'destination'] == group[0]['source']
                if mode == 'passcodeID':
                    check('invalid-passcodeID-value', fields(group[0]['payload'])[3]['value'] == 1)
                    first_request = originals[0x20]
                    first_lane = negative_lane
                else:
                    validate(group, success=False, allow_missing_failure_status=True)
                    check('invalid-cA-has-valid-TLV-shape', fields(group[4]['payload'])[1]['value'] != fields(message(originals[0x24])['payload'])[1]['value'])
                    original_cA = originals[0x24]; original_PA = message(originals[0x22])['payload']
                    second_lane = negative_lane
                failed_exchanges.add((negative_lane, group[0]['exchange']))
                negative.append({'case': mode, 'exchange_id': group[0]['exchange'], 'opcodes': observed,
                    'response_observation_limit_seconds': 12, 'controller_completed_before_abort': completed,
                    'expected_opcodes': expected, 'observed_status': {'general': 1, 'protocol': 0, 'code': 2} if status_ok else None,
                    'expected_status': {'general': 1, 'protocol': 0, 'code': 2}, 'result': 'PASS' if status_ok else 'FAIL'})
            error_case[0] = None
            # Late, structurally valid work must not revive either failed exchange.
            late_request = first_request[:16] + struct.pack('<BBHH', 5, 0x22, message(first_request)['exchange'], 0) + original_PA
            with lock:
                probe_counter = max(message(bytes.fromhex(r['data']))['counter'] for r in packets if r['direction'] == 'initiator')
            assert probe_counter < (1 << 32) - 2
            for packet, mode, lane in [(late_request, 'passcodeID', first_lane), (original_cA, 'cA', second_lane)]:
                probe_counter += 1
                packet = packet[:4] + probe_counter.to_bytes(4, 'little') + packet[8:]
                with lock:
                    start = len(packets)
                    packets.append({'lane': lane, 'direction': 'initiator', 'data': packet.hex(), 'late_probe': mode})
                proxies[lane].sendto(packet, target); late_probes.append({'case': mode, 'start': start})
            time.sleep(quiet_seconds)
            with lock:
                captured = copy.deepcopy(packets)
            for probe in late_probes:
                exchange_id = next(n['exchange_id'] for n in negative if n['case'] == probe['case'])
                progress = []
                for row in captured[probe['start'] + 1:]:
                    if row['direction'] != 'responder':
                        continue
                    p = message(bytes.fromhex(row['data']))
                    if p['session'] or (p.get('exchange') == exchange_id and
                        (p.get('opcode') in (0x21, 0x23) or (p.get('opcode') == 0x40 and p['payload'] == bytes(8)))):
                        progress.append(p)
                check('failed-exchange-not-revived-' + probe['case'], not progress)
            report['TC_SC_2_3'] = {'result': 'PASS' if all(n['result']=='PASS' for n in negative) else 'FAIL', 'negative_exchanges': negative,
                'late_correct_messages_do_not_revive': True, 'observation_seconds': quiet_seconds,
                'key_memory_inspection': 'NOT_PERFORMED; full new commissioning checks resource recovery.'}
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
                if (row['lane'], p['exchange']) in failed_exchanges:
                    continue
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
        if args.tamper_pase:
            check('both-PASE-directions-tampered', [t['direction'] for t in tamper] == ['initiator', 'responder'])
            for t in tamper:
                check('bad-MIC-silent-before-original-' + t['direction'],
                      t['original_released'] and not t['unexpected_peer_progress'] and
                      t['quiet_elapsed_seconds'] >= quiet_seconds)
            first_session = next(s for s in sessions if s['lane'] == 0)
            check('same-PASE-session-ID-after-I2R-error', tamper[0]['session_id'] == first_session['responder_session_id'])
            check('same-PASE-session-ID-after-R2I-error', tamper[1]['session_id'] == first_session['initiator_session_id'])
            report['tamper'] = tamper
            report['TC_SC_2_2'] = {'bidirectional_encrypted_commissioning': 'PASS',
                'Core4.8.3_bad_MIC_drop_and_same_session_recovery': 'PASS',
                'literal_step5_terminate_session_and_clear_keys': 'FAIL',
                'key_memory_inspection': 'NOT_PERFORMED; continued use of the same session disproves mandatory termination.'}
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
        report['Core_result'] = 'FAIL' if any(c['status']=='FAIL' for c in report.get('conformance_checks', [])) else 'PASS'
        report['literal_procedure_result'] = 'FAIL'
        report['result'] = report['Core_result']  # Independent evidence; never an original CSA verdict.
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
