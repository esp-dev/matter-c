"""Private IPv6 UDP observations for original manual TC-SC-2.1.

Unmodified chip-tool commissions two independent fabrics, opening the second
window over the first fabric's live CASE session. No packets are altered. Core1.6.1 checks
and literal original-procedure discrepancies are reported separately. This is
independent operator evidence, not an automatic CSA result. --tamper-pase also
records TC-SC-2.2 bidirectional traffic: alter the first encrypted request and
response MIC, then release the original packets after a real quiet interval.
--pase-errors records TC-SC-2.3 invalid passcodeID/cA and terminal exchanges.
--mrp-size records TC-SC-1.1 at the complete IPv6 packet size boundary.
--mrp-flows records TC-SC-1.2 ACK/data flows, including encrypted R=0 reads.
--mrp-retries records TC-SC-1.3 complete ACK loss and bounded retransmissions.
--mrp-duplicates records TC-SC-1.4 matching ACKs without repeated PASE work.
--descriptor-profile records the current five-endpoint TC-DESC-2.1 inventory.
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


def mrp_size_probes(ipv6, interface, target, check, packets, lock):
    """Real UDP, no IPv6 extensions: packet size = 40 IPv6 + 8 UDP + Matter.

    Core4.4.1.7 MX bytes pad an otherwise small valid PBKDF request, keeping
    application limits separate from the transport boundary. Oversize inputs
    have unique ephemeral identities/counters, never a previously ACKed replay.
    """
    receipts = []
    for index, size in enumerate((1231, 1232, 1233, 1280, 1281)):
        source = 0x1234000000000000 + index
        counter = 0x40000000 + index * 4; exchange = 0x7100 + index
        random = bytes([index + 1]) * 32
        payload = b'\x15\x30\x01\x20' + random + b'\x25\x02\x01\x00\x24\x03\x00\x28\x04\x18'
        header = struct.pack('<BHBIQ', 4, 0, 0x20, counter, source)
        protocol = struct.pack('<BBHH', 5, 0x20, exchange, 0)
        padding = size - len(header) - 2 - len(protocol) - len(payload)
        packet = header + struct.pack('<H', padding) + bytes(padding) + protocol + payload
        assert len(packet) == size and message(packet)['payload'] == payload
        assert fields(payload)[3]['value'] == 0
        received = []
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind((ipv6, 0, 0, interface)); sock.settimeout(.1)
            # Fresh socket has no IPv6 extension options. DONTFRAG prevents
            # accidentally exercising reassembly instead of the MTU policy.
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DONTFRAG, 1)
            check('size-send-' + str(size), sock.sendto(packet, target) == size)
            with lock:
                packets.append({'lane': -1, 'direction': 'initiator', 'size_probe': size, 'data': packet.hex()})
            end = time.monotonic() + 2
            while time.monotonic() < end:
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                assert peer[0] == target[0] and peer[1] == target[1]
                decoded = message(data); received.append(decoded)
                with lock:
                    packets.append({'lane': -1, 'direction': 'responder', 'size_probe': size, 'data': data.hex()})
                # ACK responder's reliable PBKDF response to avoid retries.
                if decoded.get('exchange_flags', 0) & 4:
                    ack = struct.pack('<BHBIQ', 4, 0, 0, counter + 1, source)
                    ack += struct.pack('<BBHHI', 3, 0x10, exchange, 0, decoded['counter'])
                    sock.sendto(ack, target)
            acks = [p for p in received if p.get('exchange') == exchange and
                    p.get('acknowledged_counter') == counter and p.get('protocol') == 0]
            responses = [p for p in received if p.get('exchange') == exchange and p.get('opcode') == 0x21]
            if size <= 1232:
                check('size-matching-ACK-' + str(size), bool(acks))
                check('size-valid-PBKDF-response-' + str(size), bool(responses) and
                      fields(responses[0]['payload'])[1]['value'] == random)
                # End only this deliberately incomplete handshake. This is
                # cleanup, not an assertion of the CSA39 error-status behavior.
                cleanup = struct.pack('<BHBIQ', 4, 0, 0, counter + 2, source)
                cleanup += struct.pack('<BBHH', 5, 0x22, exchange, 0) + b'\x15\x18'
                sock.sendto(cleanup, target)
                time.sleep(.6)
            else:
                check('size-oversize-silent-' + str(size), not received)
            receipts.append({'matter_udp_payload_bytes': size, 'ipv6_header_bytes': 40,
                             'udp_header_bytes': 8, 'ipv6_packet_bytes': size + 48,
                             'reliability': True, 'matching_ACK': bool(acks),
                             'PBKDF_response': bool(responses), 'received_datagrams': len(received),
                             'observation_seconds': 2, 'packet_sha256': hashlib.sha256(packet).hexdigest(),
                             'result': 'PASS'})
    return {'result': 'PASS', 'packet_boundary_bytes': 1280, 'probes': receipts,
            'padding': 'Core4.4.1.7 Message Extensions; valid small PBKDFParamRequest',
            'negative_scope': '2-second observation per unique oversize message; no duplicate/replay shortcut'}


def mrp_flow_probes(ipv6, interface, target, check, packets, lock):
    """Independent test-only PASE peer; secrets never leave this function.

    Reuse the existing affine SPAKE vector arithmetic, not production crypto.
    Real ephemeral randomness is used here. AES-CCM is from cryptography; no
    native DUT codecs or crypto are used by this peer. Original vector output
    is suppressed, not logged. No changes to controller/DUT protocol clocks.
    """
    import contextlib
    import io
    import runpy
    import secrets
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    vector = Path(__file__).with_name('pase-vector.py')
    if not vector.exists():
        vector = Path(__file__).parent.parent / 'fixtures' / 'pase-vector.py'
    with contextlib.redirect_stdout(io.StringIO()):
        v = runpy.run_path(str(vector))
    source = secrets.randbelow(0xffffffeffffffffe) + 1
    counter = 0x51000000; exchange = 0x7200; local_session = 0x7a01
    secure_counter = secrets.randbits(28)
    read = bytes.fromhex('153600172402002403282404021818290324ff0d18')
    observation = .7
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind((ipv6, 0, 0, interface)); sock.settimeout(.05)

        def send(data, label):
            assert sock.sendto(data, target) == len(data)
            with lock:
                packets.append({'lane': -2, 'direction': 'initiator', 'flow_probe': label, 'data': data.hex()})

        def unsecured(opcode, payload, flags=5, acknowledged=None, number=None):
            nonlocal counter
            if number is None:
                counter += 1; number = counter
            return (struct.pack('<BHBIQ', 4, 0, 0, number, source) +
                    struct.pack('<BBHH', flags, opcode, exchange, 0) +
                    (struct.pack('<I', acknowledged) if flags & 2 else b'') + payload)

        def receive(label, decrypt=None, expected=None):
            rows = []; end = time.monotonic() + (10 if expected is not None else observation)
            while time.monotonic() < end:
                try:
                    data, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                assert address[0] == target[0] and address[1] == target[1]
                outer = message(data)
                if decrypt and outer['session']:
                    assert outer['session'] == local_session and data[0] == data[3] == 0
                    nonce = data[3:4] + data[4:8] + bytes(8)  # PASE has no operational NodeId.
                    plain = decrypt.decrypt(nonce, data[8:], data[:8])
                    decoded = message(bytes(8) + plain); decoded['counter'] = outer['counter']
                else:
                    decoded = outer
                rows.append(decoded)
                with lock:
                    packets.append({'lane': -2, 'direction': 'responder', 'flow_probe': label, 'data': data.hex()})
                if decoded.get('exchange_flags', 0) & 4:
                    if decrypt:
                        ack_plain = struct.pack('<BBHHI', 3, 0x10, decoded['exchange'], 0, outer['counter'])
                        send(seal(ack_plain), label + '-response-ACK')
                    else:
                        send(unsecured(0x10, b'', 3, decoded['counter']), label + '-response-ACK')
                if decoded.get('opcode') == expected:
                    break
            return rows

        random = secrets.token_bytes(32)
        request = b'\x15\x30\x01\x20' + random + b'\x25\x02' + struct.pack('<H', local_session) + b'\x24\x03\x00\x28\x04\x18'
        first = unsecured(0x20, request); request_counter = message(first)['counter']
        send(first, 'reliable-data-request'); rows = receive('reliable-data-request')
        responses = [p for p in rows if p.get('opcode') == 0x21 and p.get('exchange') == exchange]
        check('flow-reliable-request-received', bool(responses))
        response = responses[0]
        check('flow-data-reply-piggybacks-ACK', bool(response['exchange_flags'] & 2) and response.get('acknowledged_counter') == request_counter,
              conformance=True)
        check('flow-PBKDF-random-echo', fields(response['payload'])[1]['value'] == random)
        send(first, 'reliable-no-data-duplicate'); duplicate = receive('reliable-no-data-duplicate')
        duplicate_ack = [p for p in duplicate if p.get('opcode') == 0x10 and p.get('acknowledged_counter') == request_counter]
        check('flow-duplicate-standalone-ACK-only', bool(duplicate_ack) and len(duplicate_ack) == len(duplicate) and
              all(not p['payload'] and not p['exchange_flags'] & 4 for p in duplicate), conformance=True)

        doc = fields(response['payload']); peer_session = doc[3]['value']; params = doc[4]['value']
        wide = hashlib.pbkdf2_hmac('sha256', struct.pack('<I', 20202021), params[2]['value'], params[1]['value'], 80)
        w0, w1 = (int.from_bytes(wide[i:i+40], 'big') % v['N'] for i in (0, 40))
        scalar = secrets.randbelow(v['N'] - 1) + 1
        pa = v['enc'](v['add'](v['mul'](scalar, v['G']), v['mul'](w0, v['M'])))
        send(unsecured(0x22, b'\x15\x30\x01\x41' + pa + b'\x18'), 'pake1')
        rows = receive('pake1', expected=0x23); p2 = next(p for p in rows if p.get('opcode') == 0x23)
        pb_doc = fields(p2['payload']); pb = pb_doc[1]['value']; assert len(pb) == 65 and pb[0] == 4
        point = (int.from_bytes(pb[1:33], 'big'), int.from_bytes(pb[33:], 'big'))
        assert 0 <= point[0] < v['P'] and 0 <= point[1] < v['P'] and (point[1]**2 - point[0]**3 + 3*point[0] - v['B']) % v['P'] == 0
        nq = v['mul'](w0, v['Q']); minus = (nq[0], (-nq[1]) % v['P'])
        base = v['add'](point, minus)
        z, vv = v['enc'](v['mul'](scalar, base)), v['enc'](v['mul'](w1, base))
        context = hashlib.sha256(b'CHIP PAKE V1 Commissioning' + request + response['payload']).digest()
        transcript = b''.join(len(a).to_bytes(8, 'little') + a for a in
            (context, b'', b'', v['enc'](v['M']), v['enc'](v['Q']), pa, pb, z, vv, w0.to_bytes(32, 'big')))
        key = hashlib.sha256(transcript).digest(); confirmation = v['hkdf'](key[:16], b'ConfirmationKeys', 32)
        check('flow-independent-PASE-responder-confirmation', v['mac'](confirmation[16:], pa) == pb_doc[2]['value'])
        ca = v['mac'](confirmation[:16], pb)
        send(unsecured(0x24, b'\x15\x30\x01\x20' + ca + b'\x18'), 'pake3')
        rows = receive('pake3', expected=0x40); finished = [p for p in rows if p.get('opcode') == 0x40]
        check('flow-independent-PASE-finished', len(finished) == 1 and finished[0]['payload'] == bytes(8))
        # The owner activates PASE after receiving the final ACK. Do not send
        # the first application datagram in the same UDP burst as that ACK.
        time.sleep(.25)
        keys = v['hkdf'](key[16:], b'SessionKeys', 48)
        encrypt, decrypt = AESCCM(keys[:16]), AESCCM(keys[16:32])

        def seal(plain):
            nonlocal secure_counter
            secure_counter += 1
            header = struct.pack('<BHBI', 0, peer_session, 0, secure_counter)
            nonce = header[3:4] + header[4:8] + bytes(8)
            return header + encrypt.encrypt(nonce, plain, header)

        def read_once(index, reliable):
            ex = 0x7300 + index
            send(seal(struct.pack('<BBHH', 5 if reliable else 1, 2, ex, 1) + read),
                 'read-' + str(index))
            rows = receive('read-' + str(index), decrypt)
            # A single VendorID read returns ReportData, not merely a transport ACK.
            reports = [p for p in rows if p.get('protocol') == 1 and p.get('opcode') == 5 and p.get('exchange') == ex]
            # Known one-path ReportData: VendorID65521 is context-tag2 uint16.
            value = any(b'\x25\x02\xf1\xff' in p['payload'] for p in reports)
            acks = [p for p in rows if p.get('acknowledged_counter') is not None]
            return {'index': index, 'R': reliable, 'data_reply': bool(reports), 'expected_VendorID': value,
                    'acknowledgements': len(acks), 'responses': len(rows),
                    'reply_flags': [p['exchange_flags'] for p in reports]}

        before = read_once(0, True)
        check('flow-encrypted-reliable-read-control-before', before['expected_VendorID'])
        unreliable = [read_once(i, False) for i in range(1, 6)]
        for row in unreliable:
            check('flow-unreliable-read-data-no-ACK-' + str(row['index']),
                  row['expected_VendorID'] and row['acknowledgements'] == 0, conformance=True)
        after = read_once(6, True)
        check('flow-encrypted-reliable-read-control-after', after['expected_VendorID'])
        # Release this uncommissioned PASE session before real chip-tool
        # commissioning. Core4.11.1.4 CloseSession, R=0, no ACK requested.
        close = struct.pack('<BBHH', 1, 0x40, 0x7400, 0) + struct.pack('<HIH', 0, 0, 3)
        send(seal(close), 'close-PASE'); receive('close-PASE', decrypt)
    passed = (bool(response['exchange_flags'] & 2) and response.get('acknowledged_counter') == request_counter and
              bool(duplicate_ack) and len(duplicate_ack) == len(duplicate) and
              all(p['expected_VendorID'] and not p['acknowledgements'] for p in unreliable))
    return {'result': 'PASS' if passed else 'FAIL', 'observation_seconds_per_message': observation,
            'reliable_reply_piggyback': bool(response['exchange_flags'] & 2) and response.get('acknowledged_counter') == request_counter,
            'duplicate_standalone_ACK_only': bool(duplicate_ack) and len(duplicate_ack) == len(duplicate),
            'unreliable': unreliable, 'reliable_before': before, 'reliable_after': after,
            'vector_source_sha256': hashlib.sha256(vector.read_bytes()).hexdigest(),
            'keys_exported': False, 'peer': 'Independent Python affine SPAKE2+ fixture and cryptography AES-CCM; valid reliable PASE, then IM ReadRequest R=0/1 controls'}


def mrp_retry_probes(ipv6, interface, target, check, packets, lock):
    """No replies during loss: five total sends vs four retransmissions.

    Peer advertises idle=active=500ms so choice of active/idle cannot confound
    the procedure's idle base. Observe real monotonic time, no clock scaling.
    Fixed default backoff constants come from Core1.6.1 Table22, not DUT code.
    """
    from fractions import Fraction
    import math
    import secrets

    interval = 500; transmissions = 5; observation = 12
    source = secrets.randbelow(0xffffffeffffffffe) + 1
    counter = 0x53000001; exchange = 0x7500; random = secrets.token_bytes(32)
    payload = b'\x15\x30\x01\x20' + random + b'\x25\x02\x02\x7a\x24\x03\x00\x28\x04'
    payload += b'\x35\x05\x25\x01\xf4\x01\x25\x02\xf4\x01\x25\x03\xa0\x0f\x18\x18'
    doc = fields(payload)
    assert doc[5]['value'][1]['value'] == doc[5]['value'][2]['value'] == interval
    request = struct.pack('<BHBIQBBHH', 4, 0, 0, counter, source, 5, 0x20, exchange, 0) + payload
    responses = []; late_responses = []; records = []
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind((ipv6, 0, 0, interface)); sock.settimeout(.05)

        def record(data, direction, phase):
            row = {'lane': -3, 'direction': direction, 'retry_probe': phase,
                   'monotonic_ns': time.monotonic_ns(), 'data': data.hex()}
            with lock:
                packets.append(row)
            records.append(row)
            return row

        start = time.monotonic()
        check('retry-initial-request-sent', sock.sendto(request, target) == len(request))
        record(request, 'initiator', 'loss')
        until = start + observation
        while time.monotonic() < until:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            assert address[0] == target[0] and address[1] == target[1]
            row = record(data, 'responder', 'loss'); h = message(data)
            assert h['session'] == h['protocol'] == h['vendor'] == 0 and h['exchange'] == exchange and h['destination'] == source
            if h['opcode'] == 0x21:
                responses.append((row, h))
            else:
                assert h['opcode'] == 0x10 and h.get('acknowledged_counter') == counter
            # Deliberately send nothing: drop every DUT message, including ACKs.
        observed_end = time.monotonic_ns()
        check('retry-five-total-transmissions', len(responses) == transmissions)
        first = bytes.fromhex(responses[0][0]['data'])
        check('retry-identical-bytes-and-counter', all(bytes.fromhex(row['data']) == first for row, _ in responses))
        check('retry-reliable-response-and-matching-request-ACK', all(h['exchange_flags'] == 6 and
              h.get('acknowledged_counter') == counter and fields(h['payload'])[1]['value'] == random for _, h in responses))
        gaps = []
        for n, ((previous, _), (current, _)) in enumerate(zip(responses, responses[1:])):
            factor = Fraction(11, 10) * Fraction(8, 5) ** max(0, n - 1)
            lower = math.ceil(interval * factor); upper = math.ceil(interval * factor * Fraction(5, 4))
            actual = (current['monotonic_ns'] - previous['monotonic_ns']) / 1_000_000
            # Receive timestamps include OS/VM scheduling. Preserve raw values
            # and explicit -25/+125ms tolerance; do not adjust protocol timers.
            check('retry-backoff-gap-' + str(n + 1), lower - 25 <= actual <= upper + 125)
            gaps.append({'after_send_index': n, 'observed_ms': actual, 'Core_min_ms': lower,
                         'Core_max_ms': upper, 'receive_tolerance_below_ms': 25, 'receive_tolerance_above_ms': 125})
        final_max = math.ceil(interval * Fraction(11, 10) * Fraction(8, 5) ** 3 * Fraction(5, 4))
        quiet_ms = (observed_end - responses[-1][0]['monotonic_ns']) / 1_000_000
        check('retry-silence-beyond-final-wait-and-guard', quiet_ms >= final_max + 1000)
        check('retry-no-peer-replies-during-loss', sum(row['direction'] == 'initiator' for row in records) == 1)
        # ACK only after the bounded retry train and expiry guard. It must not
        # restart the exhausted exchange. Full fresh commissioning follows.
        ack = struct.pack('<BHBIQBBHHI', 4, 0, 0, counter + 1, source, 3, 0x10, exchange, 0, responses[0][1]['counter'])
        check('retry-late-ACK-sent', sock.sendto(ack, target) == len(ack))
        record(ack, 'initiator', 'late-ACK')
        until = time.monotonic() + .7
        while time.monotonic() < until:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            assert address[0] == target[0] and address[1] == target[1]
            record(data, 'responder', 'late-ACK'); late_responses.append(data)
        check('retry-late-ACK-does-not-restart', not late_responses)
    return {'Core_result': 'PASS', 'literal_step4_result': 'FAIL',
            'procedure_issue': 'Step4 verification says total MRP_MAX_TRANSMISSIONS-1 messages. Observed/Core:5 total,4 retransmissions. Literal total4 is not met; clarify total versus retry count without altering DUT/test.',
            'maximum_transmissions': transmissions, 'total_transmissions': len(responses), 'retransmissions': len(responses) - 1,
            'peer_advertised_idle_ms': interval, 'peer_advertised_active_ms': interval,
            'idle_active_selection_proved': False, 'gaps': gaps, 'loss_observation_seconds': observation,
            'tail_silence_ms': quiet_ms, 'final_wait_max_ms': final_max, 'expiry_guard_ms': 1000,
            'peer_messages_during_loss': 1, 'peer_replies_during_loss': 0, 'late_ACK_restarted': bool(late_responses),
            'response_packet_sha256': hashlib.sha256(first).hexdigest(),
            'terminal_scope': 'No retries after full wait+guard, no restart on late ACK, then fresh commissioning. Internal timeout/eviction callback is not instrumented on the wire.'}


def mrp_duplicate_probes(ipv6, interface, target, check, packets, lock):
    """Exact reliable repeats after the original data reply was ACKed."""
    import secrets
    source = secrets.randbelow(0xffffffeffffffffe) + 1
    counter = 0x54000001; exchange = 0x7600; next_counter = counter
    random = secrets.token_bytes(32)
    payload = b'\x15\x30\x01\x20' + random + b'\x25\x02\x03\x7a\x24\x03\x00\x28\x04\x18'
    packet = struct.pack('<BHBIQBBHH', 4, 0, 0, counter, source, 5, 0x20, exchange, 0) + payload
    receipts = []
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind((ipv6, 0, 0, interface)); sock.settimeout(.05)

        def record(data, direction, index):
            with lock:
                packets.append({'lane': -4, 'direction': direction, 'duplicate_probe': index, 'data': data.hex()})

        for index in range(4):
            check('duplicate-request-sent-' + str(index), sock.sendto(packet, target) == len(packet))
            record(packet, 'initiator', index); rows = []
            until = time.monotonic() + .7
            while time.monotonic() < until:
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                assert peer[0] == target[0] and peer[1] == target[1]
                h = message(data); rows.append(h); record(data, 'responder', index)
                assert h['session'] == h['protocol'] == h['vendor'] == 0 and h['exchange'] == exchange and h['destination'] == source
                if h['exchange_flags'] & 4:
                    next_counter += 1
                    ack = struct.pack('<BHBIQBBHHI', 4, 0, 0, next_counter, source, 3, 0x10, exchange, 0, h['counter'])
                    assert sock.sendto(ack, target) == len(ack); record(ack, 'initiator-ACK', index)
            acked = [h for h in rows if h.get('acknowledged_counter') == counter and h['exchange_flags'] & 2]
            check('duplicate-matching-ACK-' + str(index), bool(acked))
            if index == 0:
                data_replies = [h for h in rows if h['opcode'] == 0x21]
                check('duplicate-original-application-reply', len(data_replies) == 1 and fields(data_replies[0]['payload'])[1]['value'] == random)
            else:
                check('duplicate-standalone-ACK-only-' + str(index), bool(rows) and
                      all(h['opcode'] == 0x10 and h['exchange_flags'] == 2 and not h['payload'] and
                          h.get('acknowledged_counter') == counter for h in rows))
            receipts.append({'index': index, 'same_request_counter': counter, 'matching_ACKs': len(acked),
                             'application_responses': sum(h['opcode'] == 0x21 for h in rows),
                             'received_opcodes': [h['opcode'] for h in rows], 'result': 'PASS'})
        # Terminate only this unfinished handshake; do not assert CSA39 error
        # status behavior. Subsequent full chip-tool commissioning proves liveness.
        cleanup = struct.pack('<BHBIQBBHH', 4, 0, 0, next_counter + 1, source, 5, 0x22, exchange, 0) + b'\x15\x18'
        sock.sendto(cleanup, target); record(cleanup, 'cleanup', 4); time.sleep(.7)
    return {'Core_result': 'PASS', 'literal_procedure_result': 'PASS', 'reliable_inputs': 4,
            'exact_duplicates': 3, 'request_sha256': hashlib.sha256(packet).hexdigest(),
            'receipts': receipts, 'observation_seconds_per_request': .7,
            'side_effect_scope': 'One original PBKDF response, none for exact duplicates after ACKing original. Core duplicate drop before application delivery is also source-reviewed; no live internal allocation/callback tracing claimed.'}


def descriptor_profile(client, command, check):
    """Read the actual hierarchy and served-cluster attribute catalogs over CASE."""
    from chip_tool_energy_profile import frames, ids, integer
    inventory = []; known = {0, 1, 3, 4, 5}
    root_required = {0x1d, 0x1f, 0x28, 0x2a, 0x30, 0x31, 0x33, 0x36, 0x38, 0x3c, 0x3e, 0x3f}
    for endpoint in sorted(known):
        text = command(client, ['descriptor', 'read-by-id', '0xffffffff', 1, endpoint], r'Flushed pending ack for MessageCounter:')
        attrs = {f['path'][2]: f for f in frames(text) if f['kind'] == 'Attribute' and f['path'][:2] == (endpoint, 0x1d)}
        check('descriptor-required-attributes-' + str(endpoint), {0, 1, 2, 3, 0xfffb, 0xfffc, 0xfffd} <= set(attrs))
        types = [(int(a), int(b)) for a, b in re.findall(r'^DeviceType: (\d+)[^\n]*\nRevision: (\d+)\b', attrs[0]['body'], re.M)]
        wanted = {0x16: 5, 0x12: 1} if endpoint == 0 else {0x510: 1, 0x511: 1, 0x512: 1} if endpoint == 1 else {0x510: 1}
        check('descriptor-device-types-revisions-' + str(endpoint), len(types) == len(wanted) and dict(types) == wanted)
        parts = ids(attrs[3]['body'], 'PartsList'); servers = ids(attrs[1]['body'], 'ServerList'); clients = ids(attrs[2]['body'], 'ClientList')
        expected_parts = known - {0} if endpoint == 0 else {3, 4, 5} if endpoint == 1 else set()
        check('descriptor-hierarchy-' + str(endpoint), set(parts) == expected_parts and all(1 <= p <= 65534 for p in parts))
        required = root_required if endpoint == 0 else {0x1d, 0x90, 0x91, 0x9c, 3, 0xb06} if endpoint == 1 else {0x1d, 0x90, 0x9c}
        check('descriptor-server-device-requirements-' + str(endpoint), required <= set(servers))
        check('descriptor-client-roles-' + str(endpoint), set(clients) == ({0x29} if endpoint == 0 else set()))
        feature = integer(attrs[0xfffc]['body'], 'FeatureMap')
        check('descriptor-tag-feature-attribute-' + str(endpoint), bool(feature & 1) == (4 in attrs) and feature == (0 if endpoint == 0 else 1))
        tags = []
        if endpoint:
            tags = [(int(a), int(b)) for a, b in re.findall(r'^NamespaceID: (\d+)[^\n]*\nTag: (\d+)\b', attrs[4]['body'], re.M)]
            check('descriptor-standard-AC-tags-' + str(endpoint), tags == [(10, 1 if endpoint == 1 else endpoint - 1)])
        catalogs = {}
        for cluster in servers:
            text = command(client, ['any', 'read-by-id', cluster, '0xfffb', 1, endpoint], r'Flushed pending ack for MessageCounter:')
            catalog = next(f for f in frames(text) if f['kind'] == 'Attribute' and f['path'] == (endpoint, cluster, 0xfffb))
            if cluster > 0xffff and "Don't know how to log attribute value" in catalog['body']:
                # Named TOO output lacks the vendor schema, but DMG still logs
                # the actual decoded TLV array for this single-attribute read.
                dmg = '\n'.join(re.findall(r'\[DMG\]\s*([^\r\n]*)', text))
                arrays = re.findall(r'\bData = \[(.*?)\]', dmg, re.S)
                check('descriptor-vendor-attribute-array-' + str(endpoint), len(arrays) == 1)
                attributes = [int(x) for x in re.findall(r'\b(\d+) \(unsigned\)', arrays[0])]
                check('descriptor-vendor-attribute-array-values-' + str(endpoint), bool(attributes) and
                      len(attributes) == len(set(attributes)) and all(0 <= x <= 0xffffffff for x in attributes) and
                      not re.sub(r'\b\d+ \(unsigned\)|[,\s]', '', arrays[0]))
            else:
                attributes = ids(catalog['body'], 'AttributeList')
            check('descriptor-listed-server-serves-attributes-' + str(endpoint) + '-' + str(cluster),
                  {0xfff8, 0xfff9, 0xfffb, 0xfffc, 0xfffd} <= set(attributes))
            catalogs[str(cluster)] = attributes
        inventory.append({'endpoint': endpoint, 'device_types': [{'type': a, 'revision': b} for a, b in types],
                          'parts': parts, 'servers': servers, 'clients': clients, 'feature_map': feature,
                          'tags': tags, 'attributes': catalogs})
    return {'Core_result': 'PASS', 'inventory': inventory,
            'literal_all_nonroot_PartsLists_empty': all(not x['parts'] for x in inventory if x['endpoint']),
            'root_TagList_applicable': False,
            'all_device_cluster_acceptance_complete': False,
            'limits': 'Device-type metadata, hierarchy, mandatory cluster presence and served AttributeLists verified. Vendor AttributeList uses decoded DMG TLV output because TOO has no vendor schema. This is not closure of every cluster command/attribute behavior test; campaign still has unexecuted and failed procedures.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--valgrind', action='store_true')
    parser.add_argument('--tamper-pase', action='store_true', help='TC-SC-2.2: corrupt one MIC in each direction, then release originals')
    parser.add_argument('--pase-errors', action='store_true', help='TC-SC-2.3: invalid passcodeID/cA, terminal probes, then valid commissioning')
    parser.add_argument('--mrp-size', action='store_true', help='TC-SC-1.1: full IPv6 MTU boundary, then valid commissioning')
    parser.add_argument('--mrp-flows', action='store_true', help='TC-SC-1.2: ACK/data flows and five authenticated unreliable reads')
    parser.add_argument('--mrp-retries', action='store_true', help='TC-SC-1.3: drop all replies, measure immutable retransmissions and stop')
    parser.add_argument('--mrp-duplicates', action='store_true', help='TC-SC-1.4: repeat reliable requests and require ACK without application re-execution')
    parser.add_argument('--descriptor-profile', action='store_true', help='TC-DESC-2.1: current profile hierarchy and served cluster catalogs')
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    if sum((args.tamper_pase, args.pase_errors, args.mrp_size, args.mrp_flows, args.mrp_retries, args.mrp_duplicates, args.descriptor_profile)) > 1:
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
        if args.mrp_duplicates:
            report['TC_SC_1_4'] = mrp_duplicate_probes(args.ipv6, args.interface, target, check, packets, lock)
        if args.mrp_retries:
            report['TC_SC_1_3'] = mrp_retry_probes(args.ipv6, args.interface, target, check, packets, lock)
        if args.mrp_flows:
            report['TC_SC_1_2'] = mrp_flow_probes(args.ipv6, args.interface, target, check, packets, lock)
        if args.mrp_size:
            report['TC_SC_1_1'] = mrp_size_probes(args.ipv6, args.interface, target, check, packets, lock)
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
            if args.descriptor_profile and lane == 0:
                report['TC_DESC_2_1'] = descriptor_profile(client, command, check)
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
            if any(key in row for key in ('size_probe', 'flow_probe', 'retry_probe', 'duplicate_probe')):
                continue
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
