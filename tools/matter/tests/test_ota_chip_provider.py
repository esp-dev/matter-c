"""OTA laboratory acceptance with the unmodified CHIP OTA Provider application.

busy-update observes TC-SU-2.1's two-minute Busy window before the next
announcement/query and a complete signed host-simulation update/restart.
update exercises the same download/apply/restart path without that timing
procedure, suitable for separate Memcheck and ASan/UBSan/LSan runs.
Neither mode installs executable firmware or is an automatic CSA test.
CSA20 modes cover TC-SU-2.2 response scenarios using a provider built with
matter_enable_tracing_support=true and matter_log_json_payload_hex=true.
interrupt-retry covers TC-SU-2.3: kill the provider mid-transfer, observe
at least five real minutes, read Idle, then restart the same provider and
verify a new ReceiveInit at offset zero and a complete update.
Requires Python cryptography, chip-tool and trusted development PAAs.
apply-* modes cover TC-SU-2.5 with real provider delays, never an accelerated
requestor clock. They verify peer responses, retry counts and image disposal.
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


def image_fixture(directory, version=2, signed_version=None):
    """Independent OpenSSL-backed signature; no private key is written to disk."""
    body = bytes((i * 17 + 3) % 256 for i in range(16387))
    key = ec.generate_private_key(ec.SECP256R1())
    signed_version = version if signed_version is None else signed_version
    manifest = b'WWOTA001' + struct.pack('<HHIQ', 0xfff1, 0x8001, signed_version, len(body)) + hashlib.sha256(body).digest()
    r, s = utils.decode_dss_signature(key.sign(manifest, ec.ECDSA(hashes.SHA256())))
    payload = manifest + r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + body
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    del key
    header = (b'\x15\x25\x00\xf1\xff\x25\x01\x01\x80\x24\x02' + bytes([version]) + b'\x2c\x03\x02v' + str(version).encode()
              + b'\x26\x04' + struct.pack('<I', len(payload))
              + b'\x24\x08\x01\x30\x09\x20' + hashlib.sha256(payload).digest() + b'\x18')
    image = struct.pack('<IQI', 0x1beef11e, 16 + len(header) + len(payload), len(header)) + header + payload
    for name, data in [('source.ota', image), ('public.sec1', public)]:
        with (directory / name).open('xb') as output:
            output.write(data)
    return {'format': 'Matter OTA header and WWOTA001 signed host simulation',
            'version': version, 'signed_version': signed_version, 'image_bytes': len(image), 'image_sha256': hashlib.sha256(image).hexdigest(),
            'public_key_sha256': hashlib.sha256(public).hexdigest()}


def tlv_document(data):
    """Independent, bounded reader for anonymous/context-tagged IM trace fields."""
    offset = 0

    def take(size):
        nonlocal offset
        if offset + size > len(data):
            raise ValueError('truncated trace TLV')
        value = data[offset:offset + size]; offset += size; return value

    def element(depth=0):
        if depth > 16:
            raise ValueError('trace TLV nesting limit')
        control = take(1)[0]; kind = control & 31; tagging = control >> 5
        if tagging > 1:
            raise ValueError('unexpected trace TLV tag')
        tag = take(1)[0] if tagging else None
        if kind == 24:
            return tag, None, True
        if kind <= 7:
            value = int.from_bytes(take(1 << (kind & 3)), 'little', signed=kind < 4)
        elif kind in (8, 9):
            value = kind == 9
        elif 12 <= kind <= 19:
            size = int.from_bytes(take(1 << (kind & 3)), 'little')
            value = take(size)
            if kind <= 15:
                value = value.decode('utf-8')
        elif kind == 20:
            value = None
        elif kind in (21, 22, 23):
            value = []
            while True:
                child_tag, child, end = element(depth + 1)
                if end:
                    break
                value.append((child_tag, child))
        else:
            raise ValueError('unsupported trace TLV type')
        return tag, value, False

    tag, value, end = element()
    if tag is not None or end or offset != len(data):
        raise ValueError('invalid trace TLV document')
    return dict(value)


def trace_messages(path):
    """Reassemble actual peer JSON trace records split into ATM log chunks."""
    if not path.exists():
        return []
    decoder = json.JSONDecoder(); result = []; pending = ''; stamp = 0
    # json:log avoids an upstream OpenFile/create_directories failure. CHIP
    # splits long JSON lines into 256-byte ATM chunks: concatenate exactly.
    for line in ANSI.sub('', path.read_text(errors='replace')).splitlines():
        match = re.match(r'^\[(\d+\.\d+)\].*?\[ATM\] (.*)$', line)
        if not match:
            continue
        chunk = match[2]
        if not pending:
            if not chunk.lstrip().startswith('{'):
                continue
            stamp = round(float(match[1]) * 1000)
        pending += chunk
        try:
            record, end = decoder.raw_decode(pending.lstrip())
        except json.JSONDecodeError:
            continue
        assert not pending.lstrip()[end:].strip(), 'extra trace record data'
        pending = ''
        record['time_ms'] = stamp  # SDK log prefix; no time_ms in json:log mode.
        result.append(record)
    return result


def ota_messages(path, command_id, requests=False):
    """Decode OTA fields; raw tokens remain in private traces, never reports."""
    result = []
    for record in trace_messages(path):
        header = record.get('payloadHeader', {})
        if record.get('event') != ('MessageReceived' if requests else 'MessageSend') or header.get('protocolId') != 1 or header.get('messageType') != (8 if requests else 9):
            continue
        document = tlv_document(bytes.fromhex(record['payload']['hex']))
        for _, response in document.get(2 if requests else 1, []):
            command = response if requests else dict(response).get(0)
            if command is None:
                continue
            command = dict(command); command_path = dict(command[0])
            if command_path != {0: 0, 1: 0x29, 2: command_id}:
                continue
            fields = dict(command[1])
            result.append({'time_ms': record['time_ms'], 'fields': fields})
    return result


def bdx_profile(path, image):
    """Validate a complete negotiated receiver-driven transfer from peer octets.

    BDX itself is a binary protocol, not Matter TLV. The JSON trace holds its
    actual payload octets; never infer BlockAck from an MRP standalone ACK.
    """
    messages = [r for r in trace_messages(path) if r.get('payloadHeader', {}).get('protocolId') == 2]
    assert messages, 'No BDX trace'
    decoded = []
    for r in messages:
        h = r['payloadHeader']; data = bytes.fromhex(r['payload']['hex'])
        decoded.append((r['event'], h['messageType'], h['exchangeId'], data))
    initial = [d for event, op, _, d in decoded if event == 'MessageReceived' and op == 4]
    accept = [d for event, op, _, d in decoded if event == 'MessageSend' and op == 5]
    assert len(initial) == len(accept) == 1, 'Expected one ReceiveInit/Accept'
    assert len({exchange for _, _, exchange, _ in decoded}) == 1, 'Mixed BDX exchanges'
    init = initial[0]; reply = accept[0]
    assert len(init) >= 6 and len(reply) >= 4
    ptc, rc, proposed = struct.unpack_from('<BBH', init)
    assert ptc == 0x20 and rc & ~0x13 == 0 and proposed > 0, 'Not synchronous receiver drive'
    width = 8 if rc & 0x10 else 4; pos = 4; offset = length = None
    if rc & 2:
        assert len(init) >= pos + width
        offset = int.from_bytes(init[pos:pos + width], 'little'); pos += width
    if rc & 1:
        assert len(init) >= pos + width
        length = int.from_bytes(init[pos:pos + width], 'little'); pos += width
    assert len(init) >= pos + 2
    fdl = int.from_bytes(init[pos:pos + 2], 'little'); pos += 2
    assert fdl and len(init) >= pos + fdl
    tc, accepted_rc, block_size = struct.unpack_from('<BBH', reply)
    assert tc == 0x20 and accepted_rc & ~0x11 == 0 and 0 < block_size <= proposed
    accepted_length = None
    if accepted_rc & 1:
        size = 8 if accepted_rc & 0x10 else 4
        assert len(reply) >= 4 + size
        accepted_length = int.from_bytes(reply[4:4 + size], 'little')
    queries = []; blocks = []; eof = []; acks = []
    for event, op, _, data in decoded:
        if op in (0x10, 0x11, 0x12, 0x14):
            assert len(data) >= 4
            counter = int.from_bytes(data[:4], 'little')
            if op in (0x10, 0x14):
                assert event == 'MessageReceived' and len(data) == 4
                (queries if op == 0x10 else acks).append(counter)
            else:
                assert event == 'MessageSend' and len(data) - 4 <= block_size
                blocks.append((counter, data[4:]))
                if op == 0x12:
                    eof.append(counter)
        else:
            assert op in (4, 5), 'Unexpected BDX opcode'
    assert queries == [n for n, _ in blocks] == list(range(len(blocks))) and len(blocks) > 1
    assert eof == acks == [len(blocks) - 1], 'EOF and AckEOF counters differ'
    body = b''.join(data for _, data in blocks)
    expected = image.read_bytes()[offset or 0:]
    if length:
        expected = expected[:length]
    assert body == expected and (accepted_length in (None, 0, len(body))), 'Transferred image/range mismatch'
    return {'result': 'PASS', 'transfer_control': ptc, 'range_control': rc,
            'proposed_max_block_size': proposed, 'accepted_max_block_size': block_size,
            'start_offset_field': offset, 'effective_start_offset': offset or 0,
            'proposed_length_field': length, 'accepted_length': accepted_length,
            'file_designator_length': fdl, 'metadata_bytes': len(init) - pos - fdl,
            'block_counters': queries, 'eof_counter': eof[0], 'ack_eof_counter': acks[0],
            'bytes': len(body), 'image_sha256': hashlib.sha256(body).hexdigest(),
            'ordinary_BlockAck': False, 'limits': 'Negotiated synchronous receiver drive: next BlockQuery acknowledges prior block; no sender-driven or nonzero-offset transfer claimed.'}


def query_messages(path, requests=False):
    """Read QueryImage/Response from CHIP's JSON log records; omit tokens."""
    return [dict(time_ms=m['time_ms'], version=m['fields'][2]) if requests else
            dict(time_ms=m['time_ms'], status=m['fields'][0], delay=m['fields'].get(1, 0),
                 uri=m['fields'].get(2), version=m['fields'].get(3))
            for m in ota_messages(path, 0 if requests else 1, requests)]


def apply_binding(paths, version, require_notify=True):
    """Require the latest offered token/version in every actual Apply request."""
    messages = []
    for path in paths:
        for command, requests in ((1, False), (2, True), (4, True)):
            messages.extend((m['time_ms'], command, m['fields']) for m in ota_messages(path, command, requests))
    messages.sort(key=lambda m: m[0])
    token = None; offered = None; applied = []; notified = 0
    for stamp, command, fields in messages:
        if command == 1 and fields[0] == 0:
            token, offered = fields[5], fields[3]
            assert type(token) is bytes and 8 <= len(token) <= 32 and type(offered) is int
        elif command in (2, 4):
            assert token is not None and fields[0] == token, 'OTA command did not echo latest offered UpdateToken'
            assert type(fields[0]) is bytes and type(fields[1]) is int and fields[1] == offered == version, 'OTA token/version binding mismatch'
            if command == 2:
                applied.append({'time_ms': stamp, 'new_version': fields[1], 'token_size': len(token),
                                'token_sha256': hashlib.sha256(token).hexdigest()})
            else:
                notified += 1
    assert applied, 'No decoded ApplyUpdateRequest in provider trace'
    assert bool(notified) == require_notify, 'Unexpected NotifyUpdateApplied presence in provider trace'
    return applied


def ota_event_reports(text):
    """Read the independent chip-tool decoder's OTA event structures."""
    fields = {'StateTransition': {'PreviousState', 'NewState', 'Reason', 'TargetSoftwareVersion'},
              'VersionApplied': {'SoftwareVersion', 'ProductID'},
              'DownloadError': {'SoftwareVersion', 'BytesDownloaded', 'ProgressPercent', 'PlatformCode'}}
    result = []
    for match in re.finditer(r'\b(StateTransition|VersionApplied|DownloadError):\s*\{(.*?)\n[^\n]*?\[TOO\]\s*\}', text, re.S):
        values = {}
        for name in fields[match[1]]:
            value = re.search(r'\b' + name + r':\s*(null|-?0x[0-9a-fA-F]+|-?\d+)\b', match[2])
            if value is None:
                raise ValueError('Missing event field ' + name)
            token = value[1]
            values[name] = None if token == 'null' else int(token, 16 if '0x' in token else 10)
        result.append(dict(event=match[1], fields=values))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'provider', 'chip-tool', 'paa', 'credentials', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--subscriptions-per-fabric', type=int, default=3, help='Explicit requestor budget; must fit its compiled transport capacity.')
    p.add_argument('--mode', choices=('busy-update', 'update', 'busy-60', 'busy-180',
                   'not-available', 'same-version', 'older-version', 'invalid-uri',
                   'interrupt-retry', 'version-mismatch', 'apply-proceed-0',
                   'apply-proceed-180', 'apply-await-60', 'apply-await-180',
                   'apply-discontinue', 'query-timeout'), default='busy-update')
    p.add_argument('--stall-provider', help='Separate laboratory provider that stalls BDX data but keeps MRP alive; interrupt-retry only.')
    p.add_argument('--events', action='store_true', help='Subscribe to actual OTA events before announcement and verify their fields/sequences.')
    p.add_argument('--default-provider', action='store_true', help='Configure DefaultOTAProviders before UpdateAvailable announcements; existing default uses SimpleAnnouncement.')
    p.add_argument('--valgrind', action='store_true')
    p.add_argument('--require-trace', action='store_true', help='Require and verify actual QueryImageResponse fields, also in update mode.')
    p.add_argument('--apply-binding', action='store_true', help='Verify UpdateToken/NewVersion from peer Query/Apply/Notify traces.')
    p.add_argument('--bdx-profile', action='store_true', help='Verify ReceiveInit/Accept, all block counters, image bytes and AckEOF from actual peer traces.')
    p.add_argument('--image-version', type=int, choices=(2, 3), default=2, help='Positive update fixture version; enables a nonconstant NewVersion control.')
    a = p.parse_args()
    apply_policy = {'apply-proceed-0': (0, 0), 'apply-proceed-180': (0, 180),
                    'apply-await-60': (1, 60), 'apply-await-180': (1, 180),
                    'apply-discontinue': (2, 180)}.get(a.mode)
    negative = a.mode in ('not-available', 'same-version', 'older-version', 'invalid-uri', 'version-mismatch', 'apply-discontinue', 'query-timeout')
    busy_mode = a.mode in ('busy-update', 'busy-60', 'busy-180')
    delay = {'busy-60': 60, 'busy-180': 180, 'not-available': 60}.get(a.mode, 150 if a.mode == 'busy-update' else 0)
    if a.image_version != 2 and a.mode != 'update':
        p.error('--image-version=3 requires --mode update')
    if a.stall_provider and a.mode != 'interrupt-retry':
        p.error('--stall-provider requires --mode interrupt-retry')
    if a.apply_binding and a.mode != 'update':
        p.error('--apply-binding requires --mode update')
    if a.bdx_profile and a.mode not in ('update', 'interrupt-retry'):
        p.error('--bdx-profile requires --mode update or interrupt-retry')
    image_version = {'same-version': 1, 'older-version': 0, 'version-mismatch': 3}.get(a.mode, a.image_version)
    need_trace = a.events or a.require_trace or a.apply_binding or a.bdx_profile or a.mode not in ('busy-update', 'update')
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    report = {'scope': 'CHIP Provider and C requestor, laboratory protocol/simulated restart; not certification',
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'mode': a.mode, 'valgrind': a.valgrind, 'trace_required': need_trace, 'subscriptions_per_fabric': a.subscriptions_per_fabric,
              'default_provider': a.default_provider, 'announcement_reason': 1 if a.default_provider else 0,
              'checks': [], 'fixture': image_fixture(out, image_version, 2 if a.mode == 'version-mismatch' else None),
              'binaries': {n: hashlib.sha256(Path(v).read_bytes()).hexdigest() for n, v in
                           [('requestor', a.exe), ('provider', a.provider), ('chip-tool', a.chip_tool)]}}
    if a.stall_provider:
        report['fault_provider_sha256'] = hashlib.sha256(Path(a.stall_provider).read_bytes()).hexdigest()
    provider = node = client = reader = None
    logs = []; phase = 0; provider_phase = 0

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
        return ''.join(ANSI.sub('', path.read_text(errors='replace')) for path in provider_logs())

    def provider_logs():
        return [out / ('provider.log' if i == 1 else f'provider-{i}.log')
                for i in range(1, provider_phase + 1)]

    def query_count():
        return provider_text().count('OTA Provider received QueryImage')

    def responses():
        return [message for path in provider_logs() for message in query_messages(path)]

    def apply_messages(command_id, requests=False):
        return [m for path in provider_logs() for m in ota_messages(path, command_id, requests)]

    def observe_apply():
        action, delay_seconds = apply_policy
        wait(lambda: bool(apply_messages(3)), 120, allow_node_exit=action == 0 and delay_seconds == 0)
        first = apply_messages(3)[0]
        check('apply-response-action-and-delay', first['fields'] == {0: action, 1: delay_seconds}, first)
        if action == 2:
            wait(lambda: 'OTA_APPLY_DONE' in node_text())
            # Discontinue ignores DelayedActionTime. Do not wait its 180 s.
            until = time.monotonic() + 15
            while time.monotonic() < until:
                assert node.poll() is None and 'OTA_APPLY_GATE' not in node_text()
                assert not apply_messages(4, True), 'Notify after Discontinue'
                time.sleep(.05)
            state = command(client, ['otasoftwareupdaterequestor', 'read', 'update-state', 1, 0], r'UpdateState: 1\b')
            check('discontinue-idle-clears-image-without-install', 'OTA_AUTH accepted=1' in node_text()
                  and bool(re.search(r'UpdateState: 1\b', state))
                  and 'OTA_DISCARD result=0' in node_text()
                  and not (out / 'download.ota').exists() and not (out / 'download.ota.part').exists()
                  and 'OTA_SIM_REBOOT' not in node_text())
        else:
            required_seconds = max(120, delay_seconds) if action == 1 else delay_seconds
            observed = time.monotonic(); next_progress = 30
            if required_seconds:
                check('old-version-retained-during-delay', basic(client)['SoftwareVersion'] == 1)
            # A delayed response must not install early or launch a new Query/BDX.
            # The requestor's monotonic response/gate stamps below provide the
            # exact Proceed interval; peer stamps independently time Await retries.
            if not required_seconds:
                wait(lambda: 'OTA_APPLY_GATE' in node_text(), 90, allow_node_exit=True)
            while 'OTA_APPLY_GATE' not in node_text():
                elapsed = time.monotonic() - observed
                assert elapsed < required_seconds + 90, 'delayed apply timed out'
                assert node.poll() is None and provider.poll() is None, 'process exited before apply'
                assert query_count() == 1 and node_text().count('OTA_DOWNLOAD version=') == 1
                if action == 1 and len(apply_messages(2, True)) == 1:
                    assert 'OTA_SIM_REBOOT' not in node_text(), 'install without Proceed'
                if elapsed >= next_progress:
                    print(f'OBSERVE Apply action={action} delay={delay_seconds}: {elapsed:.1f}s', flush=True)
                    next_progress += 30
                time.sleep(.05)
            if action == 0:
                received = re.findall(r'OTA_APPLY_RESPONSE now_ms=(\d+)', node_text())
                gate = re.search(r'OTA_APPLY_GATE .*now_ms=(\d+)', node_text())
                assert len(received) == 1 and gate, 'missing monotonic apply stamps'
                interval = int(gate[1]) - int(received[0])
            else:
                requests = apply_messages(2, True)
                assert len(requests) == 2, 'Await must retry exactly once in this fixture'
                interval = requests[1]['time_ms'] - first['time_ms']
                received = re.findall(r'OTA_APPLY_RESPONSE now_ms=(\d+)', node_text())
                gate = re.search(r'OTA_APPLY_GATE .*now_ms=(\d+)', node_text())
                check('apply-only-after-second-response', len(received) == 2 and gate is not None
                      and int(gate[1]) >= int(received[1])
                      and int(gate[1]) - int(received[0]) >= required_seconds * 1000)
            check('apply-required-real-delay', interval >= required_seconds * 1000,
                  {'minimum_seconds': required_seconds, 'measured_ms': interval,
                   'clock': 'requestor monotonic receipt-to-gate' if action == 0 else 'provider response-send-to-retry-receive'})
        report['apply_responses'] = [dict(time_ms=m['time_ms'], action=m['fields'][0], delay=m['fields'][1]) for m in apply_messages(3)]
        expected = [(action, delay_seconds)] + ([(0, 0)] if action == 1 else [])
        check('apply-response-sequence', [(m['action'], m['delay']) for m in report['apply_responses']] == expected)
        check('single-query-single-download', query_count() == 1 and node_text().count('OTA_DOWNLOAD version=') == 1)

    def observe(seconds):
        deadline = observed + seconds
        while time.monotonic() < deadline:
            assert query_count() == 1, 'provider queried before required delay'
            assert node.poll() is None and provider.poll() is None, 'OTA process exited during observation'
            assert 'OTA_DOWNLOAD' not in node_text(), 'unexpected download during rejection/wait'
            time.sleep(.1)

    def wait(test, timeout=60, allow_node_exit=False, allow_provider_exit=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if test():
                return
            if provider is not None and provider.poll() is not None and not allow_provider_exit:
                raise AssertionError('provider exited')
            if node is not None and node.poll() is not None and not allow_node_exit:
                raise AssertionError('requestor exited: ' + node_text()[-600:])
            time.sleep(.05)
        raise AssertionError('OTA condition timed out')

    def start_node():
        nonlocal phase, node
        phase += 1
        argv = [a.exe, '--interface', str(a.interface), '--subscriptions-per-fabric', str(a.subscriptions_per_fabric), '--port', '5581', '--seconds', '900',
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
        command(client, ['otasoftwareupdaterequestor', 'announce-otaprovider', 2, 0xfff1, 1 if a.default_provider else 0, 0, 1, 0], r'status = 0x00')

    def start_provider():
        nonlocal provider, provider_phase
        provider_phase += 1
        provider = subprocess.Popen([a.stall_provider if a.stall_provider and provider_phase == 1 else a.provider, '--secured-device-port', '5561', '--discriminator', '3991',
                    '--passcode', '20202021', '--KVS', str(out / 'provider.kvs'),
                    '--filepath', str(out / 'source.ota'), '--queryImageStatus', 'busy' if busy_mode else
                    'updateNotAvailable' if a.mode == 'not-available' else 'updateAvailable',
                    '--delayedQueryActionTimeSec', str(delay),
                    *(['--applyUpdateAction', ('proceed', 'awaitNextAction', 'discontinue')[apply_policy[0]],
                       '--delayedApplyActionTimeSec', str(apply_policy[1])] if apply_policy else []),
                    *(['--ignoreQueryImage', '100'] if a.mode == 'query-timeout' else []),
                    *(['--pollInterval', '500'] if a.mode == 'interrupt-retry' and provider_phase == 1 else []),
                    *(['--imageUri', 'bdx://0000000000000001'] if a.mode == 'invalid-uri' else []),
                    *(['--trace-to', 'json:log'] if need_trace else [])],
                    stdout=log('provider.log' if provider_phase == 1 else f'provider-{provider_phase}.log'),
                    stderr=subprocess.STDOUT, env=env)
        wait(lambda: any(x in provider_logs()[-1].read_text(errors='replace')
                        for x in ('SetupQRCode', 'SetupManualCode', 'Server initialization complete')))

    try:
        start_provider()
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
        capabilities = command(client, ['basicinformation', 'read', 'capability-minima', 1, 0],
                               r'SubscriptionsPerFabric: ' + str(a.subscriptions_per_fabric) + r'\b')
        check('advertised-subscription-budget', bool(re.search(
            r'SubscriptionsPerFabric: ' + str(a.subscriptions_per_fabric) + r'\b', capabilities)), a.subscriptions_per_fabric)
        identity = basic(client); report['basic_information'] = identity
        if a.events:
            command(client, ['any', 'subscribe-event-by-id', '0x2a', '0xffffffff', 0, 2, 1, 0,
                             '--keepSubscriptions', 0, '--is-urgent', 'true'], r'Subscription established')
            check('ota-event-subscription-before-announcement', True)
        if a.default_provider:
            command(client, ['otasoftwareupdaterequestor', 'write', 'default-otaproviders',
                             json.dumps([{'providerNodeID': 2, 'endpoint': 0}]), 1, 0], r'status = 0x00')
            selected = command(client, ['otasoftwareupdaterequestor', 'read', 'default-otaproviders', 1, 0])
            check('default-provider-readback-before-update-available', bool(re.search(r'ProviderNodeID: 2\b', selected))
                  and 'Endpoint: 0' in selected and 'FabricIndex: 1' in selected)
        announce()
        if a.mode == 'query-timeout':
            wait(lambda: bool(ota_messages(out / 'provider.log', 0, True)))
            check('provider-received-query-before-ignoring-response', True)
            wait(lambda: 'OTA_STATE state=1 reason=2' in node_text(), 100)
            check('query-failure-idle-without-download', 'OTA_DOWNLOAD' not in node_text()
                  and not responses() and node.poll() is None)
        else:
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
            report['location'] = 'omitted (optional under Core 11.20.6.5.1)' if not re.search(r'\bLocation:', first) else 'present'
            check('query-image-fields', query_fields == identity and has_bdx and consent is not None and consent[1] == '0',
                  {'identity': query_fields, 'bdx_synchronous': has_bdx, 'consent': consent[1] if consent else None})
            # TC-SU-2.2 must observe the actual response, not infer it from CLI flags.
            if need_trace:
                wait(lambda: len(responses()) >= 1)
                first_response = responses()[0]; report['first_response'] = first_response
                check('query-response-fields', first_response['status'] == (1 if busy_mode else 2 if a.mode == 'not-available' else 0)
                      # The official provider emits DelayedActionTime only for Busy;
                      # omission for NotAvailable/UpdateAvailable is conformant.
                      and first_response['delay'] == (delay if busy_mode else 0) and (first_response['status'] != 0 or
                      first_response['version'] == image_version), first_response)
                if first_response['status'] == 0 and a.mode != 'invalid-uri':
                    check('response-has-usable-bdx-location', isinstance(first_response['uri'], str)
                          and first_response['uri'].startswith('bdx://0000000000000002/')
                          and len(first_response['uri']) >= 24)
        if busy_mode:
            wait(lambda: 'OTA_STATE state=3 reason=4' in node_text())
            announce()  # A repeated announcement must not bypass Busy's floor.
            observe(119.8 if delay == 60 else 120.2 if delay < 180 else 179.8)
            check('busy-single-query-for-120s' if a.mode == 'busy-update' else 'busy-observation-no-early-query',
                  query_count() == 1, {'observed_seconds': time.monotonic() - observed})
            report['next_announcement_monotonic'] = time.monotonic()
            announce()
            wait(lambda: query_count() >= 2, 75, allow_node_exit=True)
            check('announcement-next-query', query_count() == 2,
                  {'seconds_from_first_observed': time.monotonic() - observed})
            report['provider_query_times'] = [float(x) for x in re.findall(
                r'^\[(\d+\.\d+)\].*OTA Provider received QueryImage', provider_text(), re.M)]
            if need_trace:
                wait(lambda: len(responses()) >= 2)
                response = responses()[1]; report['second_response'] = response
                requests = query_messages(out / 'provider.log', requests=True)
                assert len(requests) == 2, requests
                query_interval = requests[1]['time_ms'] - requests[0]['time_ms']
                delay_interval = requests[1]['time_ms'] - first_response['time_ms']
                check('busy-delay-respected', query_interval >= 120000 and delay_interval >= delay * 1000,
                      {'query_interval_ms': query_interval, 'response_to_next_query_ms': delay_interval})
                check('busy-retry-update-available', response['status'] == 0 and response['version'] == 2, response)
        if a.mode == 'interrupt-retry':
            partial = out / 'download.ota.part'
            wait(lambda: partial.exists() and partial.stat().st_size >= 4096)
            # The file stream buffers writes; the visible prefix is a lower
            # bound on received data. The provider's EOF must still be absent.
            prefix = partial.read_bytes()
            check('partial-transfer-before-kill', 0 < len(prefix) < report['fixture']['image_bytes']
                  and prefix == (out / 'source.ota').read_bytes()[:len(prefix)]
                  and 'Transfer completed, got AckEOF' not in provider_text()
                  and 'OTA_AUTH' not in node_text() and 'OTA_SIM_REBOOT' not in node_text(),
                  {'visible_prefix_bytes': len(prefix), 'prefix_sha256': hashlib.sha256(prefix).hexdigest()})
            if not a.stall_provider:
                provider.kill(); provider.wait(timeout=10)
                report['provider_kill_exit'] = provider.returncode
            killed = time.monotonic(); failure_elapsed = None; next_progress = 30
            report['interruption_start_utc_ms'] = round(time.time() * 1000)
            report['interruption_fault'] = 'BDX-data-stall-with-live-MRP' if a.stall_provider else 'provider-kill'
            # Official step 4 requires a real five-minute observation. An MRP
            # delivery failure can terminate the transfer sooner than its BDX
            # idle timer; record that separately instead of calling it idle expiry.
            while time.monotonic() - killed < 301:
                elapsed = time.monotonic() - killed
                assert node.poll() is None, 'requestor exited during interrupted transfer'
                text = node_text()
                assert 'OTA_AUTH' not in text and 'OTA_SIM_REBOOT' not in text, 'partial image accepted'
                assert not (out / 'download.ota').exists(), 'partial image published'
                if failure_elapsed is None and 'OTA_DOWNLOAD_FAILED' in text:
                    failure_elapsed = elapsed
                if elapsed >= next_progress:
                    print(f'OBSERVE interrupted transfer {elapsed:.1f}s', flush=True); next_progress += 30
                time.sleep(.1)
            if a.stall_provider:
                check('bdx-idle-not-before-five-minutes', failure_elapsed is not None and failure_elapsed >= 300,
                      {'failure_after_seconds': failure_elapsed, 'provider_still_running': provider.poll() is None})
                check('bdx-stall-provider-retains-live-process', provider.poll() is None and 'CSA26_BDX_STALL bytes=' in provider_text())
            report['interruption'] = {'observation_seconds': time.monotonic() - killed,
                                      'failure_observed_after_seconds': failure_elapsed}
            wait(lambda: 'OTA_DOWNLOAD_FAILED' in node_text(), 45, allow_provider_exit=True)
            idle = command(client, ['otasoftwareupdaterequestor', 'read', 'update-state', 1, 0], r'UpdateState: 1\b')
            check('idle-after-five-real-minutes', bool(re.search(r'UpdateState: 1\b', idle))
                  and not partial.exists() and not (out / 'download.ota').exists(), report['interruption'])
            check('version-retained-after-interruption', basic(client)['SoftwareVersion'] == 1)
            if provider.poll() is None:
                provider.terminate(); provider.wait(timeout=10)
            start_provider()  # Same image, KVS, node/fabric and requestor process.
            announce()
            # A still-live BDX peer can restart with its old CASE session lost.
            # Allow one failed Invoke and the unchanged 120 s query backoff.
            wait(lambda: query_count() == 2, 240 if a.stall_provider else 90, allow_node_exit=True)
            wait(lambda: len(responses()) == 2, allow_node_exit=True)
            check('retry-query-update-available', responses()[1]['status'] == 0 and responses()[1]['version'] == 2,
                  responses()[1])
            wait(lambda: 'Start Offset:' in provider_logs()[-1].read_text(errors='replace'), allow_node_exit=True)
            receive = ANSI.sub('', provider_logs()[-1].read_text(errors='replace')).split('[ATM] ReceiveInit', 1)[1]
            offset = re.search(r'Start Offset:\s*(0x[0-9a-fA-F]+)', receive)
            control = re.search(r'Range Control:\s*(0x[0-9a-fA-F]+)', receive)
            check('retry-receive-init-starts-at-zero', offset is not None and int(offset[1], 16) == 0
                  and control is not None and int(control[1], 16) & 2 == 0,
                  {'start_offset': int(offset[1], 16) if offset else None,
                   'range_control': int(control[1], 16) if control else None})
        if apply_policy:
            observe_apply()
        if a.mode == 'apply-discontinue':
            report['apply_requests'] = apply_binding(provider_logs(), image_version, require_notify=False)
            check('discontinue-single-bound-apply-no-notify', len(report['apply_requests']) == 1)
        elif a.mode == 'version-mismatch':
            wait(lambda: 'OTA_AUTH accepted=0' in node_text() and 'OTA_DOWNLOAD_FAILED' in node_text())
            check('signed-version-mismatch-rejected', True, {'offered_version': image_version, 'signed_version': 2})
            time.sleep(3)
            check('no-apply-or-notify-for-rejected-version',
                  not any(ota_messages(path, command, True) for path in provider_logs() for command in (2, 4))
                  and 'OTA_SIM_REBOOT' not in node_text() and node.poll() is None)
        elif a.mode == 'query-timeout':
            pass
        elif negative:
            wait(lambda: 'OTA_STATE state=1 reason=1' in node_text())
            if a.mode != 'not-available':
                announce()  # Also challenge the shared query floor after rejection.
            observe(120.2 if a.mode == 'not-available' else 3)
            check('rejected-without-bdx-or-install', query_count() == 1 and not (out / 'download.ota').exists()
                  and 'Type 0002:01 (BDX:ReceiveInit)' not in provider_text()
                  and 'OTA_AUTH' not in node_text() and 'OTA_SIM_REBOOT' not in node_text(),
                  {'observed_seconds': time.monotonic() - observed})
            if a.mode == 'invalid-uri':
                check('invalid-uri-was-sent', first_response['uri'] == 'bdx://0000000000000001')
        else:
            wait(lambda: 'OTA_SIM_REBOOT' in node_text(), 120, allow_node_exit=True)
            check('signed-download-and-reboot', node.wait(timeout=30) == 0 and 'authenticated=1 installed=1' in node_text())
            check('download-matches-image', hashlib.sha256((out / 'download.ota').read_bytes()).hexdigest() == report['fixture']['image_sha256'])
            check('provider-received-final-block-ack', 'Transfer completed, got AckEOF' in provider_text())
            if a.bdx_profile:
                report['BDX_profile'] = bdx_profile(provider_logs()[-1], out / 'source.ota')
                check('bdx-peer-binary-transfer-profile', report['BDX_profile']['result'] == 'PASS')
            start_node()
            wait(lambda: 'OTA_NOTIFY_DONE' in node_text(), 90)
            check('notify-update-applied', 'OTA_NOTIFY_DONE success=1' in node_text()
                  and 'OTA Provider received NotifyUpdateApplied' in provider_text())
            if a.apply_binding or apply_policy:
                report['apply_requests'] = apply_binding(provider_logs(), image_version)
                check('apply-token-and-version-bound-to-query-and-image', True, report['apply_requests'])
                if apply_policy:
                    check('no-extra-apply-after-proceed', len(report['apply_requests']) == (2 if apply_policy[0] == 1 else 1))
        reader = Client(Path(a.chip_tool).resolve(), Path(a.paa).resolve(), out, 'fresh-reader', client.storage, advertise=False)
        restored = basic(reader)
        boot = command(reader, ['generaldiagnostics', 'read', 'boot-reason', 1, 0])
        check('fresh-case-version-and-boot' if negative else 'fresh-case-after-restart', restored['SoftwareVersion'] == (1 if negative else image_version)
              and bool(re.search(r'BootReason: ' + ('1' if negative else '5') + r'\b', boot)), restored)
        if a.events:
            command(reader, ['any', 'read-event-by-id', '0x2a', '0xffffffff', 1, 0])
            time.sleep(.2)  # Let chip-tool finish printing the last decoded structure.
            records = ota_event_reports(client.text()) + ota_event_reports(reader.text())
            report['ota_events'] = records
            transitions = [r['fields'] for r in records if r['event'] == 'StateTransition']
            check('state-transition-target-version-fields', bool(transitions) and all(
                t['TargetSoftwareVersion'] == (image_version if t['NewState'] in (4, 5, 7) else None)
                for t in transitions), transitions)
            sequence = [(t['PreviousState'], t['NewState']) for t in transitions]
            prefix = [(1, 2), (2, 1)] if a.mode in ('query-timeout', 'not-available', 'same-version', 'older-version', 'invalid-uri') else (
                [(1, 2), (2, 3), (3, 2), (2, 4), (4, 5)] if busy_mode else [(1, 2), (2, 4)])
            check('ota-event-transition-sequence', sequence[:len(prefix)] == prefix, sequence)
            if not negative:
                check('downloading-directly-to-applying', (4, 5) in sequence and (4, 1) not in sequence
                      if a.mode != 'interrupt-retry' else (4, 5) in sequence, sequence)
                applied = [r['fields'] for r in records if r['event'] == 'VersionApplied']
                check('version-applied-event-matches-basic-information', bool(applied) and all(
                    r == {'SoftwareVersion': restored['SoftwareVersion'], 'ProductID': restored['ProductID']}
                    for r in applied), applied)
            if busy_mode:
                check('delayed-on-query-event', any(t['NewState'] == 3 and t['Reason'] == 4 for t in transitions))
            if apply_policy and apply_policy[0] == 1:
                check('delayed-on-apply-event', any(t['PreviousState'] == 5 and t['NewState'] == 6
                                                  and t['Reason'] == 4 for t in transitions))
            if a.mode == 'query-timeout':
                check('query-failure-event-reason', any(t['PreviousState'] == 2 and t['NewState'] == 1
                                                       and t['Reason'] == 2 for t in transitions))
            if a.mode == 'interrupt-retry':
                errors = [r['fields'] for r in records if r['event'] == 'DownloadError']
                all_node_logs = ''.join((out / f'node-{i}.log').read_text() for i in range(1, phase + 1))
                failed_bytes = int(re.search(r'OTA_DOWNLOAD_FAILED bytes=(\d+)', all_node_logs)[1])
                percent = (failed_bytes * 100 + report['fixture']['image_bytes'] // 2) // report['fixture']['image_bytes']
                check('download-error-exact-bytes-and-nearest-percent', bool(errors) and all(
                    r == {'SoftwareVersion': image_version, 'BytesDownloaded': failed_bytes,
                          'ProgressPercent': percent, 'PlatformCode': None} for r in errors), errors)
        node.terminate(); check('clean-requestor-stop', node.wait(timeout=30) == 0)
        for i in range(1, phase + 1):
            assert not (out / f'node-{i}.err').read_text()
            if a.valgrind:
                text = (out / f'valgrind-{i}.log').read_text()
                assert 'ERROR SUMMARY: 0 errors' in text and 'in use at exit: 0 bytes in 0 blocks' in text
        check('memory-diagnostics-clean', True, f'boots={phase}; ' + ('Memcheck' if a.valgrind else 'stderr logs empty'))
        report['result'] = 'PASS'; report['restarts'] = phase - 1; report['provider_restarts'] = provider_phase - 1
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
