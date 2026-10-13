"""MP04a: browse before two full runtimes start, without an announcement delay.

Uses an unmodified chip-tool and the complete pair oracle. UDP multicast capture
needs no raw-socket capability. Keep the output (controller state and LAN packets)
private. Run scenarios serially on a dedicated interface; this is not a CSA test.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time

from test_mdns_linux import decode, read_name


def inspect(packets, first):
    """Independent wire correlation, including probe authority and announcements."""
    records = []
    query_times = []
    for packet in packets:
        data = bytes.fromhex(packet['hex'])
        try:
            flags, rr = decode(data)
            pos = 12
            for _ in range(struct.unpack_from('!H', data, 4)[0]):
                name, pos = read_name(data, pos)
                pos += 4
                if not flags & 0x8000 and name.lower() == f'_l{first}._sub._matterc._udp.local.':
                    query_times.append(packet['time'])
            records.append((packet['time'], flags, rr))
        except (ValueError, IndexError, struct.error, UnicodeError):
            continue  # unrelated malformed LAN traffic is not a DUT result
    owners = {}
    for stamp, flags, rr in records:
        for name, typ, _, ttl, data in rr:
            if typ == 33 and ttl and name.endswith('._matterc._udp.local.'):
                port = struct.unpack_from('!H', data, 4)[0]
                if port in (5541, 5542):
                    assert owners.setdefault(name, port) == port, 'instance changed port'
    assert len(owners) == 2 and set(owners.values()) == {5541, 5542}, owners
    seen = {port: set() for port in owners.values()}
    hosts = {}
    first_record = None
    for stamp, flags, rr in records:
        for name, typ, _, ttl, data in rr:
            if not ttl:
                continue
            if name in owners:
                port = owners[name]
                discriminator = 3846 if port == 5541 else 1234
                first_record = stamp if first_record is None else min(first_record, stamp)
                if typ == 33:
                    assert struct.unpack_from('!H', data, 4)[0] == port
                    host, _ = read_name(data, 6)
                    assert hosts.setdefault(port, host) == host
                elif typ == 16:
                    fields = {}; pos = 0
                    while pos < len(data):
                        size = data[pos]; pos += 1
                        assert pos + size <= len(data), 'truncated DUT TXT'
                        key, value = data[pos:pos+size].split(b'=', 1); pos += size
                        assert key not in fields, 'duplicate DUT TXT key'
                        fields[key] = value
                    assert fields[b'D'] == str(discriminator).encode(), (port, fields)
                    assert fields[b'CM'] in (b'0', b'1', b'2', b'3'), fields
                    seen[port].add('TXT')
                if flags & 0x8000:
                    seen[port].add('response')
            elif typ == 12:
                target, _ = read_name(data, 0)
                port = owners.get(target.lower())
                if port:
                    disc = 3846 if port == 5541 else 1234
                    allowed = {'_matterc._udp.local.', '_cm._sub._matterc._udp.local.',
                               f'_l{disc}._sub._matterc._udp.local.', f'_s{disc >> 8}._sub._matterc._udp.local.'}
                    assert name in allowed, ('crossed PTR/discriminator', name, port)
                    if flags & 0x8000 and name.startswith(f'_l{disc}.'):
                        seen[port].add('long-PTR')
    assert query_times and min(query_times) < first_record, 'browse did not precede DUT startup'
    assert len(hosts) == 2 and len(set(hosts.values())) == 2, hosts
    assert all({'TXT', 'long-PTR', 'response'} <= got for got in seen.values()), seen
    return {'ports': sorted(seen), 'browse_before_DUT': True,
            'coherent_PTR_SRV_TXT': True, 'distinct_instances_and_hosts': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exe', required=True, help='runtime-pair-host')
    p.add_argument('--chip-tool', required=True)
    p.add_argument('--paa', required=True)
    p.add_argument('--credentials', required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--mode', choices=('plain', 'memcheck', 'sanitize'), required=True)
    p.add_argument('--reverse', action='store_true')
    p.add_argument('--legacy-discovery', action='store_true', help='Expected upstream failure reproduction, never a PASS waiver')
    a = p.parse_args()
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    packets = []; node = controller = None
    result = {'mode': a.mode, 'reverse': a.reverse, 'legacy': a.legacy_discovery}
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock, \
            (out/'node.log').open('w') as log, (out/'controller.log').open('w') as ctl_log:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::', 5353))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', a.interface))
        command = [sys.executable, str(Path(__file__).with_name('chip_tool_three_phase.py')),
                   '--chip-tool', a.chip_tool, '--paa', a.paa, '--output', str(out/'checks'),
                   '--discriminator', '3846', '--pair-discriminator', '1234',
                   '--source-registers', '--meter-services']
        if a.reverse:
            command.append('--pair-reverse')
        if a.legacy_discovery:
            command.append('--pair-legacy-discovery')
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        try:
            controller = subprocess.Popen(command, stdout=ctl_log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 180
            start_deadline = time.monotonic() + 15
            first = 1234 if a.reverse else 3846
            while time.monotonic() < deadline:
                if select.select([sock], [], [], .05)[0]:
                    data, peer = sock.recvfrom(4096)
                    packets.append({'time': time.monotonic(), 'source': peer[0], 'hex': data.hex()})
                    # Wait for observable controller readiness, not an arbitrary
                    # sleep. The DUT is absent until the real subtype query.
                    if node is None:
                        try:
                            flags = struct.unpack_from('!H', data, 2)[0]
                            pos = 12; names = []
                            for _ in range(struct.unpack_from('!H', data, 4)[0]):
                                name, pos = read_name(data, pos); pos += 4; names.append(name.lower())
                            launch = not flags & 0x8000 and f'_l{first}._sub._matterc._udp.local.' in names
                        except (ValueError, IndexError, struct.error, UnicodeError):
                            launch = False
                        if launch:
                            prefix = []
                            if a.mode == 'memcheck':
                                prefix = ['valgrind', '--leak-check=full', '--show-leak-kinds=all',
                                          '--errors-for-leak-kinds=all', '--track-origins=yes',
                                          '--error-exitcode=99', '--log-file='+str(out/'valgrind.log')]
                            node = subprocess.Popen([*prefix, str(Path(a.exe).resolve()), str(a.interface),
                                                     a.credentials, str(out/'a.bin'), str(out/'b.bin'),
                                                     '--meter-services'], stdout=log, stderr=subprocess.STDOUT, env=env)
                if controller.poll() is not None:
                    assert controller.returncode == 0, f'controller exit {controller.returncode}; see controller.log'
                    assert node is not None, 'DUT was never started'
                    result['node_exit'] = node.wait(timeout=40)
                    assert result['node_exit'] == 0, result
                    break
                assert node is not None or time.monotonic() < start_deadline, 'no initial discriminator query'
            else:
                raise TimeoutError('full pair scenario')
            result.update(inspect(packets, first))
            result['status'] = 'PASS'
            print(json.dumps(result), flush=True)
        finally:
            for child in (controller, node):
                if child is not None and child.poll() is None:
                    if child is controller:
                        os.killpg(child.pid, signal.SIGTERM)  # include its interactive chip-tool
                    else:
                        child.terminate()
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        if child is controller:
                            os.killpg(child.pid, signal.SIGKILL)
                        else:
                            child.kill()
                        child.wait()
            (out/'packets.json').write_text(json.dumps(packets, indent=2)+'\n')
            result.setdefault('status', 'FAIL')
            (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
