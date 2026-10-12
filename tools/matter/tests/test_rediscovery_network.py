"""Real host/CASE/MRP route loss; independent Matter.js operational discovery.

A transparent UDP proxy disappears. DNS-SD points to the controller's existing
socket, so recovery must preserve the CASE session and its live subscription.
Only the selected local interface is used; no firewall/route changes.
"""
import argparse
from collections import Counter
from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import uuid
from zeroconf import IPVersion, Zeroconf

p = argparse.ArgumentParser()
p.add_argument('--exe', required=True)
p.add_argument('--interface', type=int, required=True)
p.add_argument('--ipv6', required=True)
p.add_argument('--runtime', default='')
p.add_argument('--node', default='node')
p.add_argument('--modules', default='build/matter-controller/node_modules')
a = p.parse_args()
assert version('zeroconf') == '0.147.0'
run = Path('build') / ('rediscovery-network-' + uuid.uuid4().hex)
run.mkdir()
env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else '') + os.environ['PATH'],
           ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
subprocess.run([a.node, 'tools/matter/tests/host_controller.mjs', a.modules, 'credentials', str(run / 'credentials')],
               check=True, env=env, timeout=30)
target = (a.ipv6, 0, 0, a.interface)
peer = None
cut, stop = threading.Event(), threading.Event()
blocked = Counter()
errors = []


def forward(sock):
    global peer
    while not stop.is_set():
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError as error:
            if not stop.is_set():
                errors.append(error)
            return
        if source[1] == target[1]:
            if cut.is_set():
                blocked[data] += 1
            elif peer:
                sock.sendto(data, peer)
        else:
            peer = source
            if not cut.is_set():
                sock.sendto(data, target)


children = []
worker = None
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as proxy, (run / 'node.log').open('w') as out, (run / 'node.err').open('w') as err:
    proxy.bind((a.ipv6, 0, 0, a.interface))
    proxy.settimeout(.1)
    try:
        host = subprocess.Popen([str(Path(a.exe).resolve()), '--interface', str(a.interface), '--credentials', str(run / 'credentials'),
                                 '--state', str(run / 'state.tlv'), '--seconds', '55'], stdout=out, stderr=err, env=env)
        children.append(host)
        deadline = time.monotonic() + 10
        while 'NODE instance=' not in (run / 'node.log').read_text() and time.monotonic() < deadline:
            assert host.poll() is None, (run / 'node.err').read_text()
            time.sleep(.05)
        banner = next(line for line in (run / 'node.log').read_text().splitlines() if line.startswith('NODE '))
        port = int(next(field[5:] for field in banner.split() if field.startswith('port=')))
        target = (a.ipv6, port, 0, a.interface)
        worker = threading.Thread(target=forward, args=(proxy,))
        worker.start()
        with (run / 'controller.log').open('w') as log:
            controller = subprocess.Popen([a.node, 'tools/matter/tests/host_rediscovery.mjs', a.modules,
                                           a.ipv6 + '%' + str(a.interface), str(port), run.name,
                                           str(proxy.getsockname()[1]), str(run)], stdout=log, stderr=subprocess.STDOUT, env=env)
            children.append(controller)
            deadline = time.monotonic() + 30
            while not (run / 'peer.json').exists() and time.monotonic() < deadline:
                assert controller.poll() is None, (run / 'controller.log').read_text()[-6000:]
                time.sleep(.05)
            identity = json.loads((run / 'peer.json').read_text())
            assert peer is not None
            with Zeroconf(interfaces=[a.interface], ip_version=IPVersion.V6Only) as observer:
                discovered = observer.get_service_info('_matter._tcp.local.', identity['instance'] + '._matter._tcp.local.', timeout=3000)
                (run / 'discovered.txt').write_text(str(discovered) + '\nactual peer=' + str(peer))
                assert discovered is not None and discovered.port == peer[1], 'Controller DNS-SD does not advertise its direct socket'
            # Matter.js advertises its own authenticated fabric/node identity
            # and direct socket. No competing/fabricated DNS-SD record is added.
            # Finish unsolicited announcements; the resolver has no persistent
            # cache, and must query while MRP runs.
            time.sleep(2)
            cut.set()
            (run / 'cut').write_text('drop both directions of the old route')
            assert controller.wait(timeout=25) == 0, (run / 'controller.log').read_text()[-6000:]
        assert 'PASS rediscovery:' in (run / 'controller.log').read_text()
        assert blocked and max(blocked.values()) >= 2, 'Missing identical encrypted initial transmission/first retry on old route'
        assert not errors, errors
        assert host.wait(timeout=55) == 0, (run / 'node.err').read_text()
        assert not (run / 'node.err').read_text(), (run / 'node.err').read_text()
        assert 'result=0' in (run / 'node.log').read_text()
        (run / 'proxy.json').write_text(json.dumps({'old_port': proxy.getsockname()[1], 'new_port': peer[1],
                                                  'dropped_packets': sum(blocked.values()), 'identical_retries': max(blocked.values()), **identity}))
    finally:
        stop.set()
        if worker:
            worker.join(timeout=2)
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
print('PASS real rediscovery: IPv6 proxy loss, fresh DNS-SD, same CASE/subscription, immutable MRP, second fabric:', run)
