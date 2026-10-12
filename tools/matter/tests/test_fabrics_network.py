"""Two independent controller fabrics, three server lifetimes and a fresh boot."""
import argparse
import os
from pathlib import Path
import subprocess
import time
import uuid

p = argparse.ArgumentParser()
p.add_argument('--exe', required=True)
p.add_argument('--interface', type=int, required=True)
p.add_argument('--ipv6', required=True)
p.add_argument('--runtime', default='')
p.add_argument('--node', default='node')
p.add_argument('--modules', default='build/matter-controller/node_modules')
p.add_argument('--mdns', action='store_true', help='Verify selective goodbye using pinned python-zeroconf')
a = p.parse_args()
run = Path('build') / ('fabrics-network-' + uuid.uuid4().hex)
run.mkdir()
env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else '') + os.environ['PATH'], ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
subprocess.run([a.node, 'tools/matter/tests/host_controller.mjs', a.modules, 'credentials', str(run / 'credentials')], check=True, env=env, timeout=30)
base = [str(Path(a.exe).resolve()), '--interface', str(a.interface), '--credentials', str(run / 'credentials'), '--state', str(run / 'state.tlv')]
for mode in ('pair', 'self', 'last', 'fresh'):
    outpath, errpath = run / (mode + '.node.log'), run / (mode + '.node.err')
    with outpath.open('w') as out, errpath.open('w') as err:
        child = subprocess.Popen(base + ['--seconds', '3' if mode == 'fresh' else '45'], stdout=out, stderr=err, env=env)
        try:
            deadline = time.monotonic() + 10
            while 'NODE instance=' not in outpath.read_text() and time.monotonic() < deadline:
                assert child.poll() is None, errpath.read_text()
                time.sleep(.05)
            banner = next(line for line in outpath.read_text().splitlines() if line.startswith('NODE '))
            assert ('mode=CM1' if mode in ('pair', 'fresh') else 'mode=CM0') in banner, banner
            port = next(field[5:] for field in banner.split() if field.startswith('port='))
            zc = browser = None
            if a.mdns and mode in ('pair', 'self'):
                from test_discovery_network import Listener
                from zeroconf import IPVersion, ServiceBrowser, Zeroconf
                from importlib.metadata import version
                assert version('zeroconf') == '0.147.0'
                listener = Listener()
                zc = Zeroconf(interfaces=[a.interface], ip_version=IPVersion.V6Only)
                browser = ServiceBrowser(zc, '_matter._tcp.local.', listener)
            if mode != 'fresh':
                with (run / (mode + '.controller.log')).open('w') as log:
                    result = subprocess.run([a.node, 'tools/matter/tests/host_fabrics.mjs', a.modules, mode, a.ipv6 + '%' + str(a.interface), port, run.name], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=65)
                text = (run / (mode + '.controller.log')).read_text()
                assert result.returncode == 0, text[-5000:]
                assert ('LAST_REMOVE_CONFIRMED' if mode == 'last' else 'PASS ' + mode) in text
                if zc:
                    names = [line.split('instance=')[1] + '._matter._tcp.local.' for line in outpath.read_text().splitlines() if line.startswith('FABRIC index=')]
                    assert len(names) == 2, names
                    listener.wait({('_matter._tcp.local.', name) for name in names})
                    listener.wait({('_matter._tcp.local.', names[1])}, removed=True)
                    assert ('_matter._tcp.local.', names[0]) not in listener.removed
                    browser.cancel()
                    zc.close()
                    browser = zc = None
            assert child.wait(timeout=50) == 0, errpath.read_text()
            assert not errpath.read_text(), errpath.read_text()
            assert 'STOPPED' in outpath.read_text() and 'result=0' in outpath.read_text()
            if mode == 'last':
                assert 'RESET last fabric removed' in outpath.read_text()
            if mode == 'fresh':
                assert 'FABRIC index=' not in outpath.read_text()
        finally:
            if 'browser' in locals() and browser:
                browser.cancel()
            if 'zc' in locals() and zc:
                zc.close()
            if child.poll() is None:
                child.kill()
                child.wait()
print('PASS multi-fabric commissioning, labels, selective other/self removal, durable restart, last reset and fresh CM1:', run)
