"""Independent CASE credential rotation, timeout and process-crash recovery."""
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
p.add_argument('--mdns', action='store_true', help='Verify announcements/goodbyes with pinned zeroconf')
a = p.parse_args()
run = Path('build') / ('update-network-' + uuid.uuid4().hex)
run.mkdir()
env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else '') + os.environ['PATH'], ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
subprocess.run([a.node, 'tools/matter/tests/host_controller.mjs', a.modules, 'credentials', str(run / 'credentials')], check=True, env=env, timeout=30)
base = [str(Path(a.exe).resolve()), '--interface', str(a.interface), '--credentials', str(run / 'credentials'), '--state', str(run / 'state.tlv')]
for mode in ('pair', 'timeout', 'crash', 'recovery'):
    outpath, errpath = run / (mode + '.node.log'), run / (mode + '.node.err')
    with outpath.open('w') as out, errpath.open('w') as err:
        zc = browser = None
        if a.mdns:
            from test_discovery_network import Listener
            from zeroconf import IPVersion, ServiceBrowser, Zeroconf
            from importlib.metadata import version
            assert version('zeroconf') == '0.147.0'
            listener = Listener()
            zc = Zeroconf(interfaces=[a.interface], ip_version=IPVersion.V6Only)
            browser = ServiceBrowser(zc, '_matter._tcp.local.', listener)
        child = subprocess.Popen(base + ['--seconds', '35'], stdout=out, stderr=err, env=env)
        try:
            deadline = time.monotonic() + 10
            while 'NODE instance=' not in outpath.read_text() and time.monotonic() < deadline:
                assert child.poll() is None, errpath.read_text()
                time.sleep(.05)
            banner = next(line for line in outpath.read_text().splitlines() if line.startswith('NODE '))
            assert ('mode=CM1' if mode == 'pair' else 'mode=CM0') in banner, banner
            port = next(field[5:] for field in banner.split() if field.startswith('port='))
            with (run / (mode + '.controller.log')).open('w') as log:
                result = subprocess.run([a.node, 'tools/matter/tests/host_update.mjs', a.modules, mode,
                    a.ipv6 + '%' + str(a.interface), port, run.name, str(run / 'ca.bin')],
                    env=env, stdout=log, stderr=subprocess.STDOUT, timeout=50)
            text = (run / (mode + '.controller.log')).read_text()
            assert result.returncode == 0, text[-7000:]
            assert ('CRASH_READY' if mode == 'crash' else 'PASS ' + mode) in text
            if zc:
                # UpdateNOC response can precede completion of old publisher
                # goodbye/drain. Wait for the target publication before querying.
                target = '0000000000000004' if mode == 'crash' else '0000000000000002'
                deadline = time.monotonic() + 6
                while True:
                    names = [line.split('instance=')[1] + '._matter._tcp.local.' for line in outpath.read_text().splitlines() if line.startswith('FABRIC index=1 ')]
                    if names and names[-1].endswith(target + '._matter._tcp.local.'):
                        break
                    assert time.monotonic() < deadline, (mode, names)
                    time.sleep(.05)
                listener.wait({('_matter._tcp.local.', names[-1])})
                if mode in ('pair', 'timeout'):
                    listener.wait({('_matter._tcp.local.', names[-2])})
                    listener.wait({('_matter._tcp.local.', names[-2])}, removed=True)
                # The same Node ID can reappear after restart on a new UDP port.
                # Discovery has asynchronous probes/announcements; wait for the
                # fresh SRV instead of accepting an earlier cached answer.
                deadline = time.monotonic() + 6
                info = None
                while time.monotonic() < deadline:
                    info = zc.get_service_info('_matter._tcp.local.', names[-1], timeout=1000)
                    if info is not None and info.port == int(port):
                        break
                    time.sleep(.1)
                assert info is not None and info.port == int(port), names
                browser.cancel()
                zc.close()
                browser = zc = None
            if mode == 'crash':
                child.kill()
                child.wait()
            else:
                assert child.wait(timeout=40) == 0, errpath.read_text()
                assert 'STOPPED' in outpath.read_text() and 'result=0' in outpath.read_text()
            assert not errpath.read_text(), errpath.read_text()
            names = [line for line in outpath.read_text().splitlines() if line.startswith('FABRIC index=1 ')]
            if mode == 'pair':
                assert any(line.endswith('0000000000000002') for line in names), names
            if mode == 'timeout':
                assert len(names) == 3 and names[1].endswith('0000000000000003') and names[2].endswith('0000000000000002'), names
            if mode == 'recovery':
                assert len(names) == 1 and names[0].endswith('0000000000000002'), names
        finally:
            if browser:
                browser.cancel()
            if zc:
                zc.close()
            if child.poll() is None:
                child.kill()
                child.wait()
print('PASS UpdateNOC: independent CASE/CSR, new Node ID/key, selective retirement, durable commit, timeout and crash recovery:', run)
