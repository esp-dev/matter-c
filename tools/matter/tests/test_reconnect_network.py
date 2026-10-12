"""One C host lifetime, independent CASE sessions and abrupt peer disappearance."""
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
a = p.parse_args()
run = Path('build') / ('reconnect-network-' + uuid.uuid4().hex)
run.mkdir()
env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else '') + os.environ['PATH'], ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
subprocess.run([a.node, 'tools/matter/tests/host_controller.mjs', a.modules, 'credentials', str(run / 'credentials')], check=True, env=env, timeout=30)
outpath, errpath = run / 'node.log', run / 'node.err'
with outpath.open('w') as out, errpath.open('w') as err:
    child = subprocess.Popen([str(Path(a.exe).resolve()), '--interface', str(a.interface), '--credentials', str(run / 'credentials'),
                              '--state', str(run / 'state.tlv'), '--seconds', '90'], stdout=out, stderr=err, env=env)
    try:
        deadline = time.monotonic() + 10
        while 'NODE instance=' not in outpath.read_text() and time.monotonic() < deadline:
            assert child.poll() is None, errpath.read_text()
            time.sleep(.05)
        banner = next(line for line in outpath.read_text().splitlines() if line.startswith('NODE '))
        assert 'mode=CM1' in banner, banner
        port = next(field[5:] for field in banner.split() if field.startswith('port='))
        with (run / 'controller.log').open('w') as log:
            result = subprocess.run([a.node, 'tools/matter/tests/host_reconnect.mjs', a.modules, a.ipv6 + '%' + str(a.interface), port, run.name],
                                    env=env, stdout=log, stderr=subprocess.STDOUT, timeout=85)
        text = (run / 'controller.log').read_text()
        assert result.returncode == 0, text[-6000:]
        assert 'PASS reconnect:' in text and 'PASS reconnect 12' in text
        assert child.wait(timeout=75) == 0, errpath.read_text()
        assert not errpath.read_text(), errpath.read_text()
        assert 'STOPPED' in outpath.read_text() and 'result=0' in outpath.read_text()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
print('PASS reconnect, subscriptions and bounded sessions without host restart:', run)
