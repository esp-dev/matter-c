"""Independent OTA Provider, existing CASE and fresh outbound CASE after restart."""
import argparse
import os
from pathlib import Path
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--exe', required=True)
p.add_argument('--node', required=True)
p.add_argument('--modules', required=True)
p.add_argument('--credentials', required=True)
p.add_argument('--interface', type=int, required=True)
p.add_argument('--ipv6', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
run = Path(a.output).resolve()
run.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
base = [str(Path(a.exe).resolve()), '--interface', str(a.interface), '--credentials', a.credentials,
        '--state', str(run/'state.tlv'), '--seconds', '110']
provider = None
node = None
logs = []
def wait(test, timeout=50):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if test(): return
        if node and node.poll() is not None: raise AssertionError('node stopped prematurely')
        if provider and provider.poll() is not None: raise AssertionError('provider stopped prematurely')
        time.sleep(.05)
    raise AssertionError('OTA network timeout')
def launch(phase):
    out = (run/f'{phase}.node.log').open('w')
    err = (run/f'{phase}.node.err').open('w')
    logs.extend([out, err])
    return subprocess.Popen(base, stdout=out, stderr=err, env=env)
def stop():
    node.terminate()
    assert node.wait(timeout=15) == 0
try:
    node = launch('first')
    wait(lambda: 'NODE instance=' in (run/'first.node.log').read_text())
    banner = next(x for x in (run/'first.node.log').read_text().splitlines() if x.startswith('NODE '))
    port = next(x[5:] for x in banner.split() if x.startswith('port='))
    log = (run/'provider.log').open('w'); logs.append(log)
    provider = subprocess.Popen([a.node, 'tools/matter/tests/host_ota_provider.mjs', a.modules,
        a.ipv6+'%'+str(a.interface), port, str(run)], stdout=log, stderr=subprocess.STDOUT, env=env)
    wait(lambda: (run/'restart-ready').exists())
    stop()
    node = launch('restart')
    wait(lambda: (run/'provider-pass').exists(), 70)
    wait(lambda: 'OTA_STATE state=1 reason=1' in (run/'restart.node.log').read_text())
    stop()
    (run/'node-stopped').write_text('stopped')
    assert provider.wait(timeout=15) == 0
    for phase in ('first', 'restart'):
        assert not (run/f'{phase}.node.err').read_text()
        assert 'result=0' in (run/f'{phase}.node.log').read_text()
    print('PASS OTA Provider network: CASE reuse, Busy/state, durable restart, outgoing discovery/CASE/Invoke, NotAvailable, clean drain:', run)
finally:
    for proc in (node, provider):
        if proc and proc.poll() is None: proc.kill(); proc.wait()
    for log in logs: log.close()
