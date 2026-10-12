"""Real Windows node: transient external readers during EEM checkpoints, restart.

Uses fresh development credentials/state in build/, never the live paired node.
Pass an isolated test-network interface. No firewall/network configuration edits.
"""
import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exe', required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--runtime', default='')
    p.add_argument('--node', default='node')
    p.add_argument('--modules', default='build/matter-controller/node_modules')
    a = p.parse_args()
    assert os.name == 'nt', 'Windows file sharing test'
    run = Path('build') / ('node-store-lock-' + uuid.uuid4().hex)
    run.mkdir()
    env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else '') + os.environ['PATH'],
               ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    subprocess.run([a.node, 'tools/matter/tests/host_controller.mjs', a.modules,
                    'credentials', str(run / 'credentials')], check=True, env=env, timeout=30)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    sample = re.compile(r'SAMPLE power_mW=-?\d+ import_mWh=(\d+) export_mWh=(\d+) next_event=(\d+)')
    previous = None
    for phase, seconds in [('locks', 10), ('restart', 3)]:
        outpath, errpath = run / (phase + '.log'), run / (phase + '.err')
        with outpath.open('w') as out, errpath.open('w') as err:
            command = [str(Path(a.exe).resolve()), '--interface', str(a.interface), '--seconds', str(seconds),
                       '--discriminator', '3842', '--credentials', str(run / 'credentials'),
                       '--state', str(run / 'state.tlv')]
            child = subprocess.Popen(command, stdout=out, stderr=err, env=env)
            held = 0
            try:
                until = time.monotonic() + seconds + 5
                while child.poll() is None and time.monotonic() < until:
                    if phase == 'locks':
                        # GENERIC_READ, FILE_SHARE_READ: deny replacement, allow read.
                        h = kernel.CreateFileW(str((run / 'state.tlv').resolve()), 0x80000000, 1, None, 3, 0x80, None)
                        if h != ctypes.c_void_p(-1).value:
                            try:
                                held += 1
                                time.sleep(.075)
                            finally:
                                assert kernel.CloseHandle(h)
                        else:
                            assert ctypes.get_last_error() in (2, 5, 32)
                    time.sleep(.05)
                assert child.wait(timeout=5) == 0, errpath.read_text()
            finally:
                if child.poll() is None:
                    child.kill()  # Only this test's child, after failure.
                    child.wait()
        log, errors = outpath.read_text(), errpath.read_text()
        values = [tuple(map(int, x)) for x in sample.findall(log)]
        assert len(values) >= seconds - 1 and 'result=0' in log, log[-2000:]
        assert all(all(b >= a for a, b in zip(x, y)) for x, y in zip(values, values[1:]))
        if phase == 'locks':
            assert held > 0 and 'STORE replace recovered' in errors, errors
            assert all(re.fullmatch(r'STORE replace recovered after [1-5] retries', line) for line in errors.splitlines()), errors
        else:
            assert not errors, errors
            assert all(x >= y for x, y in zip(values[0], previous)), (values[0], previous)
        previous = values[-1]
        print('PASS', phase, 'samples=', len(values), 'recoveries=', errors.count('recovered'))
    print('PASS Windows node checkpoint locks, graceful stop and durable restart:', run)


if __name__ == '__main__':
    main()
