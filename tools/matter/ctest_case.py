"""Run file-writing C regressions in a fresh private directory on every run."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--exe', required=True)
p.add_argument('--mode', choices=('normal', 'file', 'store', 'crash'), default='normal')
p.add_argument('--script')
a = p.parse_args()
# CTest's build directory is writable even in restricted Windows environments;
# avoid the account-wide temporary directory and isolate repeated/parallel runs.
with tempfile.TemporaryDirectory(prefix='matter-ctest-', dir=Path.cwd()) as directory:
    env = dict(os.environ, MATTER_TEST_STORE_DIR=directory)
    def run(*args):
        subprocess.run([a.exe, *args], cwd=directory, env=env, check=True, timeout=120)
    if a.mode == 'store':
        for mode in ('committed', 'pending'):
            for phase in ('seed', 'load'):
                run(phase, str(Path(directory) / (mode + '.tlv')), mode)
    elif a.mode == 'file':
        run(str(Path(directory) / 'state.bin'))
    elif a.mode == 'crash':
        import sys
        subprocess.run([sys.executable, a.script, '--exe', a.exe, '--output', str(Path(directory) / 'cases')],
                       cwd=directory, env=env, check=True, timeout=120)
    else:
        run()
