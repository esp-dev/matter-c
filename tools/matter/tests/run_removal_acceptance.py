"""Disposable Linux application + unmodified chip-tool: RemoveFabric response/drain.

Separate normal/Memcheck and sanitizer invocations. Never use production state.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from chip_tool_resources import Client


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('node', 'credentials', 'chip-tool', 'paa', 'output'):
        p.add_argument('--'+key, required=True, type=Path)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--port', type=int, default=5545)
    p.add_argument('--discriminator', type=int, default=3845)
    p.add_argument('--valgrind', action='store_true')
    p.add_argument('--sanitize', action='store_true')
    a = p.parse_args()
    if a.valgrind and a.sanitize: p.error('Run sanitizers separately from Memcheck')
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'TH01c application/CHIP regression, not CSA certification', 'checks': []}
    def check(name, ok):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL'})
        (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print(('PASS ' if ok else 'FAIL ')+name, flush=True)
        if not ok: raise RuntimeError(name)
    shim = out/'removal-faults.so'
    san = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if a.sanitize else []
    subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', *san,
                    str(Path(__file__).with_name('removal_faults_linux.c')), '-ldl', '-o', str(shim)], check=True)
    preload = (subprocess.check_output(['gcc', '-print-file-name=libasan.so'], text=True).strip()+':' if a.sanitize else '')+str(shim)
    for mode in ('normal', 'loss', 'noack', 'restart'):
        phase = out/mode; phase.mkdir()
        # Restart the final no-ACK reset image without deleting or editing it.
        state = (out/'noack' if mode == 'restart' else phase)/'state.tlv'
        marker = phase/'armed'
        command = [str(a.node.resolve()), '--interface', str(a.interface), '--port', str(a.port),
                   '--discriminator', str(a.discriminator), '--credentials', str(a.credentials.resolve()),
                   '--state', str(state), '--seconds', '180', '--case-resumption-profile', 'chip']
        if a.valgrind:
            command = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                       '--track-origins=yes', '--error-exitcode=99', '--log-file='+str(phase/'memcheck.log'), *command]
        (phase/'node.command').write_text(shlex.join(command)+'\n')
        env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        if mode in ('loss', 'noack'):
            env.update(LD_PRELOAD=preload, MATTER_REMOVE_MARKER=str(marker), MATTER_REMOVE_PORT=str(a.port),
                       MATTER_REMOVE_MODE=mode, MATTER_REMOVE_LOG=str(phase/'faults.log'))
        client = None
        with (phase/'node.log').open('w') as log, (phase/'node.err').open('w') as err:
            child = subprocess.Popen(command, stdout=log, stderr=err, env=env)
            try:
                until = time.monotonic()+30
                while child.poll() is None and time.monotonic()<until and 'PUBLISHED' not in (phase/'node.log').read_text(): time.sleep(.05)
                text = (phase/'node.log').read_text()
                check(mode+'-fresh-window', child.poll() is None and 'PUBLISHED' in text and 'mode=CM1' in text)
                client = Client(a.chip_tool.resolve(), a.paa.resolve(), phase, 'controller', advertise=False)
                ok, data = client.command(['pairing', 'onnetwork-long', 1, 20202021, a.discriminator, '--timeout', 45],
                                          r'Device commissioning completed with success', timeout=60)
                check(mode+'-commissioning', ok and "Successfully finished commissioning step 'AttestationVerification'" in data)
                ok, data = client.command(['operationalcredentials', 'read', 'commissioned-fabrics', 1, 0], r'CommissionedFabrics:')
                check(mode+'-single-fabric', ok and re.search(r'CommissionedFabrics:\s*1\b', data) is not None)
                ok, data = client.command(['operationalcredentials', 'remove-fabric', 254, 1, 0], r'NOCResponse:[\s\S]*?\}')
                check(mode+'-invalid-index', ok and re.search(r'statusCode:\s*11\b', data) is not None)
                ok, _ = client.command(['electricalpowermeasurement', 'read', 'active-power', 1, 1], r'ActivePower:')
                check(mode+'-read-after-invalid', ok and child.poll() is None)
                if mode == 'normal':
                    ok, _ = client.command(['electricalpowermeasurement', 'subscribe', 'active-power', 0, 10, 1, 1], r'Subscription established')
                    check('normal-live-subscription', ok)
                # Let the preceding Read's ACK leave before arming the faults.
                time.sleep(.5)
                if mode in ('loss', 'noack'): marker.touch()
                started = time.monotonic()
                ok, data = client.command(['operationalcredentials', 'remove-fabric', 1, 1, 0], r'NOCResponse:[\s\S]*?\}', timeout=35)
                check(mode+'-noc-response', ok and re.search(r'statusCode:\s*0\b', data) is not None and re.search(r'fabricIndex:\s*1\b', data) is not None)
                image = state.read_bytes()
                child.wait(timeout=40)
                check(mode+'-bounded-clean-exit', child.returncode == 0 and time.monotonic()-started<40)
                check(mode+'-reset-not-republished', state.read_bytes() == image)
            finally:
                if client: client.close()
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=30)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(); raise
        check(mode+'-stderr-empty', not (phase/'node.err').stat().st_size)
        check(mode+'-reset-once', (phase/'node.log').read_text().count('RESET last fabric removed') == 1)
        if a.valgrind:
            text = (phase/'memcheck.log').read_text()
            check(mode+'-memcheck', 'ERROR SUMMARY: 0 errors' in text and 'in use at exit: 0 bytes in 0 blocks' in text)
        if mode in ('loss', 'noack'):
            text = (phase/'faults.log').read_text()
            check(mode+'-fault-covered', 'response retry same=1' in text and ('request duplicated' in text and 'response first dropped' in text if mode=='loss' else 'rx dropped' in text))
    return 0


if __name__ == '__main__': raise SystemExit(main())
