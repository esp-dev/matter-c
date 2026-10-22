"""Run the opt-in native UDP/RGB regression with pinned Matter.js0.17.9.

Every invocation creates fresh private state below --output. Raw controller logs
contain development credentials. No board, AP, existing fabric or UART is used.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid


def wait_ready(host, log, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if host.poll() is not None:
            raise RuntimeError(f"fixture exited {host.returncode} before WIRE_READY; see {log}")
        if 'WIRE_READY' in log.read_text(encoding='utf-8'):
            return
        time.sleep(.05)
    raise TimeoutError(f"fixture not ready; see {log}")


def run_case(args, name, root):
    out = root / name
    out.mkdir()
    tick, delay, order, faults = (1, 0, 'before', False) if name == 'before' else (10, 25, 'after', True)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
        probe.bind(('::1', 0))
        port = probe.getsockname()[1]
    env = dict(os.environ, MATTER_SOAK_ATTRIBUTES='171', MATTER_WIRE_PORT=str(port),
               MATTER_WIRE_COMPLETION_MS=str(delay), MATTER_WIRE_FAULTS='1' if faults else '0')
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    env.setdefault('UBSAN_OPTIONS', 'halt_on_error=1:print_stacktrace=1')
    host_args = [str(args.host), str(out), str(port), str(tick), str(delay), order]
    if args.memcheck:
        host_args = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--track-origins=yes',
                     '--errors-for-leak-kinds=definite,indirect,possible', '--error-exitcode=99',
                     '--log-file=' + str(out / 'memcheck.log'), *host_args]
    oracle = Path(__file__).resolve().parents[3] / 'examples/esp32-runtime/tests/soak.mjs'
    node_args = [args.node, str(oracle), str(args.modules), '::1', str(out / 'state'), str(out),
                 '60', args.interface, 'host', 'wildcard']
    (out / 'command.json').write_text(json.dumps(dict(host=host_args, controller=node_args,
        tick_ms=tick, completion_ms=delay, poll_order=order, faults=faults), indent=2), encoding='utf-8')
    with (out / 'host.log').open('w', encoding='utf-8') as log:
        host = subprocess.Popen(host_args, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            wait_ready(host, out / 'host.log', 40)
            with (out / 'controller.log').open('w', encoding='utf-8') as controller:
                result = subprocess.run(node_args, stdout=controller, stderr=subprocess.STDOUT, env=env, timeout=540)
            if result.returncode:
                raise RuntimeError(f"controller exited {result.returncode}; see {out}")
        finally:
            if host.poll() is None:
                # Failures also ask the real owner to stop/drain. Never kill an
                # unrelated process or accept forced termination as a clean run.
                temporary = out / 'cleanup.tmp'
                temporary.write_text('deadbeef:0 x\n', encoding='ascii')
                temporary.replace(out / 'wire-request.txt')
                try:
                    host.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    host.kill()
                    host.wait()
                    raise RuntimeError(f"fixture failed to drain; see {out}")
        if host.returncode or 'WIRE_PASS live=0' not in (out / 'host.log').read_text(encoding='utf-8'):
            raise RuntimeError(f"fixture failed or leaked; see {out}")
    summary = json.loads((out / 'controller-results.json').read_text(encoding='utf-8'))
    stats = summary.get('host_stats', {})
    if not (summary.get('pass') is True and summary['subscription_snapshots'] >= 30 and
            summary['host_close_reconnect_cycles'] == 1 and summary['delayed_completion_cycles'] == 1 and
            summary['session_busy_probes'] == 1 and summary['unexpected_subscription_closures'] == 0 and summary.get('host_peer_closes') == 15 and
            stats.get('core_live') == 0 and stats.get('core_bytes') == 0 and stats.get('rx_reordered', 0) > 0 and
            stats.get('ack_after_completion', 0) > 0 and stats.get('core_failures') == (3 if faults else 0)):
        raise RuntimeError(f"incomplete oracle coverage; see {out}")
    if faults and not (summary['oom_cycles'] == 3 and summary.get('ack_negative_controls') == 1 and summary.get('ack_session_survived') is True and
                       stats.get('ack_before_completion', 0) > 0 and stats.get('unacknowledged', 0) > 0):
        raise RuntimeError(f"fault was not exercised; see {out}")
    if args.memcheck:
        data = (out / 'memcheck.log').read_text(encoding='utf-8')
        if 'ERROR SUMMARY: 0 errors' not in data or 'in use at exit: 0 bytes in 0 blocks' not in data:
            raise RuntimeError(f"Memcheck not clean; see {out}")
    return dict(case=name, pass_=True, elapsed_seconds=summary['elapsed_seconds'],
                subscription_snapshots=summary['subscription_snapshots'], full_reads=summary['full_reads'],
                oom_cycles=summary['oom_cycles'], stats=stats)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--node', default='node')
    parser.add_argument('--modules', required=True, type=Path)
    parser.add_argument('--interface', default='')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', choices=['all', 'before', 'after'], default='all')
    parser.add_argument('--memcheck', action='store_true')
    args = parser.parse_args()
    args.host = args.host.resolve()
    args.modules = args.modules.resolve()
    if not args.host.is_file():
        parser.error('--host must name an existing runtime-wire-host executable')
    package = args.modules / '@project-chip/matter.js/package.json'
    if not package.is_file() or json.loads(package.read_text(encoding='utf-8'))['version'] != '0.17.9':
        parser.error('--modules must contain Matter.js0.17.9')
    root = args.output.resolve() / (time.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8])
    root.mkdir(parents=True)
    results = []
    try:
        for name in (['before', 'after'] if args.case == 'all' else [args.case]):
            results.append(run_case(args, name, root))
            print(json.dumps(results[-1]), flush=True)
    finally:
        (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
