"""TC-IDM-7.1 laboratory observations with five real chip-tool fabrics.

Four fresh simulated Node lifetimes use the same binary/credentials and separate
empty stores, equivalent to factory reset between scenarios. No production
store is removed. Original manual TH acceptance is a separate recorded step.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from chip_tool_resources import Client
from chip_tool_energy_profile import frames, integer


READ_DONE = r'SuppressResponse = true[\s\S]*Flushed pending ack for MessageCounter:'


def reports(text):
    """Associate decoded attribute values with the actual Report SubscriptionId."""
    starts = [m.start() for m in re.finditer(r'\[DMG\]\s*ReportDataMessage =', text)]
    result = []
    for i, start in enumerate(starts):
        part = text[start:starts[i + 1] if i + 1 < len(starts) else len(text)]
        match = re.search(r'\[DMG\]\s*SubscriptionId = (0x[0-9a-fA-F]+)\b', part)
        if match:
            result.append((int(match[1], 16), frames(part)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--valgrind', action='store_true')
    parser.add_argument('--start-phase', type=int, choices=range(4), default=0,
                        help='Resume independent reset scenarios; omitted earlier phases need separate evidence.')
    parser.add_argument('--end-phase', type=int, choices=range(1, 5), default=4,
                        help='Exclusive end of independent reset scenarios.')
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    if args.start_phase >= args.end_phase:
        parser.error('start-phase must precede end-phase')
    report = {'scope': __doc__, 'result': 'RUNNING', 'phases': [], 'start_phase': args.start_phase,
              'end_phase': args.end_phase,
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(args.exe.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(args.chip_tool.read_bytes()).hexdigest()}

    def save():
        temporary = out / 'result.json.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(out / 'result.json')

    for phase in range(args.start_phase, args.end_phase):
        root = out / ('phase-' + str(phase)); root.mkdir()
        current = {'phase': phase, 'result': 'RUNNING', 'checks': [], 'subscriptions': [], 'attempts': []}
        report['phases'].append(current); save()
        clients = []; node = None; handles = []; subscriptions = {}; accepted = set()

        def check(name, ok):
            current['checks'].append({'name': name, 'status': 'PASS' if ok else 'FAIL'})
            save(); print(('PASS ' if ok else 'FAIL ') + str(phase) + ' ' + name, flush=True)
            if not ok:
                raise AssertionError(name)

        def client(name, source=None):
            c = Client(args.chip_tool, args.paa, root, name, source=source, advertise=False)
            clients.append(c); subscriptions[c] = []; return c

        def command(c, argv, pattern=READ_DONE, failure=False):
            if pattern == r'status = 0x00':
                # Active subscriptions also generate successful Status messages.
                # Wait for this command's response class and its ACK completion.
                response = 'WriteResponseMessage' if argv[1] == 'write' else 'InvokeResponseMessage'
                pattern = response + r' =[\s\S]*status = 0x00\b[\s\S]*Flushed pending ack for MessageCounter:'
            ok, text = c.command(argv, pattern, timeout=65, failure=failure)
            check('command-' + '-'.join(map(str, argv[:2])), ok)
            return text

        def subscribe(c, paths=3, extra=None, required=True):
            clusters = ['0x28', '0x28', '0x3', '0x28', '0x28', '0x28'][:paths]
            attributes = ['5', '6', '0', '9', '2', '4'][:paths]
            endpoints = ['0', '0', '1', '0', '0', '0'][:paths]
            data = command(c, ['any', 'subscribe-by-id', ','.join(clusters), ','.join(attributes),
                              1, 3, 1, ','.join(endpoints), '--keepSubscriptions', 'true', *(extra or [])],
                           r'Subscription established|Run command failure:.*0x000005(?:89|9[Cc])\b', failure=True)
            found = re.findall(r'SubscribeResponseMessage =[\s\S]*?SubscriptionId = (0x[0-9a-fA-F]+)\b', data)
            admitted = 'Subscription established' in data
            errors = re.findall(r'(?:status|Status)\s*=\s*0x(89|9c)\b', data)
            row = {'controller': c.directory.name, 'paths': paths, 'admitted': admitted,
                   'status': 0 if admitted else int(errors[-1], 16)}
            if admitted:
                check('new-unique-subscription-ID', len(found) == 1 and int(found[0], 16) not in accepted)
                identifier = int(found[0], 16); accepted.add(identifier); subscriptions[c].append(identifier)
                wanted = {(int(ep), int(cluster, 16), int(attribute))
                          for ep, cluster, attribute in zip(endpoints, clusters, attributes)}
                actual = {f['path'] for sid, attrs in reports(data) if sid == identifier
                          for f in attrs if f['kind'] == 'Attribute'}
                check('complete-requested-prime-paths', actual == wanted)
                row['id'] = identifier; current['subscriptions'].append(row)
            else:
                # Extra requests may see BUSY while an earlier overflow reply
                # drains. Neither status counts as an admitted subscription;
                # requests within the guaranteed three must still succeed.
                check('bounded-capacity-rejection', bool(errors))
            current['attempts'].append(row); save()
            if required:
                check('guaranteed-three-path-subscription', admitted)
            return admitted

        def changes(controllers, round_number):
            offsets = {c: len(c.text()) for c in controllers}
            previous = {f['path']: f['body'] for f in frames(controllers[0].text()) if f['kind'] == 'Attribute'}
            label = 'csa48p' + str(phase) + 'r' + str(round_number)
            if re.search(r'^NodeLabel: ' + label + r'\s*$', previous[0, 0x28, 5], re.M):
                label += 'x'
            location = 'FR' if re.search(r'^Location: DE\s*$', previous[0, 0x28, 6], re.M) else 'DE'
            command(controllers[0], ['basicinformation', 'write', 'node-label', label, 1, 0], r'status = 0x00')
            command(controllers[0], ['basicinformation', 'write', 'location', location, 1, 0], r'status = 0x00')
            command(controllers[0], ['identify', 'identify', 30 + round_number * 10, 1, 1], r'status = 0x00')
            seen = {identifier: set() for c in controllers for identifier in subscriptions[c]}
            until = time.monotonic() + 9
            while time.monotonic() < until:
                for c in controllers:
                    for identifier, attrs in reports(c.text()[offsets[c]:]):
                        if identifier not in subscriptions[c]:
                            continue
                        for f in attrs:
                            if f['kind'] != 'Attribute':
                                continue
                            if f['path'] == (0, 0x28, 5) and re.search(r'^NodeLabel: ' + label + r'\s*$', f['body'], re.M):
                                seen[identifier].add('label')
                            if f['path'] == (0, 0x28, 6) and re.search(r'^Location: ' + location + r'\s*$', f['body'], re.M):
                                seen[identifier].add('location')
                            if f['path'] == (1, 3, 0) and integer(f['body'], 'IdentifyTime') > 0:
                                seen[identifier].add('identify')
                if seen and all(len(paths) == 3 for paths in seen.values()):
                    break
                time.sleep(.05)
            current.setdefault('updates', []).append({'round': round_number, 'subscriptions': len(seen),
                                                       'observed_paths': {str(k): sorted(v) for k, v in seen.items()},
                                                       'all_three_changed_paths': all(len(v) == 3 for v in seen.values())})
            check('all-live-subscriptions-receive-three-changed-paths-' + str(round_number),
                  len(seen) == 15 and all(len(v) == 3 for v in seen.values()))

        try:
            argv = [str(args.exe), '--interface', str(args.interface), '--port', '5588', '--seconds', '600',
                    '--credentials', str(args.credentials), '--state', str(root / 'state.tlv'),
                    '--pin', '20202021', '--discriminator', '3916', '--subscriptions-per-fabric', '3',
                    '--three-phase', '--source-registers', '--meter-services', '--wifi-sim-connected']
            if args.valgrind:
                argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                        '--track-origins=yes', '--error-exitcode=99', '--log-file=' + str(root / 'memcheck.log'), *argv]
            handles = [(root / ('node.' + suffix)).open('w') for suffix in ('log', 'err')]
            node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1], env=dict(os.environ,
                                    ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
            until = time.monotonic() + 40
            while time.monotonic() < until and node.poll() is None and 'PUBLISHED' not in (root / 'node.log').read_text():
                time.sleep(.05)
            check('fresh-node-published', node.poll() is None and 'PUBLISHED' in (root / 'node.log').read_text())
            controllers = []; fabrics = []; pin = 20202021
            for index in range(5):
                c = client('RD' + str(index + 1)); controllers.append(c)
                if index:
                    opened = command(controllers[0], ['pairing', 'open-commissioning-window', 1, 1, 180, 1000, 3917],
                                     r'Manual pairing code: \[\d+\]')
                    code = re.search(r'Manual pairing code: \[(\d+)\]', opened)[1]
                    parsed = command(controllers[0], ['payload', 'parse-setup-payload', code], r'Passcode:\s*\d+')
                    pin = int(re.search(r'Passcode:\s*(\d+)', parsed)[1])
                data = command(c, ['pairing', 'already-discovered', 1, pin, args.ipv6 + '%' + str(args.interface), 5588,
                                   '--country-code', 'PL', '--timeout', 45], r'Device commissioning completed with success')
                check('verified-attestation-' + str(index), "Successfully finished commissioning step 'AttestationVerification'" in data)
                data = command(c, ['operationalcredentials', 'read', 'current-fabric-index', 1, 0])
                fabrics.append(integer(next(f['body'] for f in frames(data) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex'))
            check('five-distinct-commissioned-fabrics', len(set(fabrics)) == 5)
            data = command(controllers[0], ['basicinformation', 'read', 'capability-minima', 1, 0])
            check('declared-subscription-guarantees', 'SubscriptionsPerFabric: 3' in data and 'SubscribePathsSupported: 3' in data)
            if phase == 3:
                acl = [dict(privilege=5, authMode=2, subjects=None, targets=None)]
                command(controllers[0], ['accesscontrol', 'write', 'acl', json.dumps(acl), 1, 0], r'status = 0x00')
            order = controllers[1:] if phase == 2 else controllers
            for c in order:
                for slot in range(3):
                    if phase == 1 and c == controllers[0] and slot == 0:
                        supported = subscribe(c, paths=4, required=False); current['four_path_supported'] = supported
                        if not supported:
                            subscribe(c)
                    else:
                        subscribe(c)
            if phase == 2:
                for _ in range(6):
                    subscribe(controllers[0], required=len(subscriptions[controllers[0]]) < 3)
                # Original verification also shows one six-path request instead
                # of the label's six requests. Exercise that shape separately.
                subscribe(controllers[0], paths=6, required=False)
            check('fifteen-live-subscriptions', sum(map(len, subscriptions.values())) == 15)
            changes(controllers, 0)
            if phase == 1:
                subscribe(controllers[0], paths=4, required=False)
            if phase == 3:
                extra = client('RD1A', source=controllers[0].storage)
                subscribe(extra, extra=['--commissioner-nodeid', '2'], required=False)
                acl = [dict(privilege=5, authMode=2, subjects=[112233, 2], targets=None)]
                command(extra, ['accesscontrol', 'write', 'acl', json.dumps(acl), 1, 0, '--commissioner-nodeid', '2'], r'status = 0x00')
                data = command(controllers[0], ['accesscontrol', 'read-event', 'access-control-entry-changed', 1, 0])
                check('RD1A-authenticated-as-distinct-node-2', bool(re.search(r'AdminNodeID: 2\b', data)))
            changes(controllers, 1)
            current['result'] = 'PASS'
        except (AssertionError, KeyError, StopIteration, ValueError, OSError, subprocess.SubprocessError) as error:
            current['result'] = 'FAIL'; current['error'] = str(error)
        finally:
            for c in reversed(clients):
                c.close()
            current['controller_exits'] = {c.directory.name: c.child.returncode for c in clients}
            if any(c.child.returncode for c in clients):
                current['result'] = 'FAIL'; current['cleanup_error'] = 'Controller exit'
            if node is not None:
                if node.poll() is None:
                    node.terminate()
                try:
                    node.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    node.kill(); node.wait()
                current['node_exit'] = node.returncode
                if node.returncode or (root / 'node.err').read_bytes():
                    current['result'] = 'FAIL'; current['cleanup_error'] = 'Node exit or stderr'
            for handle in handles:
                handle.close()
            if args.valgrind and (root / 'memcheck.log').exists():
                text = (root / 'memcheck.log').read_text()
                current['memory'] = {'zero_errors': 'ERROR SUMMARY: 0 errors' in text,
                                     'zero_live': 'in use at exit: 0 bytes in 0 blocks' in text}
                if not all(current['memory'].values()):
                    current['result'] = 'FAIL'
            save()
        if current['result'] != 'PASS' and len(current['subscriptions']) < 15:
            break  # Do not repeat an unmet five-fabric prerequisite four times.
    report['result'] = 'PASS' if len(report['phases']) == args.end_phase - args.start_phase and all(p['result'] == 'PASS' for p in report['phases']) else 'FAIL'
    save(); return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
