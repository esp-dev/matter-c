"""Independent event and fabric-sensitive IM observations using real chip-tool.

Runs a disposable Linux Node. Original manual TH outcomes are recorded separately;
private credentials, packet/controller logs and persisted state are never exported.
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
from chip_tool_multi_events import numbers, ordered

READ_DONE = r'SuppressResponse = true[\s\S]*Flushed pending ack for MessageCounter:'
WRITE_DONE = r'WriteResponseMessage =[\s\S]*status = 0x00\b[\s\S]*Flushed pending ack for MessageCounter:'


def reports(text):
    starts = [text.rfind('\n', 0, m.start()) + 1
              for m in re.finditer(r'\[DMG\]\s*ReportDataMessage =', text)]
    result = []
    for i, start in enumerate(starts):
        part = text[start:starts[i + 1] if i + 1 < len(starts) else len(text)]
        sid = re.search(r'SubscriptionId = (0x[0-9a-fA-F]+)', part)
        stamp = re.search(r'\[([0-9]+\.[0-9]+)\]', part[:part.index('[DMG]')])
        result.append({'id': int(sid[1], 16) if sid else None,
                       'time': float(stamp[1]) if stamp else None, 'text': part})
    return result


def complete_cycle(text, sid, events=False):
    return any(x['id'] == sid and 'MoreChunkedMessages = true' not in x['text'] and
               'IM:StatusResponse' in x['text'] for x in reports(text)) and (not events or bool(numbers(scoped(text, sid))))


def scoped(text, sid):
    return ''.join(x['text'] for x in reports(text) if x['id'] == sid)


def structures(text):
    """Actual generic DMG Data arrays, including omitted fabric-sensitive fields."""
    text = re.sub(r'[^\n]*\[DMG\]\s*', '', text)
    result = []
    for match in re.finditer(r'\bData = \[', text):
        level = 1; braces = 0; start = None
        for pos in range(match.end(), len(text)):
            char = text[pos]
            if char == '[':
                level += 1
            elif char == ']':
                level -= 1
                if not level:
                    break
            elif char == '{':
                if not braces:
                    start = pos
                braces += 1
            elif char == '}':
                braces -= 1
                if not braces and start is not None:
                    result.append(text[start:pos + 1])
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'chip-tool', 'paa', 'credentials', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--interface', type=int, required=True)
    p.add_argument('--ipv6', required=True)
    p.add_argument('--valgrind', action='store_true')
    a = p.parse_args(); out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'result': 'RUNNING', 'groups': {}, 'checks': [],
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'node_sha256': hashlib.sha256(a.exe.read_bytes()).hexdigest(),
              'chip_tool_sha256': hashlib.sha256(a.chip_tool.read_bytes()).hexdigest()}
    clients = []; node = None; handles = []; group = 'setup'

    def save():
        temp = out / 'result.tmp'; temp.write_text(json.dumps(report, indent=2)); temp.replace(out / 'result.json')

    def check(name, ok, detail=None, fatal=True):
        row = {'group': group, 'name': name, 'status': 'PASS' if ok else 'FAIL'}
        if detail is not None:
            row['detail'] = detail
        report['checks'].append(row); save(); print(row['status'], group, name, flush=True)
        if not ok and fatal:
            raise AssertionError(name)

    def command(c, args, pattern=READ_DONE, failure=False):
        offset = len(c.text())
        ok, text = c.command(args, pattern, timeout=60, failure=failure)
        # KeepSubscriptions=false intentionally retires earlier subscriptions.
        # Their retained CHIP ReadClients later emit liveness timeouts while a
        # different command is running. Do not resend the command or mistake
        # those callbacks for its result: require its actual response pattern.
        errors = re.findall(r'Run command failure:[^\n]*', text)
        retired = errors and all('ReadClient.cpp:' in e and 'Timeout' in e for e in errors)
        if not ok and retired:
            text = wait(c, offset, lambda t: bool(re.search(pattern, t)), 60)
            ok = bool(re.search(pattern, text))
            report.setdefault('retired_client_timeout_observations', []).append(
                {'command': args[:2], 'actual_response_received': ok, 'callbacks': len(errors)})
        check('command-' + '-'.join(map(str, args[:2])), ok)
        return text

    def client(name):
        c = Client(a.chip_tool, a.paa, out, name, advertise=False); clients.append(c); return c

    def read(c, cluster='0x1f', event='0', ep='0', extra=None, status=None):
        argv = ['any', 'read-event-by-id', cluster, event, 1, ep, *(extra or [])]
        if status is None:
            return ''.join(x['text'] for x in reports(command(c, argv)) if x['id'] is None)
        offset = len(c.text())
        command(c, argv, r'Run command failure:.*0x000005' + format(status, '02X'), failure=True)
        text = wait(c, offset, lambda t: bool(re.search(READ_DONE, t)), 4)
        check('error-report-ACK-complete', bool(re.search(READ_DONE, text)))
        return text

    admin = [dict(privilege=5, authMode=2, subjects=[112233], targets=None)]

    def acl(c, entries):
        return command(c, ['accesscontrol', 'write', 'acl', json.dumps(entries), 1, 0], WRITE_DONE)

    def changed(c, value):
        entry = dict(privilege=1, authMode=2, subjects=[0x10000000000 + value],
                     targets=[dict(cluster=0x28, endpoint=0, deviceType=None)])
        return acl(c, [*admin, entry])

    def sub(c, cluster='0x1f', event='0', ep='0', minimum=1, maximum=10, extra=None):
        text = command(c, ['any', 'subscribe-event-by-id', cluster, event, minimum, maximum, 1, ep,
                           '--keepSubscriptions', 'false', *(extra or [])],
                       r'Subscription established[^\n]*[\s\S]*Flushed pending ack for MessageCounter:')
        found = re.findall(r'SubscribeResponseMessage =[\s\S]*?SubscriptionId = (0x[0-9a-fA-F]+)', text)
        check('unique-subscribe-response', len(found) == 1 and 'ReportDataMessage =' in text and 'IM:StatusResponse' in text)
        sid = int(found[0], 16)
        return sid, scoped(text, sid)

    def wait(c, offset, predicate, seconds=12):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            text = c.text()[offset:]
            if predicate(text):
                return text
            time.sleep(.05)
        return c.text()[offset:]

    def run_group(name, function):
        nonlocal group
        group = name
        try:
            function()
            report['groups'][name] = {'result': 'FAIL' if any(x['group'] == name and x['status'] == 'FAIL' for x in report['checks']) else 'PASS'}
        except (AssertionError, KeyError, ValueError, TypeError, StopIteration, OSError) as error:
            report['groups'][name] = {'result': 'FAIL', 'error': str(error)}
        save()

    try:
        argv = [str(a.exe), '--interface', str(a.interface), '--port', '5589', '--seconds', '900',
                '--credentials', str(a.credentials), '--state', str(out / 'state.tlv'),
                '--pin', '20202021', '--discriminator', '3918', '--three-phase', '--meter-services',
                '--wifi-sim-connected']
        if a.valgrind:
            argv = ['valgrind', '--leak-check=full', '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                    '--track-origins=yes', '--error-exitcode=99', '--log-file=' + str(out / 'memcheck.log'), *argv]
        handles = [(out / ('node.' + s)).open('w') for s in ('log', 'err')]
        node = subprocess.Popen(argv, stdout=handles[0], stderr=handles[1], env=dict(os.environ,
                                ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'))
        end = time.monotonic() + 40
        while time.monotonic() < end and node.poll() is None and 'PUBLISHED' not in (out / 'node.log').read_text():
            time.sleep(.05)
        check('fresh-node-published', node.poll() is None and 'PUBLISHED' in (out / 'node.log').read_text())
        c = client('RC1')
        command(c, ['pairing', 'already-discovered', 1, 20202021, a.ipv6 + '%' + str(a.interface), 5589,
                    '--country-code', 'PL', '--timeout', 45], r'Device commissioning completed with success')
        selectors = [('0x1f', '0', '0'), ('0x1f', '0xffffffff', '0'), ('0xffffffff', '0xffffffff', '0'),
                     ('0x1f', '0', '0xffff'), ('0x1f', '0xffffffff', '0xffff'), ('0xffffffff', '0xffffffff', '0xffff')]

        def read_events():
            for index, selector in enumerate(selectors):
                text = read(c, *selector)
                check('selector-' + str(index), ordered(text) and 'AccessControlEntryChanged:' in text and 'EventStatusIB =' not in text)
            text = read(c, event='65534', status=0xc7)
            check('unsupported-event', 'EventStatusIB =' in text and bool(re.search(r'Status\s*=\s*0xc7\b', text, re.I)) and not numbers(text))
            restricted = [dict(privilege=5, authMode=2, subjects=[112233],
                               targets=[dict(cluster=0x1f, endpoint=0, deviceType=None)])]
            acl(c, restricted)
            text = read(c, '0x28', status=0x7e)
            check('concrete-denied', 'EventStatusIB =' in text and bool(re.search(r'Status\s*=\s*0x7e\b', text, re.I)))
            text = read(c, '0xffffffff', '0xffffffff', '0xffff')
            check('wildcard-omits-denied', 'AccessControlEntryChanged:' in text and 'StartUp:' not in text and 'CumulativeEnergyMeasured:' not in text and 'EventStatusIB =' not in text)
            acl(c, admin)
            text = read(c); before = numbers(text); check('event-history', ordered(text) and len(before) >= 2)
            text = read(c, extra=['--event-min', before[-2]])
            check('inclusive-event-min', numbers(text) == [n for n in before if n >= before[-2]])
            text = read(c, extra=['--event-min', before[-1] + 100000])
            check('future-min-empty', not numbers(text) and 'EventStatusIB =' not in text)
            for index in range(12):
                changed(c, index)
            text = read(c)
            check('event-only-chunked-read', ordered(text) and len(numbers(text)) >= 20 and 'MoreChunkedMessages = true' in text and text.count('IM:StatusResponse') >= text.count('MoreChunkedMessages = true'))
            report['read_event_numbers'] = numbers(text); save()
        run_group('TC_IDM_6_1', read_events)
        acl(c, admin)

        def subscribe_events():
            for index, selector in enumerate(selectors):
                sid, text = sub(c, *selector)
                check('selector-' + str(index), ordered(text) and 'AccessControlEntryChanged:' in text)
            for urgent in (False, True):
                sid, prime = sub(c, minimum=5, maximum=8, extra=['--is-urgent', str(urgent).lower()])
                # An IM report starts with its first chunk. A large prime may
                # take seconds to finish; its last chunk is not a new report.
                prime_times = [x['time'] for x in reports(prime) if x['id'] == sid]
                check('complete-prime-timestamps', bool(prime_times) and all(isinstance(t, float) for t in prime_times))
                anchor = prime_times[0]
                offset = len(c.text()); changed(c, 30 + int(urgent))
                text = wait(c, offset, lambda t: complete_cycle(t, sid, events=True), 12)
                update = next(x for x in reports(text) if x['id'] == sid and numbers(x['text']))
                gap = update['time'] - anchor
                check('urgent-minimum-' + str(urgent), (4.8 if urgent else 7.8) <= gap <= 11,
                      {'seconds': gap, 'minimum': 5, 'maximum': 8, 'prime_chunk_span': prime_times[-1] - anchor})
                # This ACL event path has no autonomous event producer.
                offset = len(c.text()); anchor = update['time']
                text = wait(c, offset, lambda t: complete_cycle(t, sid), 12)
                heartbeat = next(x for x in reports(text) if x['id'] == sid)
                check('no-change-max-heartbeat-' + str(urgent), not numbers(heartbeat['text']) and 7.8 <= heartbeat['time'] - anchor <= 11,
                      {'seconds': heartbeat['time'] - anchor})
            previous = sid
            sid, prime = sub(c, extra=['--is-urgent', 'true'])
            offset = len(c.text()); changed(c, 44)
            text = wait(c, offset, lambda t: any(x['id'] == sid and numbers(x['text']) for x in reports(t)), 8)
            check('keep-false-replaces-old', sid != previous and any(x['id'] == sid and numbers(x['text']) for x in reports(text)) and all(x['id'] != previous for x in reports(text)))
            check('prime-status-success-before-subresponse', prime.index('IM:StatusResponse') < prime.index('SubscribeResponseMessage ='))
            command(c, ['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
            restricted = [dict(privilege=5, authMode=2, subjects=[112233], targets=[dict(cluster=0x1f, endpoint=0, deviceType=None)])]
            acl(c, restricted)
            text = command(c, ['any', 'subscribe-event-by-id', '0x28', '0', 1, 4, 1, 0, '--keepSubscriptions', 'false'],
                           r'Run command failure:.*0x000005(?:7[Ee]|80)', failure=True)
            check('denied-subscribe-status', bool(re.search(r'Status\s*=\s*0x7e', text, re.I)) and 'Subscription established' not in text,
                  {'literal_expected': 'EventStatusIB UNSUPPORTED_ACCESS0x7e',
                   'actual_statuses': re.findall(r'(?:status|Status)\s*=\s*(0x[0-9a-fA-F]+)', text)}, fatal=False)
            sid, text = sub(c, '0xffffffff', '0xffffffff', '0xffff')
            check('wildcard-subscribe-omits-denied', 'AccessControlEntryChanged:' in text and 'StartUp:' not in text and 'CumulativeEnergyMeasured:' not in text)
            acl(c, admin)
            history = numbers(read(c)); minimum = history[-2]
            sid, text = sub(c, extra=['--event-min', minimum])
            check('event-min-prime', numbers(text) == [n for n in history if n >= minimum])
            sid, text = sub(c, extra=['--event-min', history[-1] + 100000, '--is-urgent', 'true'])
            check('future-event-min-empty-prime', not numbers(text))
            offset = len(c.text()); changed(c, 50)
            text = wait(c, offset, lambda t: bool(numbers(t)), 8)
            check('new-events-after-empty-prime', ordered(text) and min(numbers(text)) > history[-1])
            sid, text = sub(c, '0xffffffff', '0xffffffff', '0xffff', extra=['--is-urgent', 'true'])
            watermark = max(numbers(text)); offset = len(c.text())
            for index in range(3):
                changed(c, 60 + index)
            time.sleep(5); text = scoped(c.text()[offset:], sid)
            # The interactive logger can finish printing a priming tail after
            # command completion. Select new records by EventNumber, too; keep
            # duplicates/order intact above the priming watermark.
            values = [n for n in numbers(text) if n > watermark]
            check('node-wide-consecutive-event-numbers', len(values) >= 6 and values == sorted(set(values)) and
                  all(b == a + 1 for a, b in zip(values, values[1:])), values)
            report['subscribe_event_numbers'] = values; save()
        run_group('TC_IDM_6_2', subscribe_events)
        # Stop publishers through replacement semantics before the independent fabric group.
        command(c, ['subscriptions', 'shutdown-all'], r'Command: subscriptions shutdown-all')
        acl(c, admin)

        def fabric_sensitive():
            opened = command(c, ['pairing', 'open-commissioning-window', 1, 1, 180, 1000, 3919], r'Manual pairing code: \[\d+\]')
            code = re.search(r'Manual pairing code: \[(\d+)\]', opened)[1]
            parsed = command(c, ['payload', 'parse-setup-payload', code], r'Passcode:\s*\d+')
            peer = client('RC2')
            command(peer, ['pairing', 'already-discovered', 1, int(re.search(r'Passcode:\s*(\d+)', parsed)[1]),
                           a.ipv6 + '%' + str(a.interface), 5589, '--country-code', 'PL', '--timeout', 45],
                    r'Device commissioning completed with success')
            indices = [integer(next(f['body'] for f in frames(command(x, ['operationalcredentials', 'read', 'current-fabric-index', 1, 0])) if f['path'] == (0, 0x3e, 5)), 'CurrentFabricIndex') for x in (c, peer)]
            check('two-fabrics', len(set(indices)) == 2)

            def acl_read(x, filtered):
                return command(x, ['accesscontrol', 'read', 'acl', 1, 0, '--fabric-filtered', str(filtered).lower()])

            def privacy(text, own, foreign, own_count=1, foreign_count=1):
                entries = structures(text)
                indexes = lambda v: [x for x in entries if re.search(r'0x[Ff][Ee]\s*=\s*' + str(v) + r'\s+\(unsigned\)', x)]
                visible, hidden = indexes(own), indexes(foreign)
                return len(visible) == own_count and len(hidden) == foreign_count and all(re.search(r'0x0*1\s*=', x) for x in visible) and all(not re.search(r'0x0*[1-4]\s*=', x) for x in hidden)

            for x, own, foreign in ((c, indices[0], indices[1]), (peer, indices[1], indices[0])):
                text = acl_read(x, False)
                check('unfiltered-ACL-sensitive-omission-' + str(own), privacy(text, own, foreign))
                text = acl_read(x, True)
                check('filtered-ACL-own-only-' + str(own), privacy(text, own, foreign, foreign_count=0))
            changed(c, 80)
            check('modified-own-ACL', len(structures(acl_read(c, True))) == 2)
            check('foreign-filtered-ACL-unchanged', len(structures(acl_read(peer, True))) == 1)
            before = [command(x, ['operationalcredentials', 'read', 'fabrics', 1, 0, '--fabric-filtered', 'false']) for x in (c, peer)]
            check('both-unfiltered-fabric-descriptors', all('Fabrics: 2 entries' in t for t in before))
            command(c, ['operationalcredentials', 'update-fabric-label', 'csa49-public', 1, 0], r'InvokeResponseMessage =[\s\S]*statusCode: 0[\s\S]*Flushed pending ack for MessageCounter:')
            after = [command(x, ['operationalcredentials', 'read', 'fabrics', 1, 0, '--fabric-filtered', 'false']) for x in (c, peer)]
            check('both-observe-one-updated-label', all(t.count('Label: csa49-public') == 1 and 'Fabrics: 2 entries' in t for t in after))
            offsets = {}
            for x in (c, peer):
                text = command(x, ['accesscontrol', 'subscribe', 'acl', 0, 3, 1, 0, '--fabric-filtered', 'false', '--keepSubscriptions', 'false'], r'Subscription established')
                check('ACL-prime-privacy-' + x.directory.name, privacy(text, indices[0] if x == c else indices[1], indices[1] if x == c else indices[0], own_count=2 if x == c else 1, foreign_count=1 if x == c else 2))
                offsets[x] = len(x.text())
            changed(c, 81); time.sleep(5)
            own_reports = [x['text'] for x in reports(c.text()[offsets[c]:]) if structures(x['text'])]
            foreign_reports = [x['text'] for x in reports(peer.text()[offsets[peer]:]) if structures(x['text'])]
            check('ACL-subscriber-own-update', bool(own_reports) and any(str(0x10000000000 + 81) in t for t in own_reports) and all(privacy(t, indices[0], indices[1], own_count=2) for t in own_reports))
            check('ACL-subscriber-foreign-omission', bool(foreign_reports) and all(privacy(t, indices[1], indices[0], foreign_count=2) for t in foreign_reports))
            histories = [numbers(read(x)) for x in (c, peer)]
            for x, history in zip((c, peer), histories):
                sub(x, maximum=3, extra=['--event-min', max(history) + 1, '--is-urgent', 'true'])
            offsets = {x: len(x.text()) for x in (c, peer)}
            changed(c, 82); time.sleep(5)
            own, foreign = c.text()[offsets[c]:], peer.text()[offsets[peer]:]
            check('own-fabric-sensitive-events-delivered', ordered(own) and 'AdminNodeID: 112233' in own)
            check('foreign-fabric-sensitive-events-never-leak', not numbers(foreign) and 'AdminNodeID:' not in foreign and any(x['id'] for x in reports(foreign)))
        run_group('TC_IDM_8_1', fabric_sensitive)
        if report['groups']['TC_IDM_8_1']['result'] == 'PASS':
            # Original wildcard example removes every grant. Keep that literal
            # observation separate from the partial-grant omission above; this
            # disposable fabric needs no later operation or grant restoration.
            group = 'TC_IDM_6_2'
            acl(c, [dict(privilege=5, authMode=2, subjects=[987654], targets=None)])
            text = command(c, ['any', 'subscribe-event-by-id', '0xffffffff', '0xffffffff', 1, 4, 1, '0xffff',
                               '--keepSubscriptions', 'false'], r'Run command failure:.*0x00000580', failure=True)
            check('literal-all-denied-wildcard-empty-report', 'ReportDataMessage =' in text and 'EventStatusIB =' not in text,
                  {'literal_expected': 'empty ReportData', 'actual': 'INVALID_ACTION0x80; no error-free existent paths'}, fatal=False)
            if any(x['group'] == group and x['status'] == 'FAIL' for x in report['checks']):
                report['groups'][group]['result'] = 'FAIL'
        report['result'] = 'PASS' if len(report['groups']) == 3 and all(x['result'] == 'PASS' for x in report['groups'].values()) else 'FAIL'
    except (AssertionError, KeyError, ValueError, TypeError, StopIteration, OSError) as error:
        report['result'] = 'FAIL'; report['error'] = str(error)
    finally:
        for c in reversed(clients):
            c.close()
        report['controller_exits'] = {c.directory.name: c.child.returncode for c in clients}
        if node is not None:
            if node.poll() is None:
                node.terminate()
            try:
                node.wait(timeout=35)
            except subprocess.TimeoutExpired:
                node.kill(); node.wait()
            report['node_exit'] = node.returncode
            if node.returncode or (out / 'node.err').read_bytes() or any(report['controller_exits'].values()):
                report['result'] = 'FAIL'; report['cleanup_error'] = 'Node exit/stderr or controller exit'
        for h in handles:
            h.close()
        if a.valgrind and (out / 'memcheck.log').exists():
            text = (out / 'memcheck.log').read_text(); match = re.search(r'total heap usage: ([\d,]+) allocs, ([\d,]+) frees', text)
            report['memory'] = {'zero_errors': 'ERROR SUMMARY: 0 errors' in text, 'zero_live': 'in use at exit: 0 bytes in 0 blocks' in text,
                                'allocations': int(match[1].replace(',', '')), 'frees': int(match[2].replace(',', ''))}
            if not report['memory']['zero_errors'] or not report['memory']['zero_live']:
                report['result'] = 'FAIL'
        save()
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
