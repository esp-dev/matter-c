"""Validate post-teardown heap pages and identify allocations separating free spans.

Input/output belong in ignored lab directories. Maps contain addresses and sizes,
never payload contents. Attribution images change RAM layout; compare their
owners separately from normal-image memory measurements. No device access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def decode(events, elf=None, addr2line=None, source_root=None, sdk_root=None):
    states = [e['data'] for e in events if e['kind'] == 'HEAP_STATE']
    footers = [e['data'] for e in events if e['kind'] == 'HEAP_MAP']
    blocks = [e['data'] for e in events if e['kind'] == 'HEAP_BLOCK']
    names = [m['phase'] for m in footers]
    if not footers or len(set(names)) != len(names):
        raise ValueError('Missing or duplicate heap map footer')
    if {b['phase'] for b in blocks} != set(names):
        raise ValueError('Orphaned or empty heap map')
    maps = []
    validated = {}
    for footer in footers:
        phase = footer['phase']
        rows = [dict(b) for b in blocks if b['phase'] == phase]
        if footer['stable'] is not True or footer['complete'] is not True or len(rows) != footer['blocks']:
            raise ValueError('Unstable, incomplete or truncated heap map: ' + phase)
        fingerprint = 2166136261
        seen = set()
        for b in rows:
            if type(b['used']) is not bool or b['size'] <= 0 or not b['heap'] <= b['address'] < b['end'] or b['address'] + b['size'] > b['end']:
                raise ValueError('Invalid heap block range or flags')
            caller, kind = b.get('queue_caller', 0), b.get('queue_kind', 0)
            if bool(caller) != bool(kind) or (not b['used'] and (caller or kind)):
                raise ValueError('Invalid or stale SDK owner attribution')
            identity = b['heap'], b['address']
            if identity in seen:
                raise ValueError('Duplicate heap block')
            seen.add(identity)
            part = b['heap'] ^ b['address'] ^ b['size'] ^ int(b['used'])
            fingerprint = ((fingerprint ^ part) * 16777619) & 0xffffffff
        if fingerprint != footer['fingerprint']:
            raise ValueError('Heap page fingerprint mismatch: ' + phase)
        validated[phase] = rows
        islands = []
        for heap in sorted({b['heap'] for b in rows}):
            region = sorted((b for b in rows if b['heap'] == heap), key=lambda b: b['address'])
            if len({b['end'] for b in region}) != 1:
                raise ValueError('Inconsistent heap region bounds')
            for left, right in zip(region, region[1:]):
                if left['address'] + left['size'] > right['address']:
                    raise ValueError('Overlapping heap blocks')
            free = [i for i, b in enumerate(region) if not b['used']]
            for left, right in zip(free, free[1:]):
                between = region[left + 1:right]
                if between:
                    islands.append(dict(left_free=region[left], right_free=region[right],
                                        allocations=between,
                                        allocated_payload_bytes=sum(b['size'] for b in between)))
        islands.sort(key=lambda x: min(x['left_free']['size'], x['right_free']['size']), reverse=True)
        maps.append(dict(phase=phase, footer=footer,
                         free_payload_bytes=sum(b['size'] for b in rows if not b['used']),
                         allocated_payload_bytes=sum(b['size'] for b in rows if b['used']),
                         largest_walked_free=max((b['size'] for b in rows if not b['used']), default=0),
                         largest_free_spans=sorted((b for b in rows if not b['used']), key=lambda b: -b['size'])[:8],
                         separating_islands=islands))
    owners = [e['data'] for e in events if e['kind'] == 'HEAP_OWNER']
    if any(o['name'] == 'queue-map-overflows' and o['count'] for o in owners):
        raise ValueError('SDK owner attribution overflow')
    addresses = sorted({b.get('queue_caller', 0) for b in blocks} - {0})
    sites = {}
    if addresses and elf is not None:
        if addr2line is None:
            raise ValueError('addr2line is required with an ELF')
        result = subprocess.run([str(addr2line), '-f', '-C', '-e', str(elf),
                                 *[hex(pc - 1) for pc in addresses]],
                                capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        if len(lines) != 2 * len(addresses):
            raise ValueError('Unexpected addr2line output')
        roots = [(Path(p).resolve().as_posix().rstrip('/') + '/', prefix)
                 for p, prefix in ((source_root, ''), (sdk_root, 'esp-idf/')) if p]
        roots.sort(key=lambda pair: -len(pair[0]))
        for i, pc in enumerate(addresses):
            function, source = lines[2*i:2*i+2]
            if function == '??' or source.startswith('??'):
                raise ValueError('Unresolved SDK owner; use the matching ELF')
            source = source.replace('\\', '/')
            for root, prefix in roots:
                if source.startswith(root):
                    source = prefix + source[len(root):]
                    break
            sites[pc] = dict(function=function, source=source)
    for rows in validated.values():
        for b in rows:
            if b.get('queue_caller') in sites:
                b['owner'] = sites[b['queue_caller']]
    for m in maps:
        m['attributed_allocations'] = [b for b in validated[m['phase']]
                                       if b['used'] and b.get('queue_caller')]
    by_phase = {s['phase']: s for s in states}
    settle = None
    if 'complete-immediate' in by_phase and 'complete-5s' in by_phase:
        first, last = by_phase['complete-immediate'], by_phase['complete-5s']
        settle = dict(elapsed_ms=last['ms']-first['ms'],
                      free_delta=last['heap_free']-first['heap_free'],
                      largest_delta=last['largest_free']-first['largest_free'],
                      core_live=last['core_live'], core_bytes=last['core_bytes'])
    extended = None
    if 'complete-immediate' in by_phase and 'complete-65s' in by_phase:
        first, last = by_phase['complete-immediate'], by_phase['complete-65s']
        extended = dict(elapsed_ms=last['ms']-first['ms'],
                        free_delta=last['heap_free']-first['heap_free'],
                        largest_delta=last['largest_free']-first['largest_free'],
                        core_live=last['core_live'], core_bytes=last['core_bytes'])
    cleanup = None
    if 'complete-5s' in validated and 'owner-thread-cleaned' in validated:
        def used(phase):
            return {(b['heap'], b['address'], b['size']): b
                    for b in validated[phase] if b['used']}
        baseline = 'complete-65s' if 'complete-65s' in validated else 'complete-5s'
        before, after = used(baseline), used('owner-thread-cleaned')
        cleanup = dict(baseline_phase=baseline, used_blocks_disappeared=[b for key, b in before.items() if key not in after],
                       used_blocks_appeared=[b for key, b in after.items() if key not in before],
                       declared_thread_resource=next((o for o in owners if o['name']=='lwip-owner-thread-semaphore'), None))
        if 'after-final-map' in by_phase and 'owner-thread-cleaned' in by_phase:
            first, last = by_phase['after-final-map'], by_phase['owner-thread-cleaned']
            cleanup.update(free_delta=last['heap_free']-first['heap_free'],
                           largest_delta=last['largest_free']-first['largest_free'])
    return dict(schema=1, states=states, maps=maps, owners=owners, settle=settle, settle_extended=extended, thread_cleanup=cleanup,
                elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest() if elf else None,
                attribution_sites=[dict(pc=pc, **site) for pc, site in sites.items()],
                limitations=['Pagination is validated by count and fingerprint; it is not an atomic whole-heap trace.',
                             'Walked payload sizes and the SDK largest-block API differ due to allocator bookkeeping and TLSF bins.',
                             'Separating SDK allocations are observed owners, not resources safe to delete manually.',
                             'Queue-owner instrumentation shifts RAM layout; it is separate from normal-image measurements.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--events', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--elf', type=Path)
    p.add_argument('--addr2line', type=Path)
    p.add_argument('--source-root', type=Path)
    p.add_argument('--sdk-root', type=Path)
    args = p.parse_args()
    if args.output.resolve() in {x.resolve() for x in (args.events, args.elf, args.addr2line) if x}:
        p.error('output must not overwrite an input')
    events = [json.loads(line) for line in args.events.read_text(encoding='utf-8').splitlines()]
    data = decode(events, args.elf, args.addr2line, args.source_root, args.sdk_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
    print('PASS heap maps:', len(data['maps']), 'attributed sites:', len(data['attribution_sites']))


if __name__ == '__main__':
    main()
