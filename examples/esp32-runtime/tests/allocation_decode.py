"""Validate C6 allocation audit totals and resolve sites against the exact ELF.

Use a separate normal image for headline memory measurements. An observer
overflow, incomplete dump or inconsistent sum makes attribution invalid.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def decode(text, elf, addr2line, source_root=None):
    dumps = []
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r'ALLOC_AUDIT (\S+) live(\d+) bytes(\d+) peak(\d+) '
                             r'overflows(\d+) metadata(\d+) peaklive(\d+) sites(\d+)', line)
        if match:
            current = dict(phase=match[1], live_count=int(match[2]), live_bytes=int(match[3]),
                           peak_bytes=int(match[4]), overflows=int(match[5]),
                           metadata_bytes=int(match[6]), peak_live=int(match[7]),
                           site_slots=int(match[8]), live=[], peak=[])
            dumps.append(current)
        match = re.fullmatch(r'ALLOC_SITE (live|peak) ([0-9a-f]+) (\d+) (\d+)', line)
        if match:
            if current is None:
                raise ValueError('Site record before audit header')
            current[match[1]].append(dict(address=match[2], bytes=int(match[3]), count=int(match[4])))
    if not dumps:
        raise ValueError('No allocation audit dumps')
    for entry in dumps:
        if entry['overflows']:
            raise ValueError('Observer overflow: allocation attribution is invalid')
        for kind in ('live', 'peak'):
            if len({site['address'] for site in entry[kind]}) != len(entry[kind]):
                raise ValueError('Duplicate allocation site')
            if sum(site['bytes'] for site in entry[kind]) != entry[kind + '_bytes']:
                raise ValueError('Incomplete or inconsistent allocation byte totals')
        if sum(site['count'] for site in entry['live']) != entry['live_count']:
            raise ValueError('Incomplete or inconsistent live allocation count')
    if dumps[-1]['phase'] != 'complete' or dumps[-1]['live_count'] or dumps[-1]['live_bytes']:
        raise ValueError('Missing zero-live complete dump')
    addresses = sorted({site['address'] for entry in dumps for kind in ('live', 'peak') for site in entry[kind]})
    # The hook records the caller return address. One byte back locates the
    # calling instruction on this RISC-V target, including compressed code.
    lines = []
    if addresses:
        result = subprocess.run([str(addr2line), '-f', '-C', '-e', str(elf),
                                 *[hex(int(address, 16) - 1) for address in addresses]],
                                capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
    if len(lines) != 2 * len(addresses):
        raise ValueError('Unexpected addr2line output')
    lookup = {}
    for index, address in enumerate(addresses):
        function, source = lines[2 * index:2 * index + 2]
        if function == '??' or source.startswith('??'):
            raise ValueError('Unresolved allocation site: use the matching debug ELF')
        if source_root:
            source = source.replace(str(source_root).replace('\\', '/').rstrip('/') + '/', '')
        lookup[address] = dict(function=function, source=source)
    for entry in dumps:
        for kind in ('live', 'peak'):
            for site in entry[kind]:
                site.update(lookup[site['address']])
            entry[kind].sort(key=lambda site: -site['bytes'])
    return dict(elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(),
                metadata_bytes=dumps[0]['metadata_bytes'], dumps=dumps)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--addr2line', required=True, type=Path)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve() in (args.log.resolve(), args.elf.resolve(), args.addr2line.resolve()):
        parser.error('output must not overwrite an input')
    data = decode(args.log.read_text(encoding='utf-8'), args.elf, args.addr2line, args.source_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
