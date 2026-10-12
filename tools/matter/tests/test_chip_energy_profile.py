"""Mutation checks for the CHIP report oracle, using real acceptance logs."""
import argparse
from pathlib import Path
import re
from chip_tool_energy_profile import catalog, measurements


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--read', required=True, type=Path)
    p.add_argument('--subscribe', required=True, type=Path)
    a = p.parse_args()
    read, subscribe = a.read.read_text(), a.subscribe.read_text()
    assert len(catalog(read)) > 120
    measurements(subscribe, updates=True)
    cases = [
        ('missing-path', catalog, read.replace('Attribute 0x0000_0008', 'Attribute 0x0000_1234')),
        ('truncated-read', catalog, read[:len(read)//2]),
        ('prime-only', lambda s: measurements(s, True), subscribe.split('Subscription established', 1)[0]),
        ('null-energy', lambda s: measurements(s, True), re.sub(r'Energy: \d+', 'Energy: null', subscribe)),
        ('frozen-power', lambda s: measurements(s, True), re.sub(r'ActivePower: -?\d+', 'ActivePower: 3600000', subscribe)),
        ('frozen-version', lambda s: measurements(s, True), re.sub(r'DataVersion: \d+', 'DataVersion: 1', subscribe)),
        ('duplicate-events', lambda s: measurements(s, True), re.sub(r'Event number: \d+', 'Event number: 1', subscribe)),
        ('event-disagreement', lambda s: measurements(s, True), re.sub(r'((?<!\w)EnergyImported: \{.*?Energy: )(\d+)',
            lambda m: m[1] + str(int(m[2])+1), subscribe, flags=re.S)),
    ]
    for name, check, data in cases:
        try:
            check(data)
        except (KeyError, ValueError):
            print('PASS reject', name)
        else:
            raise AssertionError('Oracle accepted ' + name)


if __name__ == '__main__':
    main()
