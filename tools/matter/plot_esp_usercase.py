"""Export only numeric, verified C6 user-case results and grouped heap charts.

Private UART/controller inputs stay local. Requires matplotlib for PNG/SVG.
SDK regional local watermarks are conservative, not an exact simultaneous peak;
the second metric records the lowest observed simultaneous 100 ms sample.
"""
import argparse
import csv
import json
from pathlib import Path

PHASES = [
    ('wifi-onboarding', 'Wi-Fi +\nstack start'),
    ('commissioning', 'On-network\ncommissioning'),
    ('first-session', 'First CASE\nsession'),
    ('control-subscribe', 'RGB control +\nsubscription'),
    ('multiple-controllers', 'Three CASE\nsessions'),
    ('multi-admin', 'Second\nfabric'),
    ('fabric-removal', 'Remove\nfabric'),
    ('ota-download', 'OTA download,\napply + reboot'),
    ('ota-reboot-reconnect', 'Reconnect\nafter OTA'),
    ('matter-absent', 'Matter stopped,\nWi-Fi active'),
]
COLORS = {'c': '#B59AD9', 'reference': '#367EB5'}
LABELS = {'c': 'matter-c', 'reference': 'ESP-Matter / ConnectedHomeIP'}
BEFORE = ('never-created', 'Wi-Fi ready,\nMatter not created')


def read_run(folder, kind):
    result = json.loads((folder / 'result.json').read_text())
    assert result['pass'] and result['kind'] == kind and result['mode'] == 'full'
    assert result['expected'] == 'success' and result['version'] == 2
    assert result['applies'] == 1 and result['notifications'] == 1
    assert not result['unexpectedClosures']
    ping = json.loads((folder / 'wifi-after-stop-ping.json').read_text())
    assert ping['pass'] and ping['probes'] == 3
    events = [json.loads(line) for line in (folder / 'events.jsonl').read_text().splitlines() if line]
    oom = [json.loads(e['text'][13:])['failures'] for e in events if e['text'].startswith('USERCASE_OOM ')]
    assert oom and not any(oom)
    windows = {p['number']: p for p in result['phases']}
    assert set(windows) == set(range(1, 10))
    rows = []
    first_construct = next(e['unix_ms'] for e in events if
                           (e['text'].startswith('MEMORY ') and '"phase":"runtime-created"' in e['text']) or
                           (e['text'].startswith('REF_MEMORY ') and '"phase":"node created"' in e['text']))
    for number, (phase, label) in enumerate([BEFORE, *PHASES], -1):
        if number == -1:
            # Last shared report after Wi-Fi is ready, before runtime/node new.
            selected = [e for e in events if 'memory' in e and e['unix_ms'] < first_construct][-1:]
        elif number == 0:
            selected = [e for e in events if 'memory' in e and e['unix_ms'] < windows[1]['begin_ms']]
        elif number == 7:
            # Include new firmware startup between physical reset and Notify.
            selected = [e for e in events if 'memory' in e and
                        windows[7]['begin_ms'] <= e['unix_ms'] < windows[8]['begin_ms']]
        else:
            selected = [e for e in events if 'memory' in e and e['memory']['phase'] == phase and
                        windows[number]['begin_ms'] <= e['unix_ms'] <= windows[number]['end_ms']]
        assert selected, (kind, number, 'missing measurement')
        data = [e['memory'] for e in selected]
        rows.append(dict(stack=kind, case=phase, label=label.replace('\n', ' '),
                         free_min_sdk_bytes=min(d['heap_min'] for d in data),
                         free_min_sampled_bytes=min(d['heap_min_sampled'] for d in data),
                         free_last_bytes=data[-1]['heap_free'],
                         largest_min_sampled_bytes=min(d['largest_min_sampled'] for d in data),
                         largest_last_bytes=data[-1]['largest_free'],
                         free_blocks_last=data[-1]['free_blocks'],
                         telemetry_records=len(data)))
    tasks = {}
    for event in events:
        if event['text'].startswith('USERCASE_TASK '):
            task = json.loads(event['text'][14:])
            name, free = task['name'], task['min_free_bytes']
            tasks[name] = min(tasks.get(name, free), free)
    assert 'main' in tasks and tasks['main'] > 0
    if kind == 'reference':
        assert 'CHIP' in tasks or 'chip' in tasks
    counts = {key: result[key] for key in ('casePairs', 'subscriptions', 'reports', 'invokes', 'reads',
                                         'busyRetries', 'unexpectedClosures', 'queries', 'applies', 'notifications')}
    return rows, dict(counts=counts, peer=result['peer'], task_min_free_bytes=tasks, sdk_failed_allocations=max(oom),
                      physical_version_before=1, physical_version_after=2,
                      wifi_after_stop_ping=ping)


def plot(rows, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    for metric, title, filename in [
            ('free_min_sdk_bytes', 'Minimum free internal heap across the user case', 'free-heap'),
            ('largest_min_sampled_bytes', 'Smallest observed largest free internal block', 'largest-block')]:
        fig, ax = plt.subplots(figsize=(16, 6.8), layout='constrained')
        fig.set_facecolor('white')
        for kind, shift in [('c', -.20), ('reference', .20)]:
            data = [r for r in rows if r['stack'] == kind]
            positions = [i + shift for i in range(len(data))]
            values = [r[metric]/1024 for r in data]
            ax.bar(positions, values, width=.36, color=COLORS[kind], label=LABELS[kind], zorder=3)
            if metric == 'free_min_sdk_bytes':
                ax.scatter(positions, [r['free_min_sampled_bytes']/1024 for r in data],
                           facecolors='white', edgecolors=COLORS[kind], linewidths=1.5, s=25, zorder=5)
            for x, y in zip(positions, values):
                ax.annotate(f'{y:.1f}', (x, y), xytext=(0, 5), textcoords='offset points',
                            ha='center', va='bottom', fontsize=8, color='#30323A')
        ax.set_title(title + '\nESP32-C6 | ESP-IDF 6.0.2 | Wi-Fi | BLE off | CHIP shell off | signed OTA 1 → 2',
                     loc='left', fontsize=15, pad=17, color='#22242B')
        ax.set_xticks(range(len(PHASES)+1), [label for _, label in [BEFORE, *PHASES]], fontsize=8)
        ax.set_ylabel('Free internal 8-bit heap [KiB]' if metric == 'free_min_sdk_bytes' else 'Largest block [KiB]', fontsize=11)
        ax.set_ylim(0, max(r[metric] for r in rows)/1024*1.22)
        ax.grid(axis='y', color='#E2E5EA', linewidth=.8, zorder=0)
        ax.set_axisbelow(True)
        for spine in ('top', 'right'):
            ax.spines[spine].set_visible(False)
        handles, labels = ax.get_legend_handles_labels()
        if metric == 'free_min_sdk_bytes':
            handles.append(Line2D([], [], marker='o', linestyle='None', markerfacecolor='white',
                                  markeredgecolor='#777777', label='100 ms observed minimum'))
            labels.append('100 ms observed minimum')
        ax.legend(handles, labels, loc='upper left', frameon=False, ncol=3, fontsize=9)
        note = ('Bars: conservative SDK regional watermarks per phase. Circles: observed simultaneous minima at 100 ms.\n'
                'Includes Wi-Fi, lwIP, SDK tasks and reserved task stacks. Automatic controllers; no BLE or manual phone-app test.'
                if metric == 'free_min_sdk_bytes' else
                '100 ms samples; includes SDK allocations. Separate heap regions also limit contiguity, independently of allocator fragmentation.')
        fig.supxlabel(note, fontsize=9, color='#555A66', ha='left', x=.01)
        for extension in ('png', 'svg'):
            target = output / f'{filename}.{extension}'
            fig.savefig(target, dpi=180)
            if extension == 'svg':
                # Matplotlib emits path lines with trailing spaces.
                target.write_bytes(('\n'.join(line.rstrip() for line in
                    target.read_text(encoding='utf8').splitlines()) + '\n').encode('utf8'))
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows, details = [], {}
    for kind, folder in [('c', args.c), ('reference', args.reference)]:
        data, run = read_run(folder, kind)
        rows += data
        details[kind] = run
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'results.json').write_text(json.dumps(dict(schema=1, metric='internal|8bit',
        sdk='ESP-IDF v6.0.2', sample_period_ms=100, measurements=rows, validation=details), indent=2) + '\n')
    with (args.output / 'results.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    plot(rows, args.output)
    print('Exported verified numeric results and charts; private inputs remain local')


if __name__ == '__main__':
    main()
