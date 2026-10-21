"""Extract telemetry/counters from a private C6 soak run without copying raw logs.

Usage: python summarize.py <private-run-directory> <summary.json>
The result intentionally excludes controller storage, topology, UART text,
addresses, attribute values and exception stacks. Review before publishing.
"""
import argparse
import hashlib
import json
from pathlib import Path


def summarize(root):
    records = []
    for line in (root / 'events.jsonl').read_text(encoding='utf-8').splitlines(keepends=True):
        # A live collector may still be appending its last record.
        if line.endswith('\n'):
            records.append(json.loads(line))
    groups = {kind: [r['data'] for r in records if r['kind'] == kind]
              for kind in ('SOAK', 'MEMORY', 'NETWORK', 'TASK_MEMORY')}
    soak, memory = groups['SOAK'], groups['MEMORY']
    result = {'runtime_ready': any(r['kind'] == 'READY' for r in records),
              'runtime_pass': any(r['kind'] == 'PASS' for r in records)}
    if soak:
        result['system_heap'] = {
            'maximum_allocated_sampled_bytes': max(r['heap_max_sampled'] for r in soak),
            'minimum_free_sampled_bytes': min(r['heap_min_sampled'] for r in soak),
            'minimum_largest_free_sampled_bytes': min(r['largest_min_sampled'] for r in soak),
            'sdk_failed_allocation_attempts': max(r.get('sdk_alloc_failures', 0) for r in soak),
            'sdk_largest_failed_request_bytes': max(r.get('sdk_largest_failed_request', 0) for r in soak),
            'smallest_largest_free_logged_sample': min(soak, key=lambda r: r['largest_free']),
            'last_sample': soak[-1],
        }
        result['tracked_peak_bytes'] = max(r['core_peak'] for r in soak)
    if memory:
        result['sdk_per_region_low_water_sum_bytes'] = min(r['heap_min'] for r in memory)
        result['owner_stack'] = {
            'reserved_bytes': memory[0]['owner_stack_reserved'],
            'maximum_observed_used_bytes': max(r['owner_stack_reserved'] - r['owner_stack_min_free'] for r in memory),
        }
        result['final_memory'] = memory[-1]
    if groups['NETWORK']:
        result['last_network'] = groups['NETWORK'][-1]
    if groups['TASK_MEMORY']:
        result['task_minimum_free_bytes'] = {}
        for row in groups['TASK_MEMORY']:
            key = row['name']
            result['task_minimum_free_bytes'][key] = min(
                result['task_minimum_free_bytes'].get(key, row['min_free_bytes']), row['min_free_bytes'])
    controller = root / 'controller-results.json'
    if controller.exists():
        source = json.loads(controller.read_text(encoding='utf-8'))
        # Explicitly omit exception details and arbitrary controller values.
        names = ('mode', 'read_workload', 'requested_seconds', 'rounds', 'full_reads',
                 'read_attributes', 'concrete_reads', 'concrete_read_attributes',
                 'subscription_snapshots', 'subscription_updates', 'subscription_closed',
                 'case_pairs', 'case_resumed', 'session_busy_probes', 'oom_cycles',
                 'fault_operations_rejected', 'reconnect_cycles', 'loss_cycles',
                 'loss_operations_rejected', 'loss_rebuilt_load_cycles',
                 'loss_lost_subscriptions', 'delayed_completion_cycles',
                 'healthy_operation_errors', 'unexpected_subscription_closures',
                 'oom_lost_subscriptions', 'oom_rebuilt_load_cycles', 'sustained_seconds',
                 'recovery_busy_retries', 'recovery_busy_wait_ms',
                 'stop_wait_seconds', 'stop_read_outcome', 'pass', 'elapsed_seconds',
                 'successful_read_latency_ms', 'checkpoints')
        result['controller'] = {key: source[key] for key in names if key in source}
        if 'error' in source:
            result['controller']['failure_type'] = source['error']['name']
    result['executed_oracle_sha256'] = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ('soak-executed.mjs', 'uart-executed.py') if (root / name).exists()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = summarize(args.run)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('runtime_ready', 'runtime_pass')}))


if __name__ == '__main__':
    main()
