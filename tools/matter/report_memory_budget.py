#!/usr/bin/env python3
"""Conservative retained reporting/TX envelope from real compiler layout probes.

This accounts for existing admission partitions, including optional PASE,
replacement candidates, reserved Read delivery tails and the shared burst.
It neither changes admission nor claims a complete process/ESP32 RAM bound.
Use --legacy-copies only with a matching pre-Memory10 layout probe.
"""
import argparse
import hashlib
import json
from pathlib import Path


def calculate(probe, subscriptions=None, legacy=False):
    s = probe['sizes']
    b = s['host_buckets']
    subscriptions = s['host_subscriptions'] if subscriptions is None else subscriptions
    if not s['host_subscriptions'] <= subscriptions <= s['host_subscriptions_max']:
        raise ValueError('Subscriptions must satisfy the existing composition minimum and 10000 ceiling')
    roles = {'subscriptions_and_replacements': b * (subscriptions + 1),
             'active_reads': b, 'read_delivery_tails': b + s['host_delivery_burst'],
             'other_admissions_and_delivery': 2 * (s['host_invokes'] + s['host_writes']) + s['host_handshakes'] + s['host_rejections']}
    slots = sum(roles.values())
    if subscriptions == s['host_subscriptions'] and slots != s['host_transaction_limit']:
        raise ValueError('Layout admission partitions disagree with the compiled transaction limit')
    if slots > s['transport_capacity']:
        raise ValueError('The selected build cannot admit this subscription configuration')
    results, events, pointer = s['read_result_limit'], s['event_capacity'], s['pointer']
    # Worst temporary old table during geometric growth from 9 toward 512.
    old_capacity = 0
    capacity = s['read_path_limit']
    while capacity < results:
        old_capacity = capacity
        capacity = min(2 * capacity, results)
    values = s['snapshot_budget'] + results * s['value_snapshot_node']
    event_refs = events * (s['event_record'] if legacy else pointer)
    filters = s['read_filter_limit'] * s['read_filter']
    read_plan = s['read_plan_limit'] * s['read_plan_entry']
    read = {'owner': s['read'], 'results': results * s['read_item'],
            'old_table_during_growth': old_capacity * s['read_item'],
            'attribute_values_and_links': values, 'event_selector_state': s['read_events'],
            'event_snapshot_storage': event_refs, 'parser': s['read_parser'],
            'selectors': s['read_path_limit'] * s['read_selector'], 'version_filters': filters,
            'input_and_atomic_replacement': 2 * s['read_max_input'],
            'output': s['read_max_output'], 'chunk_plan': read_plan}
    sub = {'owner': s['subscribe'], 'persistent_results': results * s['subscribe_item'],
           'old_table_during_growth': old_capacity * s['subscribe_item'],
           'captured_values': results * s['subscribe_value'],
           'attribute_values_and_links': values, 'event_selector_state': s['subscribe_events'],
           'event_snapshot_storage': event_refs, 'parser_and_chunk_plan': s['subscribe_parser'],
           'selectors': s['subscribe_path_limit'] * s['subscribe_selector'],
           'version_filters': s['read_filter_limit'] * s['subscribe_filter'],
           'input_and_atomic_replacement': 2 * s['read_max_input'], 'output': s['read_max_output']}
    tail = {'owner': s['read'], 'attribute_values_and_links': values, 'event_snapshot_storage': event_refs}
    if legacy:
        tail.update(results=results * s['read_item'], event_selector_state=s['read_events'],
                    input=s['read_max_input'], output=s['read_max_output'],
                    selectors=s['read_path_limit'] * s['read_selector'], version_filters=filters, chunk_plan=read_plan)
    snapshots = roles['subscriptions_and_replacements'] + roles['active_reads'] + roles['read_delivery_tails']
    # Published + full prepared batch + retired nodes pinned by snapshots.
    # A shared generation can be completely evicted while every reader holds it.
    shared_nodes = 2 * events if legacy else 3 * events
    distinct_nodes = 2 * events if legacy else (2 + snapshots) * events
    owned = {'subscription_handlers': roles['subscriptions_and_replacements'] * sum(sub.values()),
             'active_read_handlers': roles['active_reads'] * sum(read.values()),
             'read_delivery_handlers': roles['read_delivery_tails'] * sum(tail.values()),
             'transaction_nodes': slots * s['transaction'],
             'retained_maximum_tx_packets': slots * s['transaction_packet'],
             'dispatcher_owner': s['dispatch'], 'event_log_owner': s['event_log']}
    base = sum(owned.values())
    return {'scope': 'Conservative requested payload envelope for reporting, event retention and dispatcher/TX; additive phase overcounts, not an observed peak or total process RAM bound.',
            'representation': 'legacy copied records' if legacy else 'immutable shared event references and compact Read delivery tails',
            'roles': roles, 'transaction_slots': slots, 'snapshot_slots': snapshots,
            'per_handler_additive_bytes': {'subscription': sub, 'active_read': read, 'read_delivery_tail': tail},
            'owned_allocation_groups': owned,
            'one_shared_evicted_generation': {'event_nodes': shared_nodes,
                'event_node_bytes': shared_nodes * s['event_node'], 'total_requested_bytes': base + shared_nodes * s['event_node']},
            'all_snapshots_distinct_generations': {'event_nodes': distinct_nodes,
                'event_node_bytes': distinct_nodes * s['event_node'], 'total_requested_bytes': base + distinct_nodes * s['event_node']},
            'largest_report_allocation': max(results * s['read_item'], results * s['subscribe_item'],
                results * s['subscribe_value'], event_refs, s['read_max_value'] + s['value_snapshot_node']),
            'not_included': ['Allocator metadata, fragmentation and alignment beyond probed object sizes',
                'Other transport owners and secure session/channel owners',
                'Invoke/Write/client/BDX and PASE/CASE/backend work',
                'Fabric publication/rollback/restore and persistence adapters',
                'Root/cluster/application/model allocations and callbacks',
                'Platform networking/radio/RTOS stack reservations and used task stacks']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--layout', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--subscriptions-per-fabric', type=int)
    p.add_argument('--legacy-copies', action='store_true')
    a = p.parse_args()
    try:
        probe = json.loads(a.layout.read_text())
        result = calculate(probe, a.subscriptions_per_fabric, a.legacy_copies)
    except (KeyError, ValueError) as error:
        p.error(str(error))
    result['layout_sha256'] = hashlib.sha256(a.layout.read_bytes()).hexdigest()
    result['compiler'] = probe['compiler']
    result['source_sha256'] = probe['source_sha256']
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('roles', 'one_shared_evicted_generation', 'all_snapshots_distinct_generations')}, indent=2))


if __name__ == '__main__':
    main()
