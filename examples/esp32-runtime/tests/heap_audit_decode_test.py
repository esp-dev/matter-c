"""Offline corruption checks for heap_audit_decode; no board or SDK needed."""
import copy
import unittest
from heap_audit_decode import decode


def fixture():
    rows = [dict(phase='complete-5s', heap=100, end=2000, address=a, size=n,
                 used=u, queue_caller=0, queue_kind=0)
            for a, n, u in ((104, 400, False), (508, 92, True), (604, 1000, False))]
    fp = 2166136261
    for b in rows:
        fp = ((fp ^ (b['heap'] ^ b['address'] ^ b['size'] ^ int(b['used']))) * 16777619) & 0xffffffff
    return [dict(kind='HEAP_BLOCK', data=b) for b in rows] + [
        dict(kind='HEAP_MAP', data=dict(phase='complete-5s', stable=True, complete=True, blocks=3, fingerprint=fp))]


class HeapMaps(unittest.TestCase):
    def test_separating_mutex(self):
        m = decode(fixture())['maps'][0]
        self.assertEqual(m['largest_walked_free'], 1000)
        self.assertEqual(m['free_payload_bytes'], 1400)
        self.assertEqual(m['separating_islands'][0]['allocated_payload_bytes'], 92)
        self.assertEqual(m['separating_islands'][0]['allocations'][0]['address'], 508)

    def test_unstable_and_incomplete(self):
        for field in ('stable', 'complete'):
            for value in (False, 'true'):
                events = fixture(); events[-1]['data'][field] = value
                with self.assertRaisesRegex(ValueError, 'Unstable'): decode(events)

    def test_truncated_and_duplicate(self):
        events = fixture(); events.pop(0)
        with self.assertRaisesRegex(ValueError, 'truncated'): decode(events)
        events = fixture(); events[1]['data'] = copy.deepcopy(events[0]['data'])
        with self.assertRaisesRegex(ValueError, 'Duplicate'): decode(events)

    def test_bad_fingerprint(self):
        events = fixture(); events[-1]['data']['fingerprint'] ^= 1
        with self.assertRaisesRegex(ValueError, 'fingerprint'): decode(events)

    def test_invalid_range_and_flags(self):
        for key, value in (('size', 0), ('address', 99), ('end', 200), ('used', 1)):
            events = fixture(); events[0]['data'][key] = value
            with self.assertRaisesRegex(ValueError, 'Invalid'): decode(events)

    def test_inconsistent_region(self):
        events = fixture(); events[0]['data']['end'] = 1900
        with self.assertRaisesRegex(ValueError, 'Inconsistent'): decode(events)

    def test_overlapping_blocks(self):
        events = fixture(); events[2]['data']['address'] = 598
        fp = 2166136261
        for e in events[:-1]:
            b = e['data']
            fp = ((fp ^ (b['heap'] ^ b['address'] ^ b['size'] ^ int(b['used']))) * 16777619) & 0xffffffff
        events[-1]['data']['fingerprint'] = fp
        with self.assertRaisesRegex(ValueError, 'Overlapping'): decode(events)

    def test_missing_footer(self):
        with self.assertRaisesRegex(ValueError, 'Missing'): decode(fixture()[:-1])

    def test_orphaned_page(self):
        events = fixture(); events[0]['data']['phase'] = 'another-run'
        with self.assertRaisesRegex(ValueError, 'Orphaned'): decode(events)

    def test_owner_overflow(self):
        events = fixture() + [dict(kind='HEAP_OWNER', data=dict(name='queue-map-overflows', count=1))]
        with self.assertRaisesRegex(ValueError, 'overflow'): decode(events)

    def test_stale_or_partial_owner(self):
        for index, caller, kind in ((0, 123, 5), (1, 123, 0), (1, 0, 5)):
            events = fixture(); events[index]['data'].update(queue_caller=caller, queue_kind=kind)
            with self.assertRaisesRegex(ValueError, 'stale'): decode(events)

    def test_settled_deltas(self):
        events = fixture() + [dict(kind='HEAP_STATE', data=dict(phase=phase, ms=ms, heap_free=free,
                 largest_free=1000, core_live=0, core_bytes=0))
            for phase, ms, free in (('complete-immediate', 10, 1400), ('complete-5s', 5020, 1420))]
        self.assertEqual(decode(events)['settle'], dict(elapsed_ms=5010, free_delta=20, largest_delta=0, core_live=0, core_bytes=0))

    def test_owner_cleanup_map_difference(self):
        events = fixture()
        block = dict(phase='owner-thread-cleaned', heap=100, end=2000, address=104,
                     size=1500, used=False, queue_caller=0, queue_kind=0)
        fp = ((2166136261 ^ (100 ^ 104 ^ 1500)) * 16777619) & 0xffffffff
        events += [dict(kind='HEAP_BLOCK', data=block),
                   dict(kind='HEAP_MAP', data=dict(phase=block['phase'], stable=True,
                                                  complete=True, blocks=1, fingerprint=fp)),
                   dict(kind='HEAP_OWNER', data=dict(name='lwip-owner-thread-semaphore', address=508, size=92))]
        cleanup = decode(events)['thread_cleanup']
        self.assertEqual([b['address'] for b in cleanup['used_blocks_disappeared']], [508])
        self.assertEqual(cleanup['used_blocks_appeared'], [])
        self.assertEqual(cleanup['declared_thread_resource']['address'], 508)

    def test_long_settle_is_not_owner_cleanup(self):
        events = fixture()
        for phase in ('complete-65s', 'owner-thread-cleaned'):
            block = dict(phase=phase, heap=100, end=2000, address=104,
                         size=1500, used=False, queue_caller=0, queue_kind=0)
            fp = ((2166136261 ^ (100 ^ 104 ^ 1500)) * 16777619) & 0xffffffff
            events += [dict(kind='HEAP_BLOCK', data=block), dict(kind='HEAP_MAP',
                       data=dict(phase=phase, stable=True, complete=True, blocks=1, fingerprint=fp))]
        for phase, ms, free, largest in (('complete-immediate',10,1400,1000), ('complete-65s',65020,1500,1500)):
            events.append(dict(kind='HEAP_STATE', data=dict(phase=phase, ms=ms,
                          heap_free=free, largest_free=largest, core_live=0, core_bytes=0)))
        a = decode(events)
        self.assertEqual(a['thread_cleanup']['baseline_phase'], 'complete-65s')
        self.assertEqual(a['thread_cleanup']['used_blocks_disappeared'], [])
        self.assertEqual(a['settle_extended']['largest_delta'], 500)


if __name__ == '__main__':
    unittest.main()
