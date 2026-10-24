# Memory39: Read/Subscribe block occupancy

This stage adds reproducible measurement tools and audits the current stable
blocks; it does not change normal Read/Subscribe storage, limits or ACK/drain.
[Results](memory39-results.json) separate one coincident table observation from
individual maxima and the exact core-allocator high-water snapshot.

## Measured inventory

C6 COM23, UART 1000000, TL-MR3020 and the same fixed five-fabric/fifteen-session
profile as Memory38. The observed coincident attribute-table footprint is
**89248 B**. Its Read and Subscribe records were saved at the same owner boundary:

| Table | Requested bytes | Slots / logical used | Empty-slot bytes | Headers B |
|---|---:|---:|---:|---:|
| Read items (4 interactions) | 24064 | 740 / 684 | 1792 | 384 |
| Subscribe items (12 interactions) | 36672 | 2220 / 2052 | 2688 | 1152 |
| Subscribe captured values | 28512 | 1728 / 1116 | 9792 | 864 |
| Total | 89248 | | 14272 | 2400 |

The value blocks have 612 empty slots at this observation. This is the largest
observed padding category. Headers are a separate 2400 B. Empty slots are not
individually freeable without changing block geometry/indexing; these numbers
are inventory, not an immediately recoverable 16672 B promise.

Individual maxima are Read 30080 B (five interactions) and Subscribe 65184 B.
They must not be added as a simultaneous peak: their sum 95264 B describes
different moments. At the Read-only maximum, 13632 B of records lie behind the
already released cursor. Whole prefix blocks may be a useful reclamation target;
partial blocks, inline data lifetimes and all later accesses need an explicit
IM/MRP ownership audit first. Subscribe metadata behind its cursor must remain
for future reports; it is not comparable reclaimable storage.

At fifteen idle subscriptions, persistent item tables total **45840 B**:
2565 logical entries, 2775 slots, 3360 B tail padding and 1440 B headers. Most of
that footprint is real per-path/per-subscriber data, not allocator bookkeeping.

The allocation observer independently snapshots actual usable allocation bytes
at the global core-allocator peak, 232164 B. Three shared block-helper buckets
account for **93444 B**: dense Subscribe translation unit 39808 B /156 blocks,
sparse Subscribe values 28532 B /108, dense Read translation unit 25104 B /52.
DWARF address ranges identify the compilation units even though these helpers
are not inlined. Dense buckets can also contain event-path metadata, so they are
not exclusive item-table labels. Allocator rounding, extra metadata and the
sampling boundary also differ from requested attribute-table bytes above. There
are zero registry/allocator overflows, 131/160 site slots and 1150/2048 peak live
allocation records. Final core objects/bytes and registries are zero/empty.

## Next optimization candidates

1. **Consumed Read prefix blocks.** Investigate freeing only whole blocks below
   the existing released cursor after both IM and MRP confirmation. The measured
   13632 B is a candidate pool, not a proven whole-heap saving. It suggests roughly
   10 KiB might be worth testing after page granularity/lifetime checks. Keep
   ordinal lookup, cached pointers, partial ARRAYs, continuation errors and the
   cumulative snapshot admission budget intact. This is the recommended next task.
2. **Sparse Subscribe value geometry.** 9792 B of unused value slots at the joint
   observation suggests several KiB of possible gain. Smaller pages can increase
   headers/allocation count in dense 512-value reports. Compare both sparse and
   maximum-density cases before changing geometry or stable references.
3. **Immutable shared path metadata.** Fifteen identical full-wildcard path sets
   repeat path IDs. A layout estimate with compact per-subscriber state and one
   shared path set suggests about 18-20 KiB in that steady profile, before a full
   design/measurement. Unique selectors/topology, generations, pool OOM and final
   reference release may erase that gain or increase worst-case memory. This is
   a separate architectural proposal, not implemented here.

Do not add those estimates or compare their independent maxima as a new global
peak. Only implementation plus matched normal-image runs can establish savings.

## Instrumentation and validation

The generators alter an isolated source copy: one intrusive registry pointer per
interaction, owner-only counters, a 100 ms owner sample and pre-delete samples.
`peak-joint` saves both inventories at the same owner boundary. Individual peak
snapshots and current data stay separate. `samples` is the cumulative per-kind
counter at dump time, not the timestamp of the saved maximum.

The allocator observer uses 2048 live entries /160 sites (19596 B). Inventory and
owner sampling add 412 B static storage: measured `.dram0.bss` is 25192 ->45200 B,
**20008 B diagnostic overhead**. Context-pointer padding adds some dynamic cost.
This firmware changes timing/layout; its heap peak 326416 B, min free 69828 B and
min largest 48128 B are not normal-image headline measurements. Memory38's
normal 326256/90172/63488 B remains the valid matched profile result.

C6 sample frames are Read 64 B, Subscribe 96 B, dump formatting 128 B, owner
sample/dump helpers 16 B. Observed owner stack use is 3208/12800 B. No heap is
allocated or payload inspected by the inventory. Existing allocation-hook
tracking/semantics are unchanged. Sampling remains a lower bound, not a complete
instantaneous or specification-wide memory bound.

Actual checks:

- Seven native instrumented Read/Subscribe/block/short/shared-report tests pass,
  including OOM, all-512 stable records, both ACK orders and cancellation/drain.
- Two real native inventories decode with empty final registries. Eleven decoder
  unit tests reject bad byte sums, occupancy, missing/duplicate modes, incomplete
  terminal phases, live registries, unknown fields and invalid counters.
- All four public generators reproduce the exact flashed C6 source outputs, with
  recorded input/output hashes. C6 builds complete; exact ELF/hash matching,
  zero-overflow allocation byte/count checks and 144 inventory records validate.
- The fixed C6 profile passes all fifteen sessions/subscriptions, parallel Reads,
  Fabric publications/removals and held completion/ACK drain, with no healthy
  errors or SDK OOM. No normal core source changes occur in this stage; the full
  Linux Memcheck/separate sanitizer campaign remains Memory38's verified result.

After the audit, the exact normal Memory38 image and original pre-sequence
fabric/NVS are restored. Nine RGB updates/transitions and single-original-fabric
checks pass, followed by zero-live drain. COM23 and TL-MR3020 are released, the
temporary Wi-Fi profile/XML removed, Windows IPv6 stays enabled and COM24 is
untouched. No new CSA, phone pairing or reference ESP-Matter campaign is claimed.
