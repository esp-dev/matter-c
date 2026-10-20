# Memory10: shared event snapshots and compact Read delivery tails

Baseline: `5d726de` (Memory09). Public APIs/layouts, wire/persistence formats,
512 expanded results, 4096-byte value/16384-byte report payload budgets, event
capacity/numbering/priorities, admission, fail-safe and ACK/drain remain unchanged.
Application scheduling and per-instance ownership remain application-controlled.

## Ownership and failure behavior

The event log's immutable record nodes now carry a reference count. A private
snapshot allocates an exact pointer vector rather than another record array.
Snapshots share published nodes but retain frozen membership, bytes and stable
addresses after eviction or fabric removal. Public copy functions still copy
the unchanged record DTO. The same matching predicate serves copying and private
capture; reference release is shared by Read and Subscribe.

Capture counts and validates the authorized union, allocates its vector, checks
every reference increment for overflow, then publishes without application
callbacks. OOM, BUSY or overflow preserve the previous snapshot and all old
counters. Log preparation, number reservation and eviction selection are
unchanged. Commit/abort and snapshot release cannot allocate. Dropping log
ownership on eviction/removal does not invalidate retained snapshots; remaining
reports still recheck authorization/fabric before output.

Read/Subscribe drop a consumed event prefix only at the existing BOTH-MRP-ACK-and-
successful-IM-continuation gate. Whole-report Subscribe success still commits its
event watermark; failed statuses cannot advance it. At final Read `sent`, output
has already been copied into independent immutable MRP storage and its borrow
expires. Results, plans, selectors/filters, RX/TX and event path metadata can
therefore release. Remaining value/event references move into the small delivery
tail and wait for final confirmation, or cancel/timeout followed by owner drain
and deletion. Intermediate chunk metadata stays live. No new quota, allocator
pool, scheduler or early transport-buffer release is introduced.

## ESP32 compile-only layouts and stack

GCC13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`; all 27 probes pass
without diagnostics. These are object layouts and individual frames, not linked
firmware, complete call-chain stack or physical RTOS high-water measurements.

| Private object | Before | After |
| --- | ---: | ---: |
| Public event DTO (unchanged) |232 B |232 B |
| Event node |240 B |248 B |
| Event-log owner |808 B |808 B |
| Exact 128-record snapshot allocation |29696 B |512 B |
| Snapshot field in event selector owner |4 B |12 B |
| Read event selector owner |5568 B |5576 B |
| Subscribe event selector owner |5576 B |5584 B |
| Read owner |288 B |296 B |

The full log costs an extra1024 B at128 records, even without event subscribers.
This is the deliberate per-node reference-count tradeoff. A final Read now owns
only its296-byte owner, remaining immutable value nodes and exact event reference
vector; it no longer retains its24576-byte full result table or5576-byte event
selector state through a delayed final ACK. Complex value data remains separately
owned until its existing confirmation/drain boundary.

| Compiler frame | Before | After |
| --- | ---: | ---: |
| Read process |160 B |144 B |
| Subscribe process |208 B |192 B |
| Event prepare |128 B |128 B |
| New event snapshot acquire |n/a |96 B |
| New snapshot clear / prefix release |n/a |32 B each |
| Read sent / confirm |32 B each |32 B each |

No large buffer was placed on a task stack. New capture/release calls still add
call-chain costs beyond these isolated frames; callbacks, libc and crypto remain
part of the eventual target stack budget.

## Node component measurement

The same public-API harness compiles against baseline and final production core.
It holds six fabric/PASE identity buckets: 24 subscription/replacement engines,
six active512-result scalar Reads and fourteen final512-result/event Reads
awaiting confirmation. Every report captures the same full128-record log, then
the entire published log is overwritten while outputs/tails remain held. Every
original event number/payload and Read result is checked during drain, with
alternating ACK-before-status and status-before-ACK. Publication OOM preserves
bytes and numbering. Separate cancellation/timeout cases retain final snapshots
through the modeled transport lease, allocate nothing and leave packet bytes
unchanged. Deletion leaves zero tracked allocations.

Fifty-two separate1232-byte packet leases model the configured maximum TX payload
allocation and output borrow/copy boundary. These are explicit proxies, not real
ciphertext or an actual dispatcher population. Existing `test_dispatch` covers
real quota partitions, replacements, closing counts, MRP and asynchronous UDP
cancellation/leases; the full-host tests below exercise real composition.

Requested production bytes instrument event, Read and Subscribe allocations plus
these explicit packet leases. Fixture/tracker/libc overhead, dispatcher objects,
other handlers, model/platform and crypto are excluded. Windows x86_64, Linux
normal/Memcheck and separate sanitizers produce the same component profile.

| Component payload | Before | After |
| --- | ---: | ---: |
| Published full log only |33688 B |34712 B |
| Subscriptions plus active Reads and all packet leases |1441140 B |551908 B |
| Plus fourteen final Read tails |2441832 B |572964 B |
| Published log fully replaced while snapshots remain |2441832 B |606756 B |
| All reports confirmed, owners/packet leases still retained |1703904 B |285352 B |
| Observed tracked allocation peak |2444160 B |625602 B |
| Largest individual request in this workload |30720 B |28672 B |

Peak reduction1818558 B (74.4%): about2.33 MiB ->611 KiB. This is a deliberately
heavy configured workload and still excludes substantial node resources. Smaller
or event-free workloads may pay the reference-count overhead without sharing
savings. Different retained generations also share less than this harness.

## Conservative reporting/event/dispatcher/TX subtotal

`tools/matter/report_memory_budget.py` consumes compiler-derived sizes/limits,
including subscription replacements and finished Read delivery slots. Defaults
produce24 subscription/replacement slots, six active Reads, fourteen Read tails
and eight other protected admission/delivery slots:52 transaction nodes/maximum
TX packets and44 possible reporting snapshots. Optional PASE has its own bucket.
Unsupported subscription/transport combinations are rejected; defaults are not
changed. The tool deliberately adds mutually exclusive parser, table-growth,
capture and delivery phases across all owners. It is a loose conservative
payload subtotal, not a reachable peak, normative requirement or total RAM bound.

| ESP32 additive envelope at existing defaults | Before | After |
| --- | ---: | ---: |
| One shared, fully evicted event generation |4063412 B |2307996 B |
| Every snapshot pins its own distinct generation |4063412 B |3672988 B |

For the shared case, node storage allows published128 + prepared128 + retired128
nodes. For distinct generations it permits `(2+44)*128=5888` nodes. The latter
prevents the incorrect assumption that a128-record log bounds all retained event
heap. Before Memory10 private event copies were included per handler instead.
The new envelope's subscription group is1423248 B, active Reads432564 B,
Read tails269360 B, transaction nodes14560 B, TX64064 B, dispatcher8160 B,
log owner808 B and event nodes95232 B (shared) or1460224 B (distinct).
The largest report result allocation on ESP32 remains24576 B contiguous.

Omissions are explicit in the output: allocator metadata/fragmentation, other
transport/secure owners, Invoke/Write/client/BDX/PASE/CASE/backend work, Fabric
publication/rollback/restore, model/application/platform, radio/lwIP and RTOS
stacks. The existing general-purpose caps permit more demand than small ESP32
internal RAM. This change cannot establish a universal RAM quantity required to
meet the specification; an application profile and target measurements remain
necessary. No configuration minima or supported request limits were reduced.

## Validation and reproduction

Windows full CTest passes93/96 inside the restricted sandbox; the exact three
socket failures pass3/3 with local socket access. Final focused event/Read/
Subscribe/dispatcher/component tests pass5/5. Linux normal and separate
ASan/UBSan/LSan CTest pass93/93 each. The full two-instance metered/source/three-
phase scenario passes6/6 under Memcheck and6/6 separately with sanitizers, with
clean exits and empty stderr. Dedicated component, event, Read and Subscribe
Memcheck runs report zero live bytes/blocks, errors or suppressions. The focused
four event/Read/Subscribe/component targets additionally run at16 and1024 event
capacity. Existing tests retain4000 differential log operations, every batch-node
OOM, durable failures, rollback, ACL/fabric changes and full snapshot delivery.
New cases check same-record identity, overflow-before-any-increment, capture OOM,
BUSY, eviction, scoped removal and allocation-free final-reference release.

The portable inventory covers254 test/fixture/controller files,95 native test
definitions,59 core sources and75 public headers. The same jscpd4.0.5 scan of66
implementation C files finds7 clones/69 duplicated lines before and after;
headers/tests are excluded. Shared matching and snapshot cleanup add no new
reported clone. No linked flash-size saving is claimed.

The native five-fabric/fifteen-session/fifteen-subscription host driver passes
50/50 checks at a3-second maximum interval. The same driver under whole-host
Massif (`--stacks=yes`) passes50/50 at30 seconds; all16 controller processes exit
zero in each run. These are three-path subscriptions with nine-path Reads,
Writes, heartbeats and protected admission, rather than the saturated event
component above.

| Whole-host largest sampled value | Memory09 | Memory10 |
| --- | ---: | ---: |
| Allocated heap payload |388317 B |388288 B |
| Used stack |6752 B |6680 B |
| Heap + allocator metadata + used stack |399176 B |399720 B |

The current heap and combined maxima coincide:388288 B payload,6128 B allocator
overhead and5304 B stack. The6680-byte stack maximum occurs in a separate early
sample; independent maxima must not be added. There is essentially no observed
heap improvement in this ordinary workload; combined demand increases544 B
(0.14%) in these sampled runs. Sharing benefits depend on concurrent retained
events and final delivery tails, while node counters add cost even without them.
Timing/sampling and allocator effects preclude attributing every small delta to
one layout change. The794 samples include host/application/Mbed TLS allocations,
exclude controller processes and do not bound every reachable workload.

Source/evidence hashes and exact profiles are in
[memory10-results.json](memory10-results.json). Linux discovery/network adapters,
host ABI/allocator and sampled used stacks cannot substitute for ESP-IDF,
radio/lwIP, target allocator and reserved RTOS stacks. No total target heap/stack
or normative RAM claim follows from these measurements.

```text
cmake --build build/memory01/windows -j4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$"
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_im_node_memory|test_events|test_dispatch|test_im_read_alloc|test_im_subscribe_alloc)$"
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory10/esp32
python tools/matter/report_memory_budget.py --layout build/memory10/esp32/layouts.json --output build/memory10/esp32-budget.json
# Linux: normal and separately -DMATTER_SANITIZE=ON; full CTest and runtime-pair-host
# with chip_tool_three_phase.py --source-registers --meter-services.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 test_im_node_memory
# Same options: test_events, test_im_read_alloc, test_im_subscribe_alloc.
# Configure -DMATTER_EVENTS_CAPACITY=16 and =1024; build/run these four targets.
# Native3s, separately Massif --stacks=yes30s:
python tools/matter/tests/chip_tool_memory_capacity.py --chip-tool <tool> --paa <paa> --output <dir> --discriminator 3860 --max-interval <3|30>
```

Changed files and purpose:

- `main/apps/matter/model/matter_events.c` and new `matter_events_internal.h`:
  reference-counted immutable nodes, shared matching and atomic exact snapshots.
- `matter_im_events_internal.h`, `matter_im_read.c`, `matter_im_subscribe.c` in
  the same directory: common reference access/cleanup, confirmed consumed-prefix
  release and compact final Read delivery tails.
- `tools/matter/tests/test_events.c`, `test_im_multi_events.h`, `test_im_complex.h`
  and new `test_im_node_memory.c`: lifetime/OOM/data/byte oracles and the identical
  baseline/final component harness.
- `tools/matter/memory_audit.py` and new `report_memory_budget.py`: compiler-derived
  role/layout metrics and conservative, explicitly scoped additive envelopes.
- `cmake/sources.json`, `cmake/test-cases.json`, `doc/oss/test-map.json` and `.md`:
  private-header membership, native target and allocation instrumentation/inventory.
- `doc/runtime.md`, `doc/oss/status.md`, this report and `memory10-results.json`:
  ownership contracts, actual measurements, validation and limitations.

No physical/linked ESP32, RTOS high-water, allocator endurance/fragmentation or
official CSA rerun. Not exhaustive concurrent distinct-generation/network/OOM
coverage. Next task: remove large contiguous expanded-result growth overlap in
Read/Subscribe using stable demand-allocated blocks, while preserving existing
limits, report ordering, allocation-failure atomicity and ACK/drain.
