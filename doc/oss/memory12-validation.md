# Memory12: demand-allocated Read/Subscribe event path metadata

Baseline: `75b7365` (Memory11). Public APIs/layouts, request/value/result/event
limits, wire/persistence formats, report order, event snapshots/numbering/
priorities, fail-safe and ACK/drain remain unchanged. The application still owns
scheduling, memory lifecycle and per-instance resources.

## Representation and ownership

The event owners formerly embedded120 path-state entries,120 filters and nine
raw-selector slots. They now own only small state plus demand allocations:

- Each decoded selector has a small linked node. These nodes retain no provider
  pointers and release when expansion finishes, before allocating filter scratch.
- Deduplicated concrete paths use the existing stable typed block mechanism.
  Blocks hold at most16 entries, with the existing small initial capacity9 and
  a last block capped at120. Growth never replaces or copies previous blocks.
- Contiguous filter scratch allocates for the actual expanded path count, rather
  than120 by default. This is capacity for all expanded paths, including denied
  ones; the authorized subset is still selected after access checks.

Concrete paths are inserted during decoding before wildcard expansion, retaining
their explicit status behavior even when an earlier wildcard overlaps them.
Urgency is ORed across matching selectors. Candidate counting still precedes
deduplication/access, and at most8 enumeration callbacks occur per process call.
The new common helpers preserve selector order, metadata privilege checks and
report status-before-data behavior. Their cached indexed lookup adds bounded
block traversal (at most8 blocks at120 paths), rather than direct array access.

Raw-selector allocation and initial concrete path reservation publish together:
failure frees the new selector and preserves earlier paths/links. Block growth
uses the existing atomic reservation. Filter OOM leaves captured paths intact;
failed interactions emit the existing ResourceExhausted response and cleanup
follows owner lifecycle. A failed expansion is terminal for that request, not a
new public retry protocol. No log/model mutation or successful partial report
is introduced. Empty wildcard results allocate no path blocks or filter scratch.
Attribute-only interactions still allocate no event metadata.

Read releases filters immediately after the immutable record snapshot is
captured; reports only need frozen records and path authorization/status state.
At final sent it releases path blocks and the small event owner after the MRP
copy. Remaining record/value references wait for their existing confirmation or
cancel/timeout/drain boundary. Subscribe retains path state and its exact filter
scratch while idle: urgency checks can reuse it without allocations or callbacks.
It does not re-enumerate metadata for later reports. Whole-report success still
commits the watermark; status alone cannot commit or release an in-flight chunk.
Deletion clears selectors, paths, filters and snapshots without allocating.

## ESP32 compile-only sizes and scope

GCC13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`; all27 probes pass with
no diagnostics. These are layouts/individual frames, not linked firmware,
complete call-chain depth or physical ESP32/RTOS high-water measurements.

| ESP32 compiler frame | Before | After |
| --- | ---: | ---: |
| Read process |144 B |144 B |
| Subscribe process |192 B |192 B |
| Read / Subscribe attribute encoder |64 /48 B |unchanged |
| Subscribe urgent pending-change helper |64 B |80 B |
| Read shared block-reserve specialization |32 B |48 B |
| New shared event path admission |n/a |64 B |
| New typed event path accessor |n/a |32 B |

Nested indexed lookup/free/reserve calls add costs beyond the isolated process
frames; no large task-stack buffer was introduced. These numbers cannot determine
the task-stack reservation needed with target crypto, libc and callbacks.

| Private event metadata | Before | After |
| --- | ---: | ---: |
| Read event owner |5576 B |144 B |
| Subscribe event owner |5584 B |160 B |
| Per expanded path / per filter |28 /16 B |unchanged |
| Per raw-selector allocation |embedded |24 B |
| Largest individual path block |embedded |456 B |
| Filter scratch at120 paths |embedded |1920 B |
| Read metadata, one expanded path after capture |5576 B |404 B |
| Subscribe metadata, one expanded path / idle |5584 B |436 B |

The one-path totals include a nine-slot path block (260 B) and the event owner;
Subscribe also retains16 B filter scratch. Record-reference vectors/nodes,
attribute results, parsers, RX/TX, allocator overhead and application resources
are excluded. Read/Subscribe primary owners remain304/360 B. Small-path event
metadata therefore shrinks by5172/5148 B without changing admission.

At120 paths, eight path blocks occupy3424 B. Read's retained metadata after
capture is3568 B; its temporary capture phase additionally needs1920 B filters,
for5488 B. Subscribe retains5504 B including filters. Baseline fixed owners were
5576/5584 B. Up to216 B raw selectors belong to the earlier expansion phase and
are freed before filters are allocated. Full-path allocations have more libc
headers and allocator calls than before; a reduction in requested payload does
not prove a reduction in fragmentation, latency or allocator overhead.

The conservative reporting/event/dispatcher/TX tool now includes all separate
path blocks, raw selector nodes and filters. It deliberately adds mutually
exclusive phases, as in earlier batches. Its shared-generation subtotal changes
2073964 ->2077996 B, and its distinct-generation subtotal3438956 ->3442988 B.
The4032 B increase is a loose additive bound including simultaneous selector and
filter phases; it is not a measured peak or an assertion that those phases
coexist. The largest report-handler allocation falls5584 ->4100 B, now an encoded
value plus link. Both subtotals omit other handlers/crypto/Fabric/model/platform/
allocator/RTOS resources and cannot establish total or normative ESP32 RAM.

## Identical component workloads

The unchanged public-API node harness compiles against both production versions.
It holds24 subscription/replacement engines, six active512-result Reads, fourteen
final Read tails and52 explicit maximum-packet allocation/borrow proxies. The
published128-record event generation is completely overwritten while old
snapshots remain held. Every old record number/payload and Read result is checked
through drain in both ACK/status orders, with publication OOM, final cancellation
and timeout cases. No tracked allocation remains after teardown.

| x86_64 requested component payload | Before | After |
| --- | ---: | ---: |
| Pre-provider512-result Read preparation peak |38558 B |33458 B |
| Largest request in that Read case |5640 B |4800 B |
| Subscriptions, active Reads and packet leases |556132 B |402556 B |
| Plus fourteen final Read tails |577412 B |423836 B |
| Log replaced while old snapshots remain held |611204 B |457628 B |
| Confirmed reports, retained owners and packets |286632 B |163848 B |
| Observed component allocation peak |620266 B |461558 B |
| Largest component request |5656 B |4800 B |

Peak reduction158708 B (25.6%), about606 ->451 KiB. This workload has one event
path per owner, where the old fixed arrays were largely unused. Read preparation
falls5100 B (13.2%). Windows, Linux normal/Memcheck and separate sanitizers agree
on requested-byte profiles. The separate fifteen512-result/16384-byte attribute
subscription reports plus five large-list Reads remain unchanged:835673 B peak,
218610 B idle,4800 B largest request,57 chunks. No event metadata is allocated
there. Fixture/tracker/libc metadata, dispatcher objects, other handlers, crypto,
model/platform resources are excluded. Packet leases are explicit proxies, not
actual ciphertext or a reachable dispatcher population; real quotas/MRP/UDP
leases remain separately checked by the dispatcher and full-host scenarios.

## Validation

The new private metadata target checks120 stable path addresses, bounded
enumeration work, exact filters, phase cleanup, selector/first-path/filter OOM,
concrete precedence, urgency union and allocation-free double cleanup. Shared
public Read/Subscribe tests additionally fault every allocation from receive to
capture for one and120 wildcard paths:4 and40 positions per engine, including
yielded parser reacquisition. Every fault must produce ResourceExhausted, no
successful partial ReportData and zero live allocations at deletion. Existing
tests retain120/121 candidates, duplicate-selector cap counting, malformed
selectors/enumerators, empty models, access/fabric changes, EventMin, record
snapshot stability across eviction, urgency, chunk order, watermark and ACK/drain.

Compiler-derived frames, full Windows/Linux regressions, independent chip-tool
wildcard Read/Subscribe acceptance, dedicated Memcheck and whole-host Massif
results are recorded with source/evidence hashes in
[memory12-results.json](memory12-results.json). Normal Memcheck and sanitizer
builds/runs remain separate. Credentials/controller/device states are excluded
from the portable source/evidence. None of these tests is an official CSA rerun.

Windows full CTest passes95/98 inside the restricted sandbox; the exact three
UDP socket failures pass3/3 with local socket access. Focused tests pass4/4.
Linux CTest passes95/95 in normal and separate ASan/UBSan/LSan builds. The full
two-instance metered/source/three-phase scenario passes6/6 under Memcheck and6/6
separately with sanitizers, with exit code0 and empty stderr. Dedicated metadata,
node-component, Read, Subscribe and saturated attribute-report Memcheck runs
report zero live bytes/blocks, errors and suppressions. Independent full-host
wildcard Read/Subscribe tests pass22/22 under Memcheck and22/22 under sanitizers,
covering six valid selector forms, overlapping concrete/wildcard paths, EventMin,
mixed chunks, empty prime, future events, ACL revocation/restore and urgency.
The corresponding node exits are0 and stderr is empty. The same14 initial
attribute-capture and four continuation-RX allocation faults remain covered.

The inventory passes256 test/fixture/controller files,97 native definitions,59
core sources and75 public headers. Source hashes verify236 exported code/test/
tool files against the checkout and158 baseline core files against the archive.

The same jscpd4.0.5 scan of66 implementation C files finds6 clones/58 duplicated
lines before and after. Shared selector/path/filter/cleanup code lives in the
existing private helper header; headers/tests are excluded from this scan. No
linked firmware flash-size saving is claimed.

The native five-fabric/fifteen-session/fifteen-three-path-subscription host driver
passes50/50 checks at a3-second maximum interval. Whole-host Massif (`--stacks=yes`)
also passes50/50 at30 seconds. All16 controller processes exit0 in each run.
This is the existing ordinary attribute-report workload, distinct from the
event-heavy component and wildcard acceptance above.

| Whole-host largest sampled value | Memory11 | Memory12 |
| --- | ---: | ---: |
| Heap payload |389010 B |390233 B |
| Used stack |6688 B |6744 B |
| Heap + allocator metadata + used stack |401048 B |402000 B |

The current heap and combined maxima coincide:390233 B payload,6503 B allocator
metadata and5264 B used stack. The6744-byte stack maximum is a separate early
sample; do not add independent maxima. Heap increases1223 B (0.31%) and combined
demand952 B (0.24%) in these sampled runs. There is no observed whole-host heap
reduction in this ordinary workload. Timing, report phase and sampling affect
the small deltas; they are not attributed solely to the new metadata layout.
Linux ABI, discovery/network adapters, host allocator and sampled used stacks
cannot substitute for target crypto, ESP-IDF/lwIP/radio, allocator fragmentation
and reserved RTOS task stacks. Controller processes are excluded.

```text
cmake --build build/memory01/windows -j4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$"
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_im_event_metadata|test_im_read_alloc|test_im_subscribe_alloc|test_im_node_memory)$"
test_im_node_memory
test_im_subscribe_alloc --memory-only
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory12/esp32
python tools/matter/report_memory_budget.py --layout build/memory12/esp32/layouts.json --output build/memory12/esp32-budget.json
# Linux normal and separately -DMATTER_SANITIZE=ON: full CTest, runtime-pair-host
# with chip_tool_three_phase.py --source-registers --meter-services.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 test_im_event_metadata
# Same options: test_im_node_memory, test_im_read_alloc, test_im_subscribe_alloc,
# and test_im_subscribe_alloc --memory-only.
python tools/matter/tests/chip_tool_event_wildcards.py --chip-tool <tool> --paa <paa> --output <fresh-dir> --discriminator 3872
# Native3s and separate Massif --stacks=yes30s full-host capacity workloads:
python tools/matter/tests/chip_tool_memory_capacity.py --chip-tool <tool> --paa <paa> --output <dir> --discriminator 3860 --max-interval <3|30>
```

Changed files and purpose:

- `main/apps/matter/model/matter_im_events_internal.h`: shared dynamic selector
  admission, stable deduplicated path blocks, exact filter reservation and cleanup.
- `matter_im_read.c` and `matter_im_subscribe.c` in the same directory: allocation
  and phase cleanup, indexed path access, unchanged snapshot/report/ACK ownership.
- New `tools/matter/tests/test_im_event_metadata.c` and expanded
  `test_im_event_wildcards.h`: lifetime/allocation/OOM oracles and public-engine
  fault coverage through maximum wildcard expansion.
- `tools/matter/memory_audit.py` and `report_memory_budget.py`: measured metadata
  layouts and explicit inclusion of dynamic allocations in the additive envelope.
- `cmake/test-cases.json`, `doc/oss/test-map.json` and `.md`: target and inventory.
- `doc/runtime.md`, `doc/oss/status.md`, this report and `memory12-results.json`:
  ownership contracts, evidence, costs and verification limits.

No linked/physical ESP32, target allocator fragmentation/endurance, RTOS high-water
or official CSA rerun. Not exhaustive network/backend allocator-fault coverage.
Next: compose the target application/ESP32 memory measurement harness, including
crypto and task stacks, before redesigning Fabric image/rollback representation.
