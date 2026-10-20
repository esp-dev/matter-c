# Memory11: stable demand-allocated Read/Subscribe result blocks

Baseline: `735b547` (Memory10). The512-result ceiling, request/selector/value/
snapshot limits, report order, public APIs/layouts, wire and persistence formats,
timeouts, fail-safe and ACK/drain gates remain unchanged. No global arena, task,
scheduler, memory quota or reduced default was introduced.

## Implementation and ownership

Read results, Subscribe persistent results and Subscribe report-only captured
values use one private indexed block mechanism. Typed flexible arrays preserve
element alignment and C99 types. Each block holds at most16 elements. A first
small reservation uses at least9 entries, retaining the previous initial result
budget; the last block stops at512. There is no fixed maximum-sized pointer
directory and no existing allocation is copied or replaced during growth.
An owner-local cache makes forward scans linear; backwards lookup restarts at
the head and traverses at most33 result blocks. This trades direct array indexing
for bounded traversal and extra allocator calls; no latency guarantee is claimed.

Each reserve stages every required new block, checking count/size overflow before
allocation. Only complete success links the staged chain. OOM leaves previous
payload, addresses, capacity, links and cache intact, frees staging and follows
the existing ResourceExhausted policy. Subscribe still reserves the entire
report value table before calling providers; no partially admitted successful
capture is published. Empty tables allocate nothing. Cleanup cannot allocate.

The existing logical Read filtering compaction still preserves order and may
copy retained entries into earlier slots; blocks themselves stay at stable
addresses. Providers never receive result-table pointers, and no result pointer
is retained across compaction. Immutable value spans remain separately owned.
Subscribe retains path/version blocks while idle; captured value blocks exist
only for its current report. Consumed complex values still wait for BOTH the
chunk's IM Success and MRP confirmation; partial lists stay live. Final Read
sent releases result blocks after the independent immutable packet copy, while
remaining value/event snapshots retain their confirmation or cancel/drain
lifetime. Prefix/whole-report cleanup, numbering and cursors are unchanged.

## ESP32 layouts, allocation requests and stack

GCC13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`: all27 compile-only
probes pass without diagnostics. No linked firmware or physical ESP32 test.

| Private storage | Before | After |
| --- | ---: | ---: |
| Read owner |296 B |304 B |
| Subscribe owner |336 B |360 B |
| Read entry / Subscribe entry / captured value |48 /24 /16 B |unchanged |
| Full512-result Read table, steady payload |24576 B |24840 B |
| Full Read table growth envelope |38400 B |24840 B |
| Largest individual Read result allocation |24576 B |776 B |
| Full512-result Subscribe table, steady payload |12288 B |12552 B |
| Full Subscribe table growth envelope |19200 B |12552 B |
| Largest individual Subscribe result allocation |12288 B |392 B |
| Full512-value report table, steady payload |8192 B |8448 B |
| Largest individual report-value table allocation |8192 B |264 B |

The result-growth envelopes compare the old288-entry plus new512-entry arrays
against all33 new blocks (including8-byte headers). Growth-only reductions are
13560 B for Read and6648 B for Subscribe. Steady full tables grow by264 B each;
the report value table grows256 B across32 blocks. Partial final blocks, a small
first reservation and larger owners can also cost extra bytes for small reports.
These are requested payload bytes, excluding allocator metadata/fragmentation.
Large encoded values and event selector workspaces still allocate independently;
this is not a promise that every node allocation is below1 KiB.

| ESP32 compiler frame | Before | After |
| --- | ---: | ---: |
| Read process |144 B |144 B |
| Subscribe process |192 B |192 B |
| Read attribute encoder |48 B |64 B |
| Read filtering compaction |32 B |48 B |
| Read reserve / shared reserve specialization |32 B |32 B |
| Subscribe reserve / shared reserve specialization |32 B |48 B |
| Subscribe attribute encoder |48 B |48 B |
| Read final sent |32 B |32 B |

New typed accessors and block free/find helpers use32-byte frames in these
probes. No large task-stack data was added. New nested lookup calls contribute
beyond the isolated caller frames; these measurements do not establish complete
call-chain depth or RTOS stack high-water. Physical target stack/allocator
endurance remains unmeasured.

## Identical baseline/final component workloads

The public-API harness is compiled against both production versions. A separate
Read case records the tracked heap high-water immediately before the first
provider read, after all512 wildcard results have expanded. It excludes its
fixture, event-log owner and explicit transport allocation, but includes Read
owner/output/parser/selector state and table-growth overlap.

| x86_64 requested Read payload | Before | After |
| --- | ---: | ---: |
| Pre-provider512-result preparation peak |54142 B |38558 B |
| Largest individual request during that case |28672 B |5640 B |

Preparation peak falls15584 B (28.8%). The new largest allocation is event path
metadata, rather than a result table. The existing node component then holds
24 subscription/replacement engines, six active512-result Reads, fourteen final
Read tails and52 independent maximum-packet allocation/borrow proxies. It fully
evicts the shared128-record event log while snapshots remain held, verifies all
original bytes/numbers/results, alternates both ACK/status orders, checks
publication OOM, and retains cancellation/timeout tails through modeled drain.

| x86_64 node component requested payload | Before | After |
| --- | ---: | ---: |
| Subscriptions, active Reads and packet leases |551908 B |556132 B |
| Plus fourteen final Read tails |572964 B |577412 B |
| Log fully replaced, old snapshots still held |606756 B |611204 B |
| Confirmed reports, retained owners and packets |285352 B |286632 B |
| Observed allocation peak |625602 B |620266 B |
| Largest request |28672 B |5656 B |

Peak falls5336 B (0.85%) while retained states grow slightly: the old transient
table replacement disappears, but block headers and owners remain. Explicit
packet leases are proxies, not real ciphertext or a reachable dispatcher
population. Real quota/closing/MRP/async UDP regressions remain in `test_dispatch`
and the full-host scenario. Component tracking excludes fixture/tracker/libc
metadata, dispatcher objects, other handlers, model/platform and crypto.

The unchanged saturated subscription harness holds fifteen512-result,16384-byte
reports plus five nine-path large-list Reads. All captured bytes, versions and
provider call counts are checked through57 chunks in both ACK/status orders.

| x86_64 saturated report payload | Before | After |
| --- | ---: | ---: |
| Fifteen captured reports |701880 B |718080 B |
| Plus five large-list Reads |816985 B |833345 B |
| Halfway through subscription delivery |660115 B |676475 B |
| Subscriptions idle, Reads deleted |210090 B |218610 B |
| Observed allocation peak |819313 B |835673 B |
| Largest request |12288 B |4800 B |

This is a measured16360 B (2.0%) peak heap regression and8520 B idle increase,
in exchange for eliminating large contiguous tables and growth copies. Headers,
alignment, slack and larger owners cost memory; more allocations also add libc
metadata not counted here. No general fragmentation or speed improvement is
inferred solely from smaller requested blocks. Windows and Linux profiles agree;
normal, dedicated Memcheck and separate sanitizers check the same workloads.

The compiler-derived reporting/event/dispatcher/TX additive envelope falls
2307996 ->2073964 B for one shared evicted generation, or3672988 ->3438956 B
when all44 snapshots retain different generations. The tool now includes block
headers and removes old-array growth overlap; legacy probes remain supported.
The largest report-handler allocation in this envelope falls24576 ->5584 B
(event selector state); a maximum encoded value plus link still needs4100 B.
The tool includes parser/selector/plan allocations in this maximum now that
result tables no longer dominate. These loose sums add mutually exclusive phases across owners
and omit crypto/other handlers/Fabric/model/platform/allocator/RTOS resources.
They are not observed peaks, total process RAM bounds, proof of ESP32 fit or
normative RAM requirements.

## Validation and reproduction

Windows full CTest passes94/97 in the restricted sandbox; the exact three socket
failures pass3/3 with local socket access. Final focused tests pass7/7. Inventory:
255 files,96 native definitions,59 core sources and75 closed public headers.
The private block test checks stable aligned zeroed addresses through512 entries,
forward/backward access, all64 empty/partially populated multi-block OOM positions,
unchanged old data/links/cache/capacity, overflow/limit and allocation-free double
cleanup. Existing suites cover512/513 result admission, filtered compaction,
overlapping selectors, list fragmentation, version/fabric/ACL changes, all14
initial capture failures, four continuation RX failures, cancellation/timeouts,
event snapshots, delayed status/ACK and independent transport ownership.

Linux CTest passes94/94 in normal and separate ASan/UBSan/LSan builds. The full
two-instance metered/source/three-phase scenario passes6/6 under Memcheck and6/6
separately under sanitizers, with exit code0 and empty stderr. Dedicated
block, node-component, Read, Subscribe and saturated-report Memcheck runs have
zero live bytes/blocks, errors and suppressions. Both saturated profiles also
pass separate sanitizers with identical requested-byte accounting. Source hashes
verify234 exported source/test/tool files against the checkout and157 baseline
core files against the archived commit. Full evidence is recorded in
[memory11-results.json](memory11-results.json). Normal and sanitizer builds remain
separate. No private credentials/controller/device states enter the portable
source export or evidence. The same jscpd4.0.5 scan of66 implementation C files
finds7 clones/69 duplicated lines before,6 clones/58 lines after shared reservation
replaces the duplicate growth code. Headers/tests are excluded; no linked flash-
size claim follows from this scan.

The native five-fabric/fifteen-session/fifteen-three-path-subscription host driver
passes50/50 checks at a3-second maximum interval. Whole-host Massif with used
stacks enabled passes50/50 at30 seconds; all16 controller processes exit zero in
each run. The driver retains nine-path Reads, Writes, heartbeat and protected
session admission checks, distinct from the512-result component workloads above.

| Whole-host largest sampled value | Memory10 | Memory11 |
| --- | ---: | ---: |
| Heap payload |388288 B |389010 B |
| Used stack |6680 B |6688 B |
| Heap + allocator metadata + used stack |399720 B |401048 B |

The current heap/combined peak is389010 B payload +6518 B allocator metadata
+5520 B used stack. The6688-byte stack maximum is a separate early snapshot;
independent maxima must not be added. Heap increases722 B (0.19%) and combined
demand1328 B (0.33%) in these sampled runs. This ordinary workload therefore
does not show a whole-host heap reduction. Block metadata/churn, timing and
sampling all affect the comparison; small deltas are not attributed solely to
one layout. Controller processes are excluded. Linux host ABI, discovery/network
adapters, allocator and used-stack samples cannot substitute for ESP-IDF,
radio/lwIP, target fragmentation and reserved RTOS task stacks.

```text
cmake --build build/memory01/windows -j4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$"
ctest --test-dir build/memory01/windows --output-on-failure -R "^(test_im_blocks|test_im_read_alloc|test_im_subscribe_alloc|test_im_node_memory|test_im_snapshots|test_events|test_dispatch)$"
test_im_node_memory
test_im_subscribe_alloc --memory-only
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory11/esp32
python tools/matter/report_memory_budget.py --layout build/memory11/esp32/layouts.json --output build/memory11/esp32-budget.json
# Linux normal and separately -DMATTER_SANITIZE=ON: full CTest and runtime-pair-host
# with chip_tool_three_phase.py --source-registers --meter-services.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 test_im_blocks
# Same Memcheck options: test_im_node_memory, test_im_read_alloc,
# test_im_subscribe_alloc and test_im_subscribe_alloc --memory-only.
# Native3s, separately Massif --stacks=yes30s:
python tools/matter/tests/chip_tool_memory_capacity.py --chip-tool <tool> --paa <paa> --output <dir> --discriminator 3860 --max-interval <3|30>
```

Changed files and purpose:

- New `main/apps/matter/model/matter_im_blocks_internal.h`: shared typed stable
  block allocation, indexed lookup, atomic staged growth and allocation-free cleanup.
- `matter_im_read.c` and `matter_im_subscribe.c` in the same directory: typed
  result/value access, shared reservation and cleanup at existing lifecycle gates.
- New `tools/matter/tests/test_im_blocks.c`, updated `test_im_node_memory.c` and
  `test_subscribe_selectors.h`: stability/OOM/size oracles, identical pre-provider
  baseline/final growth measurement and block-aware idle allocation assertions.
- `tools/matter/memory_audit.py` and `report_memory_budget.py`: block layouts,
  requested-allocation bounds and corrected growth envelope arithmetic.
- `cmake/sources.json`, `cmake/test-cases.json`, `doc/oss/test-map.json` and `.md`:
  private-header membership, native target, test inventory and coverage.
- `doc/runtime.md`, `doc/oss/status.md`, this report and `memory11-results.json`:
  ownership contracts, actual savings/regressions and reproducible evidence.

No linked/physical ESP32, RTOS high-water, allocator fragmentation/endurance or
official CSA rerun. Not exhaustive concurrent network/backend OOM coverage.
Next task: demand-sized event path/selector metadata, currently the largest
remaining allocation in the node component, preserving expansion and ACK/drain.
