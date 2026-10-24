# Memory03: demand-allocated event retention and atomic batch staging

Date: 2026-10-20. Baseline: `22aa205` ([Memory02](memory02-validation.md)).
The changes are isolated to the memory checkout. Public function signatures,
wire/storage schemas, event capacities, data/path/TLV budgets and scheduler
ownership stay intact. No official CSA result is changed.

## Implementation

The log owns a list of retained event nodes, not two capacity-sized arrays.
Each node owns a complete record, including the unchanged 192-byte maximum
payload, and keeps its address until eviction/fabric removal/deletion. Shared
helpers select victims, free node chains, and discard failed/aborted staging.

`prepare` validates every input before allocating or reserving numbers. It
allocates one new node per input and assigns the existing consecutive numbers.
It simulates the old array's retention order by marking victims in the old list.
The marked records remain untouched and owned until commit; new staged records
also participate in priority selection. As before, the entire batch is rejected
if its next victim would have higher priority than the new input or belong to
that same batch. Priority ties select the oldest surviving record.

Allocation/priority/store failure frees all staged nodes and resets marks. Old
records and `next` remain unchanged. Durable exclusive reservation is still at
least 32 numbers or the complete larger batch, with the same saturation and boot
skip. Abort may retain an already successful durable reservation, as before.

After successful prepare the log remains busy while the producer publishes its
model. `finish(true)` frees the marked old records and links prepared nodes;
`finish(false)` frees staging/reset marks. Both are allocation-free and cannot
fail. Forgetting a fabric releases just its nodes. Read/Subscribe still own
independent copies of authorized snapshots; they never borrow a retained node.
There is no change to their numbering/filter/fabric/ACL or report/ACK lifecycle.

## ESP32 measurements

Xtensa ESP32 GCC 13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`.
The capacity-128 baseline log is 60,184 B (two 29,696-byte arrays plus metadata).
One record remains 232 B; a live node is 240 B including link/eviction metadata.
The empty owner is 808 B, independent of configured capacity.

| Log-owned requested storage, capacity 128 | Before (B) | After (B) |
| --- | ---: | ---: |
| Empty log | 60,184 | 808 |
| One retained record | 60,184 | 1,048 |
| Eight retained records | 60,184 | 2,728 |
| 128 retained records | 60,184 | 31,528 |
| Full log plus one staged append | 60,184 | 31,768 |
| Full log plus a full 128-record staged batch | 60,184 | 62,248 |

Empty reservation decreases by **59,376 B**. Full retention saves **28,656 B**;
the ordinary full-log append peak saves **28,416 B**. The maximum simultaneous
full batch costs **2,064 B more**, before allocator bookkeeping/fragmentation.
Prepared peak is `808 + (retained_before_prepare + batch_size) * 240`: old victim
nodes are not freed before commit. Snapshot arrays remain separate allocations.
The audit's `event_log_records` / `event_log_pending` fields now measure pointers,
not retained storage; `event_node` supplies the per-live-record cost.

The same 26 implementation probes compile at capacities 16, 128 and 1024 with
no diagnostics. Prepare's compiler frame is 128 B, finish/forget 32 B, append
64 B. No capacity-sized buffer moves onto the task stack. Individual compiler
frames are not a complete nested task-stack or linked-firmware RAM measurement.

## Tests and evidence

`test_events.c` uses the common requested-byte/OOM helper and a heap-owned copy
of the original array policy as a differential oracle. It checks 4000 mixed
batch/abort/store-failure/fabric-removal operations, full ceiling and full-batch
commit/abort, old-first priority ties, rejection of same-batch eviction, malformed
payload/fabric/count, `UINT64_MAX` exhaustion and boot skip. Constructor/load
faults, every allocation in a representative batch and the final allocation of
a capacity-sized batch leave records/numbers/bytes unchanged. Overwriting caller
input after prepare cannot change staged output. Commit/abort are tested with
the next allocation forced to fail; no allocation occurs. Stable peer nodes,
head/tail state and exact live-byte counts are checked after each operation.

Existing full-capacity Read/Subscribe tests overwrite/evict every log record
while a multi-chunk snapshot is active and require every original number in the
report. Their deferred snapshot OOM checks remain intact. The memory assertion
now takes its baseline after log population, so it continues to measure the
snapshot independently of the newly demand-allocated node log. No assertion or
capacity was reduced. ACL/boot/diagnostics/meter/OTA producer regressions remain
enabled in the full suite.

The [portable result record](memory03-results.json) captures source/evidence
hashes and measured values. Raw logs/objects live in ignored `build/memory03/`.

| Track | Actual result |
| --- | --- |
| Windows MinGW GCC 16.2 | Full build without compiler warnings; 87/90 CTests pass in sandbox. Three socket tests then pass 3/3 with normal local network access. Final event test passes separately. |
| Linux normal | Full build and final CTest 87/87; no compiler warnings. |
| Separate Linux ASan/UBSan/LSan | Full build and final CTest 87/87; leak detection enabled, no compiler warnings or sanitizer diagnostics. |
| Full two-instance metered three-phase scenario, Memcheck | Six grouped oracle checks pass; both nodes exit 0, zero live blocks/bytes, errors and suppressions. |
| Same two-instance scenario, separate sanitizers | Six grouped checks pass, both nodes exit 0 and stderr is empty. |
| Dedicated event OOM/policy/atomicity test, Memcheck | Zero live bytes/blocks, errors and suppressions. |
| Capacities 16 and 1024, ASan/UBSan/LSan | 7/7 focused CTests each: events, Read, Subscribe and ACL with their allocation variants. Full-capacity snapshots and the new OOM/differential test are included. |
| ESP32 layouts/frames | 26/26 implementation probes at each capacity 16/128/1024; no diagnostics. |
| Inventory/diff/source identity | 249 mapped files / 89 native definitions; `git diff --check` passes, tested Linux production/test source hashes match local files. |

The pair oracle retains full commissioning/attestation/CASE/subscription for
both nodes, independent application state and Identify/UTC anchors, B's services
and subscription surviving A's teardown/deletion, and both final fabric-removal
responses. It is a local integration test, not an official CSA verdict. Memcheck
and sanitizer binaries are separate. The final explicit store-failure case was
followed by rebuilding events and rerunning the entire normal/sanitizer suite,
both capacity variants, and the focused Memcheck test; production source did
not change after the pair runs.

The first explicit full-log store-failure fixture failed its assertion at
capacity 16: the existing 32-number reservation still had unused numbers, so no
store was due and both production and reference correctly returned OK. The
fixture now first reaches the durable boundary, then injects failure. The failed
`events16-final-ctest.log` and its error marker remain preserved; accepted runs
use separate `*-accepted-*` logs. This correction did not change production or
reduce assertions/capacity.

Reproduction uses the existing CMake configuration (with an existing Mbed TLS
checkout) and the newly registered test:

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls>
cmake --build build/normal -j 3
ctest --test-dir build/normal --output-on-failure
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 build/normal/cmake/tests/test_events
cmake -S . -B build/sanitize -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls> -DMATTER_SANITIZE=ON
cmake --build build/sanitize -j 3
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ctest --test-dir build/sanitize --output-on-failure
```

Additional configurations use `-DMATTER_EVENTS_CAPACITY=16` and `1024` with
sanitizers; focused regex: `^test_(events|im_read|im_subscribe|acl)(_alloc)?$`.
The pair retains the existing `--meter-services`, `--source-registers` and two
discriminator profile. Exact executed command arrays remain with ignored logs.

jscpd 4.0.5 scans all 66 C implementation files at 8 lines/60 tokens,
`--max-lines 10000 --max-size 1mb`: **8 clones / 80 duplicated lines before and
after in this run**. No event-log block is flagged. This is textual detection,
not a proof of no semantic duplication; headers/tests are outside that scan.

## Changed files

| File | Purpose |
| --- | --- |
| `main/apps/matter/model/matter_events.c` | Node ownership, priority planning, atomic allocation-free commit/abort and cleanup. |
| `main/apps/matter/model/matter_events.h` | Document demand/OOM/finish contract; remove stale 16-record copy wording. |
| `tools/matter/tests/test_events.c` | Dedicated byte, OOM, atomicity and policy differential regression. |
| `tools/matter/tests/test_im_multi_events.h` | Isolate snapshot-byte measurement from new log allocations. |
| `tools/matter/memory_audit.py` | Measure event-node size separately from owner/pointer fields. |
| `cmake/test-cases.json`, `doc/oss/test-map.json`, `doc/oss/test-map.md` | Register and describe the new test without dropping existing routes. |
| `doc/runtime.md`, `doc/oss/status.md`, Memory03 report/results | Update the actual ownership, evidence and limits. |

## Limits and next task

No physical ESP32 execution, firmware link, official CSA rerun or full OTA
provider campaign was performed. More small allocations introduce heap metadata,
fragmentation and bounded OOM exits; layout savings do not prove worst-case
embedded heap headroom. The whole maximum batch still fits the same admission
ceiling but needs both old and new nodes until publication. Payloads within live
nodes retain the existing 192-byte field; this stage removes unused log slots,
not that per-record protocol maximum.

Next: shared bounded value-snapshot storage for Read/Subscribe, preserving
stable references, byte limits and report/ACK drain; measure before migrating
Invoke/Write/client buffers. Lower transport tables remain a later step.
