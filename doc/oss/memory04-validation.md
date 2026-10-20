# Memory04: shared demand-sized Read/Subscribe value snapshots

Date: 2026-10-20. Baseline: `f757aa9` ([Memory03](memory03-validation.md)).
Work remains in the isolated memory checkout. Public signatures, TLV encoding,
value/aggregate/result budgets, authorization/version policy and scheduler
ownership are unchanged. No official CSA result is changed.

## Implementation and lifetime

The private `matter_im_snapshot_internal.h` owns a per-handler linked store.
Read and Subscribe use the same copy, normalization, validation, allocation and
clear operations. Each complex value has one allocation: link plus its exact
encoded length. Collection never reallocates or relocates earlier copies, so
`items[].value.data` and list offsets stay valid across provider calls, yielded
capture, later allocations, output planning and multipart reports. Stores remain
independent between handlers/instances. Scalars still stay in the value metadata.

Anonymous UTF8/BYTES length calculation reserves control/length bytes, then the
existing writer performs encoding/UTF8 checks. STRUCTURE/ARRAY use their original
encoded length. All values retain the existing validation budgets (depth4,
1024 tokens, 4096 comparisons, 48 active tags), anonymous root/type checks,
4096-byte encoded maximum and 16384-byte aggregate payload ceiling. Result
admission stays at 512. The original caller preflights retain Read/Subscribe's
different error precedence. A failed copy frees its unlinked node, publishes no
pointer, and leaves earlier nodes, total bytes and the supplied value unchanged.

Read releases copies during delete, as before; completion/cancel/timeout alone
does not free them. Subscribe frees after the final report chunk has both IM
Success and MRP confirmation, using the same state gate as event snapshots.
Neither ACK alone, status before MRP completion, nor an intermediate chunk
releases values. A skipped unchanged update has no TX and releases immediately.
Starting a new capture also clears any drained/skipped previous store. Cleared
item/current data references are nulled. Subscribe cancellation/timeout retains
values until delete after caller-owned transport drain. No current TX buffer or
MRP packet ownership changes; they remain separate immutable allocations.

## ESP32 requested-byte measurements

Xtensa ESP32 GCC 13.2.0, C99 `-Os -Wall -Wextra -Werror -fstack-usage`.
All 26 implementation probes compile without diagnostics. Read remains 2136 B,
Subscribe 2736 B; the store metadata remains 8 B inside those owners. A node link
adds 4 B per copied value. The old arena reserved 16384 B on its first complex
value and stayed until delete; initial empty/scalar-only handlers already
allocated zero arena bytes and still do.

| Snapshot-owned requested storage | Before (B) | After (B) |
| --- | ---: | ---: |
| No captured complex value | 0 | 0 |
| One empty text/byte string (2 encoded bytes) | 16384 | 6 |
| One 8-byte text/byte string (10 encoded bytes) | 16384 | 14 |
| Two 8-byte STRUCTURE values | 16384 | 24 |
| Four maximum 4096-byte encoded values | 16384 | 16400 |
| 512 values x 32 encoded bytes (full aggregate ceiling) | 16384 | 18432 |
| Subscribe idle after a successful report containing complex data | 16384 retained | 0 |

The small-string example saves **16370 B** while its snapshot is live. Full
payload at 512 results costs **2048 B more** in links. These exclude allocator
metadata/alignment/fragmentation, result tables, RX/TX, event snapshots and other
handler state. More per-value allocations and freeing between reports increase
allocator churn; cumulative bytes allocated during a run need not fall. These
are compiler layouts and tested requested bytes, not RSS, linked firmware RAM,
an ESP32 heap high-water measurement or a fragmentation endurance result.

No value-sized task-stack buffer is introduced. Validation/writer/reader/tag
scratch stays in the heap-owned handler. Compiler frame reports remain under
ignored `build/memory04/esp32/`; individual frames do not prove nested task-stack
headroom.

## Regression coverage

`test_im_snapshots` checks exact encoded storage for empty/1/8/255/256/4093-byte
strings, minimal length widths, immutable copies after provider overwrite,
4096-byte value and 16384-byte aggregate boundaries, and 512 stable references.
It injects OOM at each of nine successive allocation positions and retries;
earlier pointers/content/bytes remain unchanged. Malformed, wrong-root,
duplicate-tag, depth and UTF8 failures release unlinked allocations. Clearing
is tested with the next allocation forced to fail and allocates nothing.

Read adds a requested-allocation bound for a short value and proves storage
survives final delivery confirmation until deletion. Subscribe adds live count/
byte checks with two values across both ACK/StatusResponse orderings, intermediate
and final chunks, release before SubscribeResponse, recapture, cancellation and
timeout while in flight. The existing wire oracles continue to poison shared
provider scratch, reassemble REPLACE/ADD lists, check the nine-value aggregate
limit, filter versions, revoke access between chunks, and preserve snapshots
through event-log eviction. No existing assertion, capacity or wire oracle is
reduced. Registration now covers 250 mapped files / 90 native definitions.

## Validation

The [portable result record](memory04-results.json) holds measured values and
source/evidence hashes. Raw logs/objects stay in ignored `build/memory04/`.

| Track | Actual result |
| --- | --- |
| Windows MinGW GCC 16.2 | Full build without compiler warnings; 88/91 CTests pass inside sandbox. The same three socket tests then pass 3/3 with normal local network access. |
| Linux normal | Complete build and CTest 88/88; no compiler warnings. |
| Separate Linux ASan/UBSan/LSan | Complete build and CTest 88/88; leak detection enabled, no compiler warnings or sanitizer diagnostics. |
| Full two-instance metered three-phase scenario, Memcheck | All six grouped checks pass; both nodes exit 0, 49,715 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Same two-instance scenario, separate sanitizers | All six checks pass; both nodes exit 0 and stderr is empty. |
| Dedicated snapshot boundary/OOM/stability test, Memcheck | 1,257 allocs/frees; zero live bytes/blocks, errors and suppressions. |
| Event capacities 16 and 1024, ASan/UBSan/LSan | 8/8 focused CTests each: events, value snapshots, Read, Subscribe, ACL and allocation variants. |
| ESP32 layout/stack probes | 26/26 compile with `-Werror`, no diagnostics; unchanged owner sizes and a 4-byte node header. |
| Inventory/diff/source identity | 250 mapped files / 90 native definitions, `git diff --check` passes; tested production/test/header source hashes match local files. |

The pair retains commissioning/attestation/CASE/subscription for both nodes,
independent application state and Identify/UTC anchors, B's services/subscription
surviving A's teardown/deletion, and both last-fabric responses. This remains
local acceptance rather than an official CSA verdict. The sanitizer binary is
not run under Valgrind.

Reproduction uses the existing CMake targets and a local Mbed TLS checkout:

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls>
cmake --build build/normal -j 3
ctest --test-dir build/normal --output-on-failure
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 build/normal/cmake/tests/test_im_snapshots
cmake -S . -B build/sanitize -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls> -DMATTER_SANITIZE=ON
cmake --build build/sanitize -j 3
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ctest --test-dir build/sanitize --output-on-failure
```

Additional sanitizer configurations set `-DMATTER_EVENTS_CAPACITY=16` / `1024`,
then use `^test_(events|im_snapshots|im_read|im_subscribe|acl)(_alloc)?$`. The pair
uses the existing `--meter-services`, `--source-registers` and two-discriminator
profile. Exact command arrays remain with the ignored logs.

jscpd 4.0.5, 8 lines/60 tokens, `--max-lines 10000 --max-size 1mb`, scans all
66 implementation C files: **8 -> 7 clones, 78 -> 69 duplicated lines** in this
comparison. The new shared private header is outside that C-only statistic.
This is textual duplication evidence, not linked flash-size savings.

## Changed files

| File | Purpose |
| --- | --- |
| `model/matter_im_snapshot_internal.h` under `main/apps/matter` | Shared private stable store and copy/validation/clear operations. |
| `model/matter_im_read.c`, `model/matter_im_subscribe.c` | Use the common store; preserve Read ownership and gate Subscribe cleanup. |
| `model/matter_im_read.h`, `model/matter_im_subscribe.h` | Describe actual demand/lifetime and unchanged limits. |
| `tools/matter/tests/test_im_snapshots.c` | Byte/boundary/stability/OOM helper tests. |
| `tools/matter/tests/test_im_complex.h`, `test_subscribe_complex.h` | Integrate memory assertions into existing wire/lifecycle tests. |
| `tools/matter/memory_audit.py` | Measure store/node metadata. |
| `cmake/sources.json`, `cmake/test-cases.json`, `doc/oss/test-map.*` | Register the private header and new test without dropping routes. |
| `doc/runtime.md`, `doc/oss/status.md`, Memory04 report/results | Ownership, measurements, evidence and remaining work. |

## Limits and next task

No physical ESP32 execution, firmware link, official CSA rerun or full OTA
provider campaign was performed. Per-value metadata and allocator overhead can
make a fully saturated report more expensive than the old arena. The encoded
payload budgets were preserved, not reduced to conceal that peak. Embedded heap
fragmentation and allocator latency still need device/endurance measurement.

Next: inspect Invoke/Write/client request, output and result storage for the next
demand-allocation step, retaining per-operation limits, atomic model updates and
transport/ACK drain. Lower transport tables remain a later stage.
