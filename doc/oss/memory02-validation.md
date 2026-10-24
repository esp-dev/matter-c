# Memory02: live transaction nodes and demand-sized TX packets

Date: 2026-10-20. Baseline: `5355e02ce2eb0e52947c57a0411a1d290b7abf46`
([Memory01](memory01-validation.md), now committed). Work remains isolated in
the memory checkout. Public function signatures, packet formats, persistent
schemas, scheduler ownership and default admission limits are preserved.
These are local acceptance results, with no new official CSA verdict.

## Implementation and ownership

| Changed file | Purpose |
| --- | --- |
| `main/apps/matter/runtime/matter_dispatch.c` | Demand nodes/packets and shared allocation/release helpers; preserve admission and drain. |
| `main/apps/matter/transport/matter_unsecured_prepare.h` | Publish the existing fixed framing size for shared capacity calculation. |
| `main/apps/matter/transport/matter_unsecured_prepare.c` | Use that same framing constant in the encoder. |
| `tools/matter/tests/test_dispatch.c` | Adapt private fixtures, retain prior assertions and add byte/OOM/drain coverage. |
| `tools/matter/memory_audit.py` | Distinguish live metadata ceiling, packet pointer and maximum packet storage. |
| `doc/runtime.md` | Describe the actual ownership/OOM contract. |
| `doc/oss/status.md` | Record completed local acceptance and the next task. |
| `doc/oss/memory02-validation.md` | Explain implementation, measurements, checks and limits. |
| `doc/oss/memory02-results.json` | Preserve portable measured values and source/evidence hashes. |

`matter_dispatch.c` replaces the capacity-sized Transaction array with a bounded
intrusive list. Each admitted transaction owns one separately allocated stable
node. A live count enforces the existing `6 * subscriptions + 34` ceiling without
searching a table for unused slots. Removal unlinks a node without relocating
other nodes or callback bindings. Iteration saves the next pointer before a
transaction can delete itself. The per-fabric admission, replacement, protected
response tails, shared delivery burst and connection/session policies remain.

The node owns a separate packet allocation only when output is prepared. A
shared helper checks the unchanged 1232-byte bound, allocates plaintext length
plus the existing framing overhead (secure 24 B, unsecured 16 B), then invokes
the existing encoder/sealer. The unsecured encoder and dispatcher share the
framing constant. MRP retries reuse the immutable encoded bytes and counter.
No new packet preparation occurs while the node already owns a packet.

The common release helper requires both the MRP obligation to end and accepted
UDP to complete. Explicit `sending_message` and `control_transaction` guards
protect the bytes and node during drain, including ACK/cancel before completion
and R=0 BUSY. Handler/exchange cleanup finishes before unlink/free. A persistent
subscription retains its handler/node but releases the drained packet.

Node OOM on inbound admission closes the RX exchange; RX retains outstanding
ACK/drain ownership. Optional outbound work reports failure before acquiring an
exchange or reservation. Packet OOM closes affected work before encoding or
consuming a nonce. Later framing/MRP failure releases unborrowed storage through
the same closing path. An already executed application operation is not rolled
back solely because a response cannot be allocated, consistent with existing
response construction/transport failure semantics.

## ESP32 measurements

Xtensa ESP32 GCC 13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`, transport
56/events 128. All 26 implementation probes compile without diagnostics. This
measures compiler layouts/requested allocation sizes, not allocator overhead,
fragmentation, linked firmware memory or device heap high-water.

| Dispatcher-owned storage | Before (B) | After (B) |
| --- | ---: | ---: |
| Dispatcher base | 8,152 | 8,160 |
| Transaction metadata including packet pointer/links | 1,504 with embedded 1,232-byte packet | 280 plus actual TX size |
| Idle transaction storage | 78,208 (52 entries) | 0 |
| Idle dispatcher plus transaction storage | 86,360 | 8,160 |
| One live node, no pending packet | 86,360 reserved | 8,440 |
| One live node with 32-byte packet | 86,360 reserved | 8,472 |
| All 52 nodes with maximum 1,232-byte packets | 86,360 | 86,784 |

Idle reservation decreases by **78,200 B**. Full simultaneous maximum-sized TX
costs **424 B more**, before allocator metadata/alignment/fragmentation. The new
ceiling of 14,560 B for metadata and 64,064 B for packets is demand, not startup
reservation. The changed probe's `default_transactions` field now describes
the live metadata ceiling; `default_transactions_max_tx` includes maximum TX.
`transaction_packet` remains the 1232-byte maximum; its pointer is a separate
metric. Connection tables, lower RX/MRP/ACK tables and four dispatcher scratch
buffers remain unchanged. The process compiler frame is 272 B; packet prepare
is 80 B. Individual frames are not a complete nested task-stack proof.

## Regression coverage

`test_dispatch.c` reuses the shared requested-byte/OOM accounting helper.
Fixtures construct list nodes instead of relying on vacant production slots.
Existing assertions remain for partition admission, 52 real RX/MRP records,
subscription fabric/node replacement, timed operations, rotation/removal,
fail-safe response retirement, outbound Invoke/BDX, rediscovery, PASE/CASE
failure StatusReport/retries and UDP/ACK/stop drain.

New checks cover idle bytes, node bytes through the full ceiling, rejection
without allocation above the ceiling, head/middle/tail unlink with stable peer
addresses, inbound/outbound node OOM, secure/unsecured TX and BUSY OOM, unchanged
counters on pre-encoding OOM, exact encoded size and MTU boundary, malformed
encoding cleanup, and ACK/cancel/closing before actual UDP completion. A mock
UDP backend holds the borrowed datagram while another node is allocated/freed.

## Validation

The portable [result record](memory02-results.json) stores source/evidence hashes
and measurements. Raw logs and compiler objects remain in ignored
`build/memory02/`; no credentials or device state are part of the commit.

| Track | Actual result |
| --- | --- |
| Windows MinGW GCC 16.2 full build / CTest | Build completes without compiler warnings; 86/89 pass inside the sandbox. The three socket tests then pass 3/3 with normal network access. Final additions to `test_dispatch` also pass separately. |
| Linux GCC normal | Complete build and final CTest 86/86, without compiler warnings. |
| Linux ASan/UBSan/LSan | Separate complete build and final CTest 86/86, without compiler warnings or sanitizer diagnostics. |
| Two-instance full metered three-phase scenario, Memcheck | All six grouped oracle checks pass. Both nodes exit 0; 49,227 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Same scenario, separate ASan/UBSan/LSan | All six checks pass; both nodes exit 0 and stderr is empty. Leak detection is enabled. |
| Final dispatcher OOM/drain scenarios, Memcheck | 2,369 allocs/frees; zero live bytes/blocks, errors and suppressions. |
| Transport 128, ASan/UBSan/LSan | Focused dispatcher test 1/1, including budget 8 (82 transactions), full 82-node allocation ceiling and existing replacement/fabric isolation checks. Budget 10000 still fails the unchanged transport guard. |
| ESP32 layout/stack probes | 26/26 compile with `-Werror`; no diagnostics. |
| Diff/source identity | `git diff --check` passes; tested Linux production/test source hashes match the local files. |

The pair oracle includes two complete commissioning/attestation/CASE/subscription
lifetimes, independent application state and Identify/UTC anchors, B's services
and subscription surviving A's teardown/deletion, and both last-fabric response
drains. Sanitizers are not run under Valgrind. OOM assertions track the
dispatcher's requested payload bytes; other linked subsystems and allocator
bookkeeping are outside that accounting and covered separately by Memcheck/LSan.

Reproduction uses the existing CMake targets:

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls>
cmake --build build/normal -j 3
ctest --test-dir build/normal --output-on-failure
cmake -S . -B build/sanitize -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<mbedtls> -DMATTER_SANITIZE=ON
cmake --build build/sanitize -j 3
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ctest --test-dir build/sanitize --output-on-failure
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 build/normal/cmake/tests/test_dispatch
```

The pair invocation and independent `chip_tool_three_phase.py` oracle use the
existing `--meter-services`, `--source-registers` and two-discriminator profile;
exact executed command arrays remain with the ignored evidence logs.

jscpd 4.0.5 at 8 lines/60 tokens, expanded to `--max-lines 10000 --max-size 1mb`,
includes all **66 C files**, including dispatcher/Root which the historical
default 1000-line cutoff excluded. Against the committed baseline, it reports
**8 to 7 clones, 80 to 71 duplicated lines (0.51% to 0.45%)**. The historical
64-file profile remains separate (7 clones in both versions). This measures
textual blocks, not semantic duplication or linked flash savings.

## Limits and next task

No ESP32 firmware link, physical-device execution, official CSA rerun, full OTA
provider campaign or allocator fragmentation endurance test was performed in
this stage. Peak payload capacity is preserved, but many small allocations add
allocator cost and new bounded OOM exits. Host acceptance does not prove an
ESP32 heap can sustain the full simultaneous ceiling.

Next: migrate the event log's fixed retention/staging arrays while preserving
event numbering, eviction priorities, atomic publication and immutable in-flight
Read/Subscribe snapshots. Keep transport tables until their independent
handle/ACK/drain lifetime is covered.
