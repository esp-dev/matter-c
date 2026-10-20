# Memory05: demand allocation for Invoke, Write and client messages

Date: 2026-10-20. Baseline: `36298d6` (Memory04). Work remains in the
isolated memory checkout. Public signatures, limits, TLV normalization/wire
encoding, per-instance ownership and application-owned scheduling are preserved.
This is local acceptance, with no device or official CSA result implied.

## Implementation and ownership

`matter_im_buffer_internal.h` shares checked growth and secure erase/free.
Growth allocates before replacing the old pointer; OOM leaves the old bytes and
capacity untouched. No shared global pool or value-sized stack buffer is added.
Each owner has pointers/capacities instead of embedded request/response arrays.

Invoke and Write allocate the accepted RX length, keeping the 1024-byte ceiling.
An allocation failure returns LIMIT_REACHED before changing queue/opcode/time.
Normalized arguments/value scratch uses RX length (minimum two bytes for missing
Invoke fields); removing a root context tag and canonicalizing widths cannot
grow the encoded value. Existing schema/depth/token/tag budgets still apply.

Invoke reserves status space before effects and, for response commands, the
provider's declared 2..1024-byte body capacity plus bounded reply storage. The
64-byte envelope allowance covers full-width endpoint/cluster/command/reference
and cluster status; configured output capacity remains the upper bound. Existing
maximum-status and exact declared-body capacity checks still run before invoke
or async start. Polling, final encoding, sending and confirming allocate nothing.
Consumed RX/arguments are erased/freed after start; body storage survives async
polling and is released once copied into the reply. Async callbacks still cannot
retain arguments/writer pointers and own independent backend input/work.

Write counts at most four IBs and allocates exactly that many paired descriptors
and results, instead of four embedded slots. All shapes are checked before
callbacks. Reply and one normalization buffer are reserved before the first IB
mutation; all following IBs reuse them without allocation. A 48-byte allowance
per status plus eight envelope bytes covers full-width paths/statuses; the old
256-byte implementation ceiling and configured capacity remain respected.
The existing semantics are per-IB atomicity, not an all-or-nothing multi-IB
transaction: successful earlier writes remain when a provider rejects a later
one. Handler OOM cannot introduce an allocation failure after the first effect.
ACL self-revocation grant caching, current-version checks and 64-message chunk
ceiling are unchanged. Request/scratch/items release after encoding/suppression.

Invoke/Write keep replies through sent until confirm requires MRP ACK AND
transport drain. A queued timed continuation/next chunk has separate RX storage
and cannot overwrite that reply. Cancellation/timeout retains reply allocations
until delete following owner drain. Confirm frees only reply storage, leaving
queued RX intact. Existing timeout and received-at window semantics are retained.

Client request storage is bounded by normalized input plus a conservative
48-byte envelope, capped at 1024. It releases on sent, after the caller copies
output to the MRP-owned immutable packet. On receive, response-body storage is
bounded by the selected fields' wire length; a required StatusResponse reserves
eight bytes before publishing completion. OOM keeps the client waiting without
publishing a result. Body references remain stable until delete; a status-only
result needs no body allocation. The dispatcher still retains its independent
MRP packet through ACK/drain, including a final client StatusResponse.

## Requested-byte measurements

Xtensa ESP32 GCC 13.2.0; 26 real implementation probes compile with C99,
`-Os -Wall -Wextra -Werror -fstack-usage`, without diagnostics.

| Owner structure | Baseline (B) | New (B) | Reduction (B) |
| --- | ---: | ---: | ---: |
| Invoke before RX | 5600 | 1536 | 4064 |
| Write before RX | 4288 | 1800 | 2488 |
| Client owner only | 2968 | 936 | 2032 |

The combined owner reduction is 8584 B. A client constructor also allocates its
request; the empty/waiting owner comparison alone is not its initial live heap.
For the tested five-byte fields, it requests 53 more bytes, then releases them
on sent. The tested client result uses six bytes (wire-length bound for five
normalized bytes), plus eight bytes only while its StatusResponse is pending.

The tested small Invoke retains 80 reply bytes while awaiting delivery, with
16 provider-body bytes additionally retained only during async execution. A
four-IB Write retains 200 reply bytes after processing, or a single-IB reply
reserves at most 56. Write items cost 56 B each on ESP32 and exist only while
processing. Incoming continuations add their own accepted RX length.

These are requested payload bytes and compiler layouts; allocator metadata,
alignment and fragmentation are excluded. A conservative Invoke bound with all
four buffers at 1024 is 5632 B, 32 B above the old owner; growth from its initial
64-byte reply can temporarily add another 64 B before freeing the old buffer.
Actual admissible body size is also constrained by its envelope. Write's bound
is 1800 + 1024 RX + 1024 scratch + 224 items + 200 reply = 4272 B; during growth
the old eight-byte reply adds eight more. Client has no simultaneous retained
request/result: a conservative 1024-byte result plus eight-byte reply and owner
is 1968 B. More short-lived allocations increase allocator churn; these are
not ESP32 heap/RSS high-water or fragmentation/endurance measurements.

No message-sized task-stack storage was introduced. Compiler frames remain 48 B
for Invoke process and 128 B for Write process. Client receive grows from 352 to
384 B (+32 B); nested codec/provider frames and real application task budgets
remain separate. This stack cost is a measured tradeoff, not a device validation.

## Regression coverage

`test_im_request_memory` tracks requested live bytes and injects OOM at all six
Invoke allocations, six Write allocations and four client allocations. Every
failed admission leaves the test model unchanged; failed RX can be retried.
It forces the next allocation to fail starting in the first model mutation,
then requires all four Write IBs to complete and Invoke finalization to succeed.
Async poll/cancel/timeout/delete retain/free the correct buffers without new
allocation. Client OOM cannot publish results; retry succeeds, result references
survive StatusResponse submission, and sent/confirm allocate nothing. A timed
Write continuation arrives before prior ACK/drain, including RX OOM/retry; prior
reply bytes remain unchanged and mutation waits until confirm.

Unchanged existing tests cover literal wire responses, malformed input/provider
output, authorization, fabric identity, version errors, self-revoking ACL lists,
capacity boundaries, suppression, timed/chunked writes, async Invoke completion,
two-instance isolation, MRP retry/ACK/UDP ordering and outgoing final-status drain.
Inventory: 251 files, 91 native definitions, 59 core sources, 75 public headers.

## Validation record

The [portable result record](memory05-results.json) records executed results,
source hashes and evidence hashes. Raw logs/objects remain ignored under
`build/memory05/`. After testing, one header comment was corrected from "one heap
allocation" to "heap-owned state"; the record preserves both hashes and verifies
identical C tokens after removing comments. Implementation/test bytes match the
laboratory export and ESP32 probes.

| Track | Actual result |
| --- | --- |
| Windows MinGW GCC 16.2 | Full build without compiler warnings; 89/92 CTests pass in sandbox. The same three socket tests pass 3/3 with normal local network access. |
| Linux normal | Full build and CTest 89/89, without compiler warnings. |
| Separate Linux ASan/UBSan/LSan | Full build and CTest 89/89, leak detection enabled, no compiler warnings or sanitizer diagnostics. |
| Two-instance metered three-phase scenario under Memcheck | All six grouped checks pass; exit 0, 49,764 allocs/frees; zero live bytes/blocks, errors and suppressions. |
| Same two-instance scenario under separate sanitizers | Six grouped checks pass; exit 0 and empty stderr. |
| Dedicated allocation/lifetime test under Memcheck | 178 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| ESP32 compile-only measurement | All 26 real implementation probes pass with warnings treated as errors. |
| Test/source/header inventory | 251 mapped files, 91 native definitions, 59 core sources, 75 public headers. |

Both two-instance runs cover commissioning/attestation/CASE, independent model
and Identify/UTC state, meter services/subscription surviving deletion of the
other instance, and final fabric-removal replies. The normal host runs under
Memcheck; sanitizers run in a separate build without Valgrind. Processes exit
normally through the scenario cleanup. No assertion, old test or configured
ceiling was reduced to obtain a pass.

Executed build/test commands (dependency paths abbreviated):

```text
cmake -S . -B build/memory01/windows
cmake --build build/memory01/windows -j 4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$" --output-on-failure
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory05/esp32
cmake -S <source> -B <build> -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<existing-dependency> -DMATTER_SANITIZE=OFF
cmake --build <build> -j 3
ctest --test-dir <build> --output-on-failure
# Same Linux configure/build/CTest with MATTER_SANITIZE=ON in a separate build.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <normal-build>/cmake/tests/test_im_request_memory
```

For each host variant, the existing `runtime-pair-host 2 ... --meter-services`
is driven by `chip_tool_three_phase.py --source-registers --meter-services`.
The normal host additionally uses the Memcheck options above. Sanitizer runs
set `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

Duplication scan: jscpd 4.0.5, 66 implementation C files, minimum eight lines /
60 tokens, max 10000 lines / 1 MB, identical sorted file order and options.
Seven clones remain; duplicated lines change 69 -> 70 (0.44% in both runs).
The additional allocation check extends an existing RX clone. Shared private
buffer operations avoid duplicating allocation/erase ownership; the scan
excludes headers/tests and does not measure linked flash savings.

## Changed files and purpose

| Files | Purpose |
| --- | --- |
| `matter_im_invoke.c/.h` | Demand request/argument/body/reply ownership and documented allocation failure. |
| `matter_im_write.c/.h` | Demand request/scratch/IB/result/reply memory, preflight before model effects. |
| `matter_im_client.c/.h` | Demand request/result/status buffers and MRP-copy lifetime contract. |
| `matter_im_buffer_internal.h` | Shared atomic growth and erase/free implementation. |
| `test_im_request_memory.c`, CMake inventories, test-map | Fault injection, byte/lifetime assertions and registered regression. |
| `memory_audit.py` | ESP32 owner/item measurements. |
| `doc/runtime.md`, status and Memory05 report/results | Ownership, measured costs, evidence and limitations. |

Not verified: linked ESP32 firmware, physical device behavior, real allocator
fragmentation/latency over time, full OTA provider campaign or official CSA tests.
Next task: inspect fixed parser/tag/path/result workspaces and their lifetime,
measuring the tradeoff before changing any protocol/resource ceiling.
