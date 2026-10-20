# Memory06: transient IM workspaces and demand CASE resumption cache

Date: 2026-10-20. Baseline: `e4b089f` (Memory05). Implementation stays in
the isolated memory checkout. Public C signatures, resource ceilings, wire
encoding, per-instance ownership and application-owned scheduling are unchanged.

## Implementation

Read, Subscribe, Invoke, Write and client keep their parser/validation/tag state
in a separate heap workspace. No parser array moves to a task stack or a shared
global object. Workspaces retain their existing 48/64 tag limits and TLV
depth/byte/token/comparison budgets. The small bounded arrays inside an active
workspace are deliberate: allocating every individual tag/field would add churn
without improving idle memory. Workspaces are securely erased before free.

Incoming IM requests reserve parser state together with their RX copy. Either
allocation failing returns LIMIT_REACHED without publishing input/queue/time;
new temporary input/workspace is freed and the previous reply is untouched.
Read/Subscribe free parser state after each process call. Yielded enumeration,
capture or a drained continuation reacquires it before work; OOM produces the
existing eight-byte ResourceExhausted StatusResponse using a shared checked
encoding with no writer allocation. Idle polling, confirm, sent and deadlines
need no parser. Request selectors use two validated passes and allocate exactly
the entry count: Read keeps nine combined selectors, Subscribe keeps up to 32
attribute-only selectors and the existing mixed/event limit. Selectors survive
yielded expansion, then release after copying/expansion. The request count remains
available for existing Subscribe change semantics.

Subscribe's nine-entry chunk plan also lives in the temporary workspace. Only
the encoded output survives the call; snapshots/results/list cursors have
independent stable ownership. Existing result tables already grow on demand and
retain their 512-entry ceiling. IM Success, MRP ACK and transport drain still
gate snapshot release. A queued status parser may exist before ACK, while the
previous output and snapshots remain independent. Per-chunk parser OOM can end
a report, but cannot free a borrowed MRP packet or bypass owner drain.

Invoke retains its workspace through asynchronous execution, including its
response writer. It is reserved before start and no handler allocation occurs
during poll/final encoding after effects. Write retains queued parser state
until processing, separately from an earlier reply awaiting ACK/drain. Its
allocations still precede the first model write. Client validation/tag state
exists only in construction/receive; failure unwinds construction or leaves
receive waiting without publishing a result. Client result bodies and the
dispatcher MRP packet remain independent of validation state.

Fabric host's resumption cache now uses live MRU nodes, with the same maximum
three peers per fabric and five fabric slots. Find does not refresh recency;
authenticated saves do. Existing-peer updates and full per-fabric oldest
replacement reuse nodes without allocation. A new-node OOM preserves all old
entries; CASE's existing optional-save failure policy still allows authenticated
session handoff without caching. ID collision, identity/revision checks and
cross-fabric isolation are retained. Credential/IPK changes and removal erase
only affected nodes, while final reset/delete erases all. Adding a new fabric
does not invalidate another fabric's cached session. Durable schemas are unchanged.

## ESP32 layouts, active costs and stack

Xtensa ESP32 GCC 13.2.0, 26 implementation probes, C99
`-Os -Wall -Wextra -Werror -fstack-usage`, without diagnostics.

| Owner | Baseline (B) | After (B) | Temporary parser (B) |
| --- | ---: | ---: | ---: |
| Read | 2136 | 280 | 1712 |
| Subscribe | 2736 | 328 | 1912 |
| Invoke | 1536 | 224 | 1328 |
| Write | 1800 | 232 | 1584 |
| Client | 936 | 56 | 884 |
| Fabric host, before any cached peer | 4152 | 2600 | not applicable |

The five IM owners save 8024 B together; the empty Fabric adapter saves 1552 B,
for 9576 B combined. These exclude request/reply/result storage, allocator
metadata/alignment/fragmentation and backend cryptography. Client construction
also owns its encoded request. Each three established idle subscriptions save
7224 B of owner storage. A selector costs 16 B on ESP32 and exists only until
expansion/copying; scalar/path/result state needed across calls stays in owners
or separately allocated result tables.

With all selector limits populated, owner + parser + raw selectors totals
2136 B for Read (unchanged maximum) and 2752 B for Subscribe (+16 B). Invoke
owner + parser is 1552 B (+16 B), Write 1816 B (+16 B), client 940 B (+4 B).
These are active workspace bounds before adding their existing operation
buffers. More short-lived allocations increase churn and expose bounded OOM
paths; a smaller idle owner does not imply a smaller worst-case operation.

A resumption node costs 112 B, versus 104 B per old inline entry. Empty host
2600 B, one cached peer 2712 B, full 15-peer host 4280 B versus 4152 B before
(128 B more at saturation). There is no empty cache allocation. Application
libraries may add allocator metadata; the default ceilings remain unchanged.

| ESP32 individual frame | Before (B) | After (B) |
| --- | ---: | ---: |
| Read process | 160 | 160 |
| Subscribe process | 208 | 208 |
| Invoke process | 48 | 48 |
| Write process | 128 | 112 |
| Client receive | 384 | 384 |

A single exit cleanup path avoids a new wrapper frame around parser/provider
calls. No message-sized local buffer is introduced. These individual compiler
frames do not prove complete nested application-task stack headroom; linked
ESP32 firmware and physical stack high-water were not measured.

## Larger Fabric/PASE/CASE allocations before and after commissioning

The image has not yet been made sparse. It remains 15552 B for the entire image
lifetime, with zero or five fabrics. Its 15536-byte data contains a 10104-byte
view (five 1936-byte records = 9680 B, plus view metadata/pending root), 1648 B ACL,
688 B group-key metadata, 960 B group-key bytes and a 1936-byte previous record,
plus keys/journal metadata. Fabric host also still retains a 1936-byte work
record, making it another concrete idle-memory candidate after this cache change.

The persistence path is a higher-priority remaining peak than small parser
arrays. `before()` retains a 15536-byte rollback image while `after()` calls
`persist.publish()`. Store `capture()` allocates 16160 B of complete DTO staging,
and `save()` then allocates the existing 32768-byte TLV buffer. Together with the
15552-byte live image, these four payload allocations coexist at **80016 B**,
before encoder state, adapters and cryptographic allocation. This is a
source/layout-based subtotal for that path, not a measured device heap peak.
Memory01 already releases backup/staging/TLV buffers after the operation; the
remaining issue is their simultaneous size and the always-live dense image.

| Lifetime | PASE/CASE-related payload |
| --- | --- |
| Idle runtime, no handshake | No PASE/CASE attempt object; image and Fabric host remain. Factory commissioning configuration remains available for reopening the window. |
| One PASE attempt | 6384 B owner, including four 1024-byte message/transcript arrays; SPAKE and crypto backend allocations are additional. |
| One CASE attempt | 14112 B owner, including 6000 B packet/scratch arrays, 3600 B transcript and 1312 B fabric snapshot. Backend allocations are additional. |
| Handoff/final packet in flight | Secure session may coexist with handshake until its transaction drains; no early deletion is introduced. |
| Established session after handshake drain | Handshake object is deleted. A live secure-session owner is 1552 B, including its receive plaintext buffer, plus separate counter/reception/channel/connection state. CASE cache now adds only live peer nodes. |

Dispatcher `handoff()` transfers keys; `dispose()` calls PASE/CASE delete only
after existing MRP/RX/transport ownership gates. PASE confirmation and CASE's
existing authenticated-traffic/final-packet policy remain different and are
preserved. CASE scratch does not stay in every established session. Basic
commissioning verifier/configuration and operational credentials have different
lifetimes and are not discarded merely because a handshake completed.

Next priority: reduce Fabric publication's 80016-byte coexistence subtotal and
move Fabric adapter work to operation ownership, preserving durable schema,
atomic rejection, fail-safe rollback and returned views. The dense image is also
the public fixed-shape DTO/view; replacing arrays with pointers directly would
change those contracts. Separate sparse operational ownership from serialization
staging and define allocation-failure behavior of borrowed views first. Then
phase-sized CASE/PASE buffers can reduce the peak of the two admitted handshake
slots. No such broader image/handshake redesign is claimed in this batch.

## Regression and evidence

`test_im_request_memory` injects all seven Invoke, seven Write and six client
allocation failures. Failed receive can retry; no failed admission mutates the
model; four Write IBs and async Invoke finalize without allocations after effects.
Read/Subscribe test both RX allocation failures, exact selector admission,
yielded parser reacquisition OOM, all seven initial Subscribe selector/expansion
allocation positions and 64 idle polls with the next allocation forced to fail.
Existing snapshot/ACK/status and cancellation gates remain asserted. Byte/count
oracles account explicitly for a queued parser being released, rather than
weakening snapshot assertions. Original snapshot/result/plan OOM positions are
adjusted for the new exact selector allocation, retaining those fault cases.

`test_case_alloc` registers the existing CASE suite with allocator replacement,
including cache OOM before eviction, allocation-free same-peer/full-cache reuse,
new-fabric cache preservation, credential/IPK invalidation, failed publication,
revision checks, bounded eviction, ID collision and two-fabric isolation.
Original wire, schema, access, version, timed/list/chunk, resumption, handshake
and runtime/dispatcher tests remain in the full suite.

Executed results are recorded in [portable JSON](memory06-results.json), including
tested source and raw-evidence SHA256. Logs and objects remain ignored in
`build/memory06/`. Implementation, headers and test bytes match the final
laboratory export; the ESP32 implementation hashes match those same sources.

| Track | Actual final result |
| --- | --- |
| Windows full build/CTest | No compiler warnings; 90/93 tests pass in sandbox. The same three socket tests then pass 3/3 with normal network access. |
| Linux normal | Full build and CTest 90/90, no compiler warnings. |
| Separate Linux ASan/UBSan/LSan | Full build and CTest 90/90, leak detection enabled, no compiler warnings or sanitizer diagnostics. |
| Full two-instance metered scenario under Memcheck | Six grouped checks pass, exit 0; 50,170 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Same full scenario under separate sanitizers | Six grouped checks pass, exit 0, empty stderr. |
| Request OOM/lifetimes under Memcheck | 260 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Full CASE/cache/OOM allocation suite under Memcheck | 1,896,281 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Full Read allocation suite under Memcheck | 10,150 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Full Subscribe allocation suite under Memcheck | 26,086 allocs/frees, zero live bytes/blocks, errors and suppressions. |
| Inventory | 251 mapped files, 92 native definitions, 59 core sources, 75 public headers. |

Both full-host variants commission/attest two nodes, establish CASE/subscriptions,
verify independent model/Identify/UTC state, retain B's services/subscription after
deleting A, and drain both final fabric-removal replies. Initial focused failures
were stale allocation-position/live-count oracles after moving parser/selector
storage; those checks now explicitly retain the snapshot guarantees and include
the additional allocation sites. Earlier logs remain in the ignored evidence
folder. The final runs use unchanged protocol/resource ceilings.

Duplication scan: offline jscpd 4.0.5, all 66 sorted implementation C files,
minimum eight lines / 60 tokens, maximum 10000 lines / 1 MB. Clone count remains
seven; duplicated lines change 70 -> 69 (0.44% -> 0.43%). Private shared cleanup
and emergency-status encoding avoid duplicating ownership operations. Headers
and tests are outside this scan; textual sharing is not linked flash evidence.

Executed commands (dependency/compiler paths abbreviated):

```text
cmake -S . -B build/memory01/windows
cmake --build build/memory01/windows -j 4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$" --output-on-failure
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory06/esp32
cmake -S <source> -B <build> -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<existing-dependency> -DMATTER_SANITIZE=OFF
cmake --build <build> -j 3
ctest --test-dir <build> --output-on-failure
# Separate Linux build repeats configure/build/CTest with MATTER_SANITIZE=ON.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <normal-build>/cmake/tests/<target>
```

Dedicated Memcheck targets are `test_im_request_memory`, `test_case_alloc`,
`test_im_read_alloc` and `test_im_subscribe_alloc`. The full two-instance host
uses the same Memcheck options plus a log file, driven by the existing
`chip_tool_three_phase.py --source-registers --meter-services`. A separate
sanitizer build runs the same scenario with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, without Valgrind.

## Files and scope

| Files | Reason |
| --- | --- |
| Five `model/matter_im_*.c/.h` handlers | Demand parser/tag/field workspaces, exact attribute selectors, temporary Subscribe chunk plan and cleanup/lifetime contracts. |
| `matter_im_buffer_internal.h` | Shared secure workspace destruction and allocation-free emergency status encoding. |
| `matter_fabric_host.c/.h`, `matter_fabric_resumption_internal.h` | Live bounded cache, safe MRU reuse and invalidation. |
| IM/CASE test fixtures, CMake/test-map inventories | New failure sites, byte/lifetime oracles and native CASE allocation coverage. |
| `memory_audit.py`, runtime/status, Memory06 report/results | Reproducible layouts, unchanged stack frames, larger-allocation audit and evidence. |

Not verified: physical ESP32 heap/stack or linked firmware, allocator endurance,
fragmentation/latency, full OTA provider campaign or official CSA tests. Local
host interoperability never changes an official CSA verdict.
