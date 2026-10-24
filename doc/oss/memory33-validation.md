# Memory33: demand-sized ACL encoding

Baseline Memory32 is committed as `64e5fd0`. ACL's resident encoded[4096] becomes
one owned, exact-size provider span. C API, TLV bytes and limits, fabric filtering,
foreign-field redaction, authorization, staged writes/events, Read/Subscribe
snapshots and IM/MRP/TX drain gates remain unchanged. Windows coverage, Linux
Memcheck/separate sanitizers and all C6 profiles/restoration pass. Source-matched
measurements and final validation are recorded in [results](memory33-results.json).

## Ownership, filtering and atomic writes

One shared read helper measures a pure encoder with the existing private TLV
measuring writer, allocates exactly the output size, then encodes the same stable
validated backend view. The view callback runs once per accepted encoded read;
no view/store callback or yield occurs between passes. The model busy guard
covers the callback, sizing, allocation and encoding. The backend owner continues
to serialize mutations, as required by the existing port contract. The original
4096-byte budget, depth 4 for entries/depth 1 for global ID lists, five fabrics,
four entries/fabric, four subjects and three targets are unchanged. No grow,
realloc, shared global buffer, large local view or new task-stack array is added.

The original entry encoder remains shared by reads and event payloads. Filtered
reads emit only the accessing fabric. Unfiltered reads preserve backend order
and emit foreign entries with only FabricIndex; sensitive fields are omitted,
including null/zero substitutes. Invalid/missing fabric is rejected before the
old span is freed. Scalars allocate no encoding memory and release the old span.

A returned encoded span remains unchanged until the next accepted provider read
or deletion. Rejected/reentrant reads, version/access/authorization queries,
validation, writes and prepared Added events do not end this borrow. In particular,
a caller may pass the encoded read directly to validate/write without a hidden
free of its input. Standalone encoded-only callers may retain one bounded span
until a later read/delete. The direct version query retains its existing behavior;
mutating/reentrant operations are rejected while encoding is busy.

Read/Subscribe copy bytes immediately into their independent immutable snapshots.
Provider free/reencoding or ACL publication before a report's ACK cannot change
the captured bytes/version. The handler still authorizes continuations; the
encoding workspace does not own reliable ciphertext or ACK/drain resources.

Encoding OOM returns ResourceExhausted to direct reads, releases temporary memory
and leaves view/version/grants unchanged for retry. Existing generic IM mappings
remain Read path Failure and InvalidAction when a sole failed initial Subscribe
path leaves no active path. The separate pending entries, parser and event
records are unchanged. Validation/store do not allocate this encoding buffer;
failed atomic store/event preparation retains the existing model/event behavior.

The cost is one allocation/free and two bounded TLV passes for each encoded read,
including short global lists. Scalars, authorization and version queries do not
allocate encoding memory. No universal CPU/fragmentation improvement is inferred.

## Normal C6 profile versus Memory32

Same IDF 6.1 SDK configuration, 12800-byte main-task reservation, 100 ms internal
8-bit whole-heap timer, COM23 at 1000000 baud and TL-MR3020. Five fabrics, 15 CASE
sessions, 15 full 171-attribute subscriptions, three parallel-Read rounds, three
Fabric publication rounds and four live own-fabric removals use the explicit
corrected diagnostic peer. RGB smoke uses the original pinned peer.

|Metric, bytes|Memory32|Memory33|
|---|---:|---:|
|SDK-timer sampled whole heap peak|341008|338944|
|Minimum sampled free heap|75216|77272|
|Minimum sampled largest free block|52224|55296|
|SDK minimum-free watermark|73580|77200|
|Tracked core block peak|246672|242876|
|Owner observed stack use / reservation|3192 /12800|3176 /12800|
|Largest free block after teardown|225280|245760|
|Free heap after teardown|390228|390200|

Observed whole-heap peak falls 2064 B, sampled free minimum rises 2056 B and
minimum largest block rises 3072 B. Core peak falls 3796 B. Whole heap includes
SDK/Wi-Fi and dynamically reserved task stacks; core is a subset and static
D/IRAM separate. Peaks must not be added, and sampled minima/SDK watermarks need
not coincide. These matched-workload single runs are not a statistical or
specification-wide worst-case RAM bound; the sampler can miss shorter peaks.

The matching normal ELF layout is ACL 6384 -> 2288 B: exactly 4096 B less resident
context. Its encoded member changes 4096 -> 4 B at offset 2284; tail alignment
accounts for the total difference. The structural reduction is not a guaranteed
4096-byte whole-system peak saving. Teardown ends with zero core live bytes/count.
Final free heap is 28 B lower with different remaining SDK allocations/placement;
the largest free block is 20480 B larger. This is not proof of eliminating
fragmentation or of a retained core allocation.

Compiler frames: old read_entries 48 B, read_ids 32 B; new wrappers 16 B,
read_encoded 64 B, encode_entries 32 B and encode_ids 16 B. Entry/ID encoder call
chains can therefore add 64 B. The observed task watermark improves by only
16 B and does not bound all call paths. read_scalar 16 B, parse 80 B,
write_entries 48 B and prepare_events 48 B stay unchanged. No task reservation
is reduced and individual frames are not a full SDK worst-case stack bound.

## Executed validation

* Focused ACL tests pass 4/4. Exact-size accounting tests all 13 combinations:
  five accessing fabrics with both filters, plus three encoded globals. Each
  allocation independently fails/retries; literal TLV, maximum counts, unchanged
  backend bytes/versions, instance isolation, rejected read retention, allocation
  hook reentry and zero-live cleanup are checked. Read-to-write aliasing works
  through validation, failed store and successful publication to another fabric
  while the next encoding allocation is armed to fail. No allocation is consumed.
* Existing event/write regressions remain, with an extra retained-span check
  through failed and successful event-producing writes. Staged event failure
  leaves ACL/version and event position unchanged. Original self-lockout,
  per-request authorization, modern/legacy writes and store/reservation failures
  remain covered.
* New concurrent Read/Subscribe regression uses real Administer authorization
  and trusted CASE fabric resolvers for different fabrics. One unfiltered read
  captures all 20 entries, with 16 foreign shells checked literally; the filtered
  subscription captures four full entries. Both need multipart ARRAY REPLACE/ADD.
  Between chunks it writes ACL, reads/reencodes, writes that borrowed input and
  frees it via a scalar read before ACK/status. Exact bytes/order and DataVersion
  17 remain stable in both handlers, with both IM/MRP confirmation orders and no
  continuation reread. Provider OOM tests existing IM mappings and zero-live drain.
  All large fixture buffers/views/parsers are on heap.
* Windows CTest suite (wire excluded) covers 107 cases: initial run passes 104/107
  in 178.96 s, with three UDP wait_event timeouts. Explicit-name repeats of
  test_udp_windows, test_udp_windows_alloc and test_unsecured_tx_windows pass
  3/3 outside sandbox after AP connection, unchanged sources. These environmental
  changes do not isolate the original cause. An intervening --rerun-failed used
  shifted numeric IDs with the wire exclusion and is not counted as a UDP retry.
  All six wire cases pass, including three OOM cycles, controlled loss/reorder,
  held reliable completion/drain and single-lost-ACK with original/corrected peer
  in both loop orders. Original peer retains the expected 14/15; corrected peer
  retains 15/15, with all 15 existing CASE Reads and zero-live cleanup.
* Normal C6 passes 291.32 s: 51 full Reads, 15 snapshots, three publication rounds,
  four live removals, stop 3.799 s. No healthy-operation errors, unexpected
  subscription closures or SDK allocation failures. The 13 deliberate boot core
  fault fixtures are separate from the runtime OOM campaign.
* C6 fault/reconnect soak passes 544.86 s: 110 full Reads, 45 snapshots,
  30 CASE pairs/resumptions, one consumed runtime allocation fault, 43 deliberately
  dropped RX packets, radio reconnect and held-completion drain. Runtime OOM
  preserves all subscriptions and needs no load rebuild; the loss window produces
  one expected PeerUnresponsiveError and a full-load rebuild. Both windows finish
  at the full 15 subscriptions. No healthy-operation errors, unexpected closures
  or SDK allocation failures. Stop takes 3.747 s; cleaned core bytes/count are 0.
  Separate fault-workload sampled peak 323172 B, min free 94816 B, min largest
  71680 B, SDK watermark 93104 B, stack use 3176/12800 B. Final free heap 390188 B,
  largest block 212992 B; these are not an additional normal-profile saving.
* Separate C6 attribution profile passes 298.81 s with 51 full Reads/15 snapshots.
  All 18 live byte/count and peak-byte sums match sites resolved against its exact ELF, with
  zero overflows, 127/128 site slots and 1149/2048 peak live records. Peak tracked
  bytes 242528 B; the ACL context contributes 2288 B at that peak. Complete dump
  has zero live bytes/count. Instrumentation costs 18956 B and changes only the
  ignored observer allocator/app sources; whole-system heap from this image is
  excluded from the normal comparison. Temporary ACL spans are absent from these
  captured peak/live maps; native exact-size/OOM tests cover their bytes.
* Linux normal CTest 104/104, full two-instance scenario 6/6 and all six wire
  cases pass under the standard runner. Pair/wire have zero Memcheck errors/exit
  allocations and pair stderr is empty. Separate ASan/UBSan/LSan CTest 104/104,
  full pair 6/6 and all six wire scenarios pass, without sanitizer diagnostics.
  All 831 exported file hashes match the frozen Windows/C6 source archive;
  changed code/test/configuration LF hashes are also recorded in public results.

Two failed prototype fixture assumptions are retained locally: the read adapter
also calls View before Administer, and fabric-scoped attributes require a trusted
CASE resolver. The corrected fixture uses both real checks and new_case handlers.
Production ACL code did not change for these fixture corrections.

Executed commands/runners:

* `cmake --build build/memory16/windows-gcc -j3` and
  `ctest --test-dir build/memory16/windows-gcc --output-on-failure -E runtime_wire`;
  focused `ctest -R ^test_acl`, the three UDP tests by explicit regex and direct
  allocation executables.
* `runtime_wire.py` all six cases with built host, pinned Node/modules and fresh
  output; Linux normal adds `--memcheck`. See [wire tests](../runtime-wire-tests.md).
* Isolated IDF 6.1 normal/observer builds, `soak.mjs` with
  `MATTER_SOAK_MEMORY_PROFILE=1` and separate fault/reconnect soak.
  `allocation_decode.py` checks all dumps against the matching observer ELF.
* Linux Debug `MATTER_SANITIZE=OFF` CTest, then the full
  `chip_tool_three_phase.py` pair and wire under Valgrind; a distinct
  `MATTER_SANITIZE=ON` build runs CTest/full pair/wire with
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
  `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
* `python tools/matter/check_test_map.py` and `git diff --check`.

Final collection verifies the source/archive and matching BIN/ELF,
zero-live/sum/overflow gates, complete Linux matrix and restored network/device
state. No new C compiler warnings in Windows/Linux/C6; existing SDK
Kconfig/include-export notices remain.

## Files, cleanup and next task

* clusters/matter_acl.c: demand-sized span, shared guarded sizing/encoding and
  accepted-read/delete cleanup; existing write/authorization code unchanged.
* clusters/matter_acl.h and doc/runtime.md: actual provider borrow and OOM contract.
* tests/test_acl.c: byte/OOM/reentry/alias accounting and retained event-write span.
* tests/test_acl_reports.c: real multi-fabric multipart snapshots and provider OOM.
* cmake/test-cases.json and doc/oss/test-map.json: native test registration/inventory.
* README/status and this report/results: measured evidence and limitations.

Normal firmware/original fresh NVS restoration, original-peer RGB smoke,
singleton-fabric check and zero-live drain pass. COM23/AP are released; own
temporary Wi-Fi profile/XML removed. IPv6 remains enabled. COM24 and AP
configuration are untouched.
Raw logs, credentials, controller/NVS state remain ignored and outside public
exports. User explicitly approved the Memory33 destination and tests after the
automatic review rejected it as outside the prior Memory32 path approval.

No new official CSA, Apple/Google Home pairing or newly matched ESP-Matter
benchmark is performed. Next candidate: audit the remaining
matter_fabric.c encoded[MATTER_IM_READ_MAX_VALUE] (4096 B), including certificate
value lifetime and secure cleanup. Its resident size is a structural opportunity,
not a measured next-stage peak saving.
