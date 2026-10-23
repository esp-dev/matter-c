# Memory32: demand-sized Diagnostics encoding

Baseline Memory31 is committed as `acf0147`. This stage replaces Diagnostics'
resident encoded[4096] with an owned, demand-sized provider span. Public C API,
TLV bytes, backend snapshot/version publication, resource limits and IM/MRP/TX
drain ownership remain unchanged. Windows, Linux Memcheck/separate sanitizers
and all C6 profiles pass. Source-matched measurements and final validation are
recorded in [results](memory32-results.json).

## Encoding and provider lifetime

One shared helper measures a pure encoder with the existing private TLV measuring
writer, allocates exactly the measured size, then encodes the same model-owned
snapshot. Both passes use the original 4096-byte budget, depth 1 for ID arrays
and depth 4 for the other containers. No callback/yield occurs between passes;
the model's busy guard covers sizing, allocation and encoding. Existing TLV
validation, widths, ordering and all maximum interface/address/fault counts stay
unchanged. A shared fault-array builder replaces three repeated loops; IDs,
interfaces and load retain their own pure builders. There is no grow/realloc,
maximum-sized pointer directory, global buffer or new task-stack byte array.

Scalar and BSSID reads allocate no encoding memory. An encoded read borrows its
span until the next accepted Diagnostics provider read (including the Wi-Fi
sibling), owner refresh or deletion. Version/access-description queries and
rejected reentrant calls leave a live span intact. General metadata remains
available when the backend is invalid, as before. The common read entry and
refresh/delete cleanup release old spans only after the applicable borrow ends;
freeing at callback return would be too early. Runtime already refreshes before
IM processing, so the last span is reclaimed on the next owner boundary.
Standalone clients retain the borrowed span until their next applicable call.

Read/Subscribe copy provider bytes synchronously into their independent immutable
snapshots. Refresh/reencoding may happen before any chunk is sent/acknowledged,
without affecting captured values or versions. Partial ARRAY values retain
their existing snapshot through REPLACE/ADD continuation; reliable ciphertext
and ACK/actual-completion drain remain independent. No scheduler, session,
Fabric persistence or generic IM error-policy change is included.

Direct encoding OOM returns ResourceExhausted, releases the temporary span and
leaves backend data/versions coherent for retry. The existing generic provider
error mapping remains: Read reports path Failure; if the sole initial Subscribe
path fails, no active path remains and priming returns InvalidAction. These
outcomes are tested explicitly rather than claiming a new global OOM mapping.
Refresh still atomically validates/publishes its pending backend snapshot.

The tradeoff is one allocation/free and two bounded TLV passes per encoded read.
Short encoded arrays also allocate their exact size; the original scalar and
BSSID fast paths remain allocation-free. No universal CPU/fragmentation saving
is inferred from the reduction of resident storage.

## Normal C6 comparison

The IDF 6.1 normal image uses the same SDK settings, 12800-byte main-task
reservation, 100 ms whole-internal-8-bit-heap timer and COM23 at 1000000 baud as
Memory31. TL-MR3020 carries five fabrics/15 CASE sessions/15 full 171-attribute
subscriptions, three parallel-Read rounds, three Fabric publications with
parallel Reads and four live own-fabric removals. The explicit corrected
diagnostic peer is used for load; RGB smoke uses the original peer.

|Metric, bytes|Memory31|Memory32|
|---|---:|---:|
|SDK-timer sampled whole heap peak|344968|341008|
|Minimum sampled free heap|71284|75216|
|Minimum sampled largest free block|47104|52224|
|SDK minimum-free watermark|68932|73580|
|Tracked core block peak|251192|246672|
|Owner observed stack use / reservation|3288 /12800|3192 /12800|
|Largest free block after teardown|221184|225280|
|Free heap after teardown|390228|390228|

Observed whole-heap peak falls 3960 B; minimum sampled free rises 3932 B and
minimum largest block rises 5120 B. Whole heap includes SDK/Wi-Fi and dynamic
task-stack reservations; core is a subset, static D/IRAM separate. Do not add
peaks or assume sampled minima and SDK region watermarks coincide. These are
single-run observations, not a specification-wide/statistical worst-case bound;
the 100 ms sampler may miss shorter transients. The request/workload is matched,
but message timing and allocator placement can differ.

The source-matched C6 ELF layout is Diagnostics 8488 -> 4392 B, an exact 4096-byte
context reduction. Its encoded member changes 4096 -> 4 B at offset 4388; tail
alignment accounts for the total layout difference. Encoded memory now exists
only during an applicable provider borrow and is sized to actual output. Normal
teardown ends at zero core live allocations/bytes. Equal final free heap and a
larger final largest block are compatible with different placement of the same
remaining SDK allocations; this does not establish elimination of fragmentation.

Compiler frames show encoded_value 64 B, encode_interfaces 16 B and interfaces 32 B;
the original general_0 frame 32 B remains. The extra helper path can add 80 B to
the static call chain, despite the lower observed normal-task watermark. Scalar
read/entry/free helpers use 16-byte frames. No task-stack reservation is reduced,
and individual frames/watermarks are not a complete worst-case SDK call bound.

## Executed validation

* Focused Diagnostics tests pass 4/4. Native allocation tests are now registered
  in CTest, retaining the existing legacy entrypoint. Scalars/idle polling/BSSID
  allocate nothing; all 11 encoded-read cases allocate exactly output size and
  independently fail/retry their allocation. Tests check versions, literal TLV,
  maximum snapshot validation, sibling/instance isolation, allocation-hook
  reentry rejection, failed refresh/static metadata and delete cleanup.
* A new public-API regression runs Read and Subscribe concurrently against one
  Diagnostics model with eight maximum-sized logical interfaces. Each handler
  needs multiple ARRAY REPLACE/ADD packets. Between chunks it refreshes, frees,
  reencodes and frees the provider span through the sibling, before ACK/status.
  Both confirmation orders retain all original child bytes and DataVersion;
  providers are not reread for continuation. Provider OOM tests the existing IM
  mapping and zero-live cleanup. All large fixture data/parsers are heap-owned.
* Windows Debug build and full CTest pass 105/105 in 279.98 s, including installed
  consumer and test inventory. All six wire cases pass: before/after plus a
  single lost ACK with original/corrected peer in both loop orders. The original
  peer still requires the known 14/15 result, corrected peer 15/15. OOM 3, strict
  wrong-role rejection, all 15 CASE Reads, RX reorder, missing ACK, held reliable
  completion, reconnect and zero-live drain are exercised.
* Normal C6 profile passes 304.11 s: 51 full Reads, 15 snapshots, three publication
  rounds, four live removals, stop 3.582 s. No healthy-operation errors, unexpected
  subscription closures or SDK allocation failures. Boot's 13 deliberate core
  constructor/fault fixtures are separate from runtime OOM campaigns.
* C6 fault/reconnect soak passes 465.63 s: 76 full Reads, 45 subscription snapshots,
  30 CASE pairs/resumptions, one forced runtime OOM (one lost subscription,
  full-load rebuild), 44 deliberately dropped RX packets, radio reconnect and
  held-completion drain. Stop takes 3.481 s. No healthy-operation errors,
  unexpected closures or SDK allocation failures; cleaned core live bytes/count 0.
  This different fault workload records sampled peak 325628 B, min free 92520 B,
  min largest 69632 B, SDK watermark 90584 B and task use 3288/12800 B. Final free
  heap 390168 B/largest 200704 B differs from the fixed normal profile; these are
  separate workloads, not an extra claimed saving.
* Separate C6 attribution profile passes 294.69 s with 51 full Reads/15 snapshots.
  All 18 dump byte/count sums match their site records against the exact observer
  ELF, with 0 overflows, 126/128 site slots and 1140/2048 peak live records. Peak
  tracked bytes 246592 B; Diagnostics context is 4392 B at that peak. Complete dump
  has 0 live bytes/count. Instrumentation costs 18956 B and changes only the
  ignored observer allocator/app sources; its whole-system heap is excluded
  from the normal comparison. The temporary encoded allocation is not present
  in these captured peak/live maps; native exact-size/OOM tests cover its bytes.
* Linux 102/102 native tests pass. The initial pair reaches the second instance's
  SendNOC step, then chip-tool reports OS EADDRNOTAVAIL (Cannot assign requested
  address) sending to IPv6 link-local ens33 and later Read timeout. This attempt
  is retained; Memcheck has 0 errors/0 exit bytes, node stderr is empty. Current
  interface has a valid link-local address. No VM/network configuration is changed.
  A fresh-state full-pair comparison with old Memory31 and then unchanged new
  Memory32 both pass 6/6 under Memcheck. The triggering interface event is not
  established; this is not relabeled a successful initial run. All six wire
  cases also pass under Memcheck, with zero errors/exit allocations. The separate
  Separate ASan/UBSan/LSan passes 102/102 native tests, full pair 6/6 and all six
  wire cases, including OOM/loss/held-TX and both-peer/both-order single-lost-ACK
  comparisons. No sanitizer diagnostic or pair stderr output. All 828 exported
  source-file hashes match the frozen Windows/C6 source archive. Public results
  also record LF-normalized hashes for changed code/test/configuration files.

Executed commands and runners:

* `cmake --build build/memory16/windows-gcc -j3` and
  `ctest --test-dir build/memory16/windows-gcc --output-on-failure -E runtime_wire`;
  focused `ctest -R ^test_diagnostics`, plus both allocation executables directly.
* `tools/matter/tests/runtime_wire.py` with the built host, pinned Node/modules
  and a fresh output directory, all six cases; Linux normal adds `--memcheck`.
  Reproduction arguments are documented in [wire tests](../runtime-wire-tests.md).
* Isolated IDF 6.1 normal/observer builds with the previous SDK profile; C6
  `soak.mjs` with `MATTER_SOAK_MEMORY_PROFILE=1`, then ordinary fault/reconnect
  soak. `allocation_decode.py` validates all dumps with the matching ELF.
* Linux Debug `MATTER_SANITIZE=OFF` native tests, full `chip_tool_three_phase.py`
  pair and wire under Valgrind; then a distinct `MATTER_SANITIZE=ON` build with
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
  `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
* `python tools/matter/check_test_map.py` and `git diff --check`.

Final collection verifies source/archive, normal/observer BIN/ELF identity,
all zero-live/sum/overflow gates and restored firmware/network state.
No new C compiler warning is observed in Windows/Linux/C6; existing SDK Kconfig and
include-export notices remain. No new official CSA, Apple/Google Home pairing
or newly matched ESP-Matter benchmark is performed.

## Files, cleanup and next task

* clusters/matter_diagnostics.c: span lifetime/cleanup, shared sizing/encoding
  helper, pure builders and common accepted-read entry without changing values.
* clusters/matter_diagnostics.h and doc/runtime.md: actual borrow/OOM contract.
* tests/test_diagnostics.c: exact-size/OOM/reentry/lifecycle accounting with the
  existing test_alloc_bytes helper.
* tests/test_diagnostics_reports.c: interleaved immutable real-provider snapshots,
  max-interface ARRAY continuation, both ACK orders and provider-OOM cleanup.
* cmake/test-cases.json and doc/oss/test-map.json: native allocation/report test
  registration and complete public inventory.
* README/status and this report/results: source-matched measured evidence.

Normal-image/original NVS restoration, original-peer RGB smoke, singleton-fabric
check and zero-live drain pass. COM23 and AP are released; own temporary Wi-Fi
profile/XML removed, Windows IPv6 remains enabled. COM24 and AP configuration
are untouched. Raw logs, credentials, controller and NVS backups are ignored
and excluded from public exports. User explicitly
approved the Memory32 transfer after the initial automatic-review path rejection.

Next candidate: audit ACL's encoded[4096] workspace, preserving fabric filtering,
authorization and staged-write atomicity before choosing a demand-sized lifetime.
Its resident 4096 B is a structural opportunity, not a measured next-step peak gain.
