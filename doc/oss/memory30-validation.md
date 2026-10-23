# Memory30: compact shared Read/Subscribe report plans

Memory29 is committed as `6a5332d`; the implementation and local/C6 evidence
are committed as `235bfa4`. This stage is compiled and tested on Windows, Linux
and C6. Full Linux two-instance tests pass under Memcheck and separately
ASan/UBSan/LSan. The initial automatic-review transfer rejection was resolved by
the user's explicit authorization of both stage directories; the frozen public
exports exclude local/, build/, private keys and device state.

## Change and invariants

Read and Subscribe now share the private `Matter_Im_Chunk_Plan`: three uint16_t
ordinals/offsets plus the prefix flag, exactly8bytes on supported builds instead
of16bytes on C6. The C99 compile-time guard checks both existing resource ceilings
and layout. Shared assignment helpers reject out-of-range values before explicit
casts. All cursors, arithmetic and complete wire attribute IDs retain their
original types. The zero-offset whole-value sentinel and ARRAY prefix/ADD rules
are unchanged; encoded packet bytes and public DTOs/APIs do not change.

Read still allocates its plan on demand and retains it through continuation.
A150-entry C6 plan is1200bytes instead of2400: direct saving1200bytes per active
Read,4800 for four observed concurrent plans or6000 for five. Subscribe's nine
plan entries reduce its ephemeral work context1920 ->1848bytes. Read work stays
1720bytes. Immutable value blocks, output leasing, retained ciphertext,
ACK/completion ordering and drain lifetimes remain unchanged. No new allocations,
reallocations, maximum-sized pointer directory or task-stack buffer is introduced.

## Normal C6 comparison

The same fixed workload as Memory29 uses IDF6.1, C6 COM23 at1000000baud,
TL-MR3020, five fabrics/15 CASE sessions/15 full171-attribute subscriptions,
three parallel-Read rounds, three Fabric publications with parallel Reads, then
four live own-fabric removals. The explicitly corrected diagnostic peer is
recorded; initial/final RGB smoke use the unmodified peer.

|Metric, bytes|Memory29|Memory30|
|---|---:|---:|
|SDK-timer sampled whole internal8-bit heap peak|357652|351084|
|Minimum sampled free heap|58520|65092|
|Minimum sampled largest free block|33792|39936|
|SDK minimum-free watermark|57288|62788|
|Tracked core block peak|262884|257296|
|Owner observed stack use / reservation|3288 /12800|3208 /12800|

Observed whole-heap peak falls6568bytes and tracked-core peak5588bytes. These
are single-run measurements, not exact attribution of every byte to plan size
or a statistical worst-case bound. The timer includes SDK/Wi-Fi/dynamic task
stack reservations; core is a subset, static D/IRAM separate. Do not add the two
peaks. Independent region watermarks and sampled minima need not coincide.
Normal images contain no RX trace or allocation observer. Source-matched ELF
layouts, hashes and telemetry are in [results](memory30-results.json).

Compiler frames stay unchanged: Read report_chunk48/process48bytes; Subscribe
chunk80/process32bytes. Task watermarks describe observed paths, not a safe
new stack-size limit. The main-task reservation remains12800bytes.

## Executed tests and retained limitations

* Windows build succeeds. The initial restricted CTest run passes99/102;
  UDP loopback tests test_udp_windows, test_unsecured_tx_windows and
  test_udp_windows_alloc time out waiting for RX. The unchanged three tests
  pass3/3 outside the sandbox network restriction. Thus all102 definitions
  have successful coverage, with the initial failure retained.
* Both Windows native wire cases pass: immediate/before71.07s and deferred/
  after297.58s. These cover five fabrics/15 sessions/subscriptions, full Reads,
  RX reorder, all three selected OOM ordinals, missing-ACK retirement/rebuild,
  strict wrong-role rejection, ACK before held reliable completion, explicit
  reconnect and zero-live actual-completion drain. The after case completes
  80 full Reads and75 subscription snapshots; no healthy-operation failure.
* The normal C6 fixed profile passes299.18s:51 full Reads,15 snapshots, three
  publication rounds and four live removals. No healthy-operation errors,
  unexpected subscription closures or SDK allocation failures.
* The separate C6 fault/reconnect run passes471.29s, including274.22s sustained
  workload,76 full Reads,45 snapshots and30 CASE pairs/resumptions. It exercises
  one OOM, one injected RX-loss phase, one reconnect and one held completion.
  OOM loses one subscription, explicitly rebuilds15/15; the loss phase needs
  no subscription rebuild. Stop waits3.728s; tracked live allocations/bytes
  end at zero, with zero SDK allocation failures. Boot's13 intentional core
  failure fixtures are distinct from the one runtime OOM.
* IDF6.1 normal build, check_test_map.py, diff review/check, ELF layout and
  compiler stack-frame inspection were executed. Existing SDK include-export/
  Kconfig notices remain; no new C compiler warning was observed.

Commands: cmake --build build/memory16/windows-gcc; ctest with -E runtime_wire;
the three-test network retry with -R; runtime_wire.py --case before/after;
local IDF6.1 build of the isolated public source tree; the fixed C6
MATTER_SOAK_MEMORY_PROFILE=1 run and ordinary run wildcard fault/reconnect
controller; final RGB smoke; python tools/matter/check_test_map.py.
Linux validation uses the frozen Memory30 source export (823 files), with all
hashes verified on the VM and the four affected production-file hashes matched
to this report. Both normal and separate sanitizer builds pass99/99 native tests.
The complete two-instance scenario passes6/6 checks under Memcheck and separately
ASan/UBSan/LSan, including dynamic three-phase attributes/events and isolated
runtimes. Both wire cases (before/after) also pass under each tool: OOM3, ACK loss,
held completion, reconnect and actual-completion drain. All Memcheck processes
end with0errors and0bytes/blocks; pair stderr is empty and sanitizer wire logs
contain no diagnostic. Linux builds emit no compiler warning/error lines.

Commands on Linux: cmake Debug with MATTER_SANITIZE=OFF, cmake --build -j3,
ctest -E runtime_wire, runtime-pair-host under valgrind plus
chip_tool_three_phase.py --source-registers --meter-services, runtime_wire.py
--case before/after --memcheck; repeat with a distinct MATTER_SANITIZE=ON build
and without Valgrind (ASAN detect_leaks/halt_on_error and UBSAN halt_on_error).
Raw logs and private state remain ignored. No official CSA, new Apple/Google Home
pairing or exhaustive hardware OOM campaign is claimed.

## Files and cleanup

* model/matter_im_chunk_internal.h: common bounded8-byte plan and checked writes.
* model/matter_im_read.c and matter_im_subscribe.c: use the common plan at every
  dynamic ordinal/offset assignment; constant prefix sentinel assignments remain.
* cmake/sources.json: package the new private header without changing public API.
* README/status and this report/results: actual Windows/Linux/C6 evidence.

The original task-start NVS and normal Memory30 image were restored. RGB smoke
passes with exactly one original fabric and zero-live drain. COM23 is released;
the own temporary Wi-Fi profile/XML is removed, IPv6 remains enabled, COM24 and
AP configuration are untouched. The second stage is developed in an isolated
copy so these measurements refer only to the compact plan. Next: selective
current-value blocks for Subscribe, with the same limits and snapshot/ACK gates.
