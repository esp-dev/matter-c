# Memory31: selective stable Subscribe value blocks

Memory30's compact shared plans are committed as `235bfa4`; its approved Linux
validation is recorded separately in `5b7ddf3`. This stage adds selective current
value storage. Windows, Linux and C6 validation is complete, including full
two-instance and six-case wire regressions under Memcheck and separately
ASan/UBSan/LSan. The user explicitly approved both frozen source transfers and
test runs; the public exports exclude build/, local/, private keys/device state.

## Change and preserved lifetimes

The existing private indexed-block helper now also supports reserve_at: allocate
only the 16-slot ordinal group containing a selected index, with the last group
clipped to the fixed logical capture count. Links remain sorted, addresses never
move, and no maximum-sized pointer directory or reallocation is introduced.
Insertion can occur before, between or after existing groups. OOM publishes no
link, capacity or cache change. Dense users retain their reservation mode; a
table must not mix dense and selective reservation modes during one capture.
The existing lookup now safely handles leading, interior and trailing gaps;
its preceding-group cache keeps forward traversal across gaps linear.

Subscribe uses this helper only for current value records. Its persistent item
catalog, original ordinals, versions, inclusion flags and resource limits stay
unchanged. A record group is allocated after a successful selected value has
been captured, rather than reserving all result slots before the first provider
read. Omitted/status-only groups need no value record. This is selective block
allocation, not one allocation per value. Successful included values always have
a stable record; status encoding and cleanup tolerate absent groups.

The entire bounded capture must succeed before the first successful ReportData
can be published. Captured bytes remain immutable while providers/scratch bytes
change. ARRAY REPLACE/ADD continuation retains its value until the cursor passes
the whole attribute. Existing IM status and reliable-delivery gates still govern
release; retained ciphertext remains separate until ACK/actual TX completion.
Application-owned scheduling and processing guards are unchanged; this adds no
callback, global storage, task-stack buffer, public API or wire format change.

Complex bytes for version-omitted values are still validated, copied and charged
by the existing snapshot mechanism. This stage removes unneeded value-record
groups, not those byte copies. Full initial/all-changed reports still require
all selected groups. No limits are lowered to obtain the measured savings.

## Measured normal C6 memory

The same IDF 6.1 normal-image profile uses COM23 at 1000000 baud and TL-MR3020:
five fabrics, 15 CASE sessions and 15 full 171-attribute subscriptions, three
parallel Read rounds, three Fabric publications with parallel Reads, then four
live own-fabric removals. Each normal run completes 51 full Reads and 15
subscription snapshots. The explicit corrected diagnostic peer is used for the
load; initial and final RGB smoke use the original peer.

|Metric, bytes|Memory29|Memory30|Memory31|
|---|---:|---:|---:|
|SDK-timer sampled whole internal 8-bit heap peak|357652|351084|344968|
|Minimum sampled free heap|58520|65092|71284|
|Minimum sampled largest free block|33792|39936|47104|
|SDK minimum-free watermark|57288|62788|68932|
|Tracked core block peak|262884|257296|251192|
|Owner observed stack use / reservation|3288 / 12800|3208 / 12800|3288 / 12800|

Memory31 adds an observed whole-heap reduction of 6116 B versus Memory30;
both stages together reduce it by 12684 B versus Memory29. The tracked core
peak falls a further 6104 B, or 11692 B across both stages. Whole heap includes
SDK/Wi-Fi and dynamically reserved task stacks; tracked core is a subset, not
an amount to add to the whole-heap peak. Static D/IRAM is separate. Sampled
minima and the SDK watermark need not coincide.

These are single-run profiles with identical requested load, not a universal
Matter RAM bound or statistical guarantee. Observer firmware is excluded from
this headline comparison. The normal timer samples every 100 ms; transients
between samples may be missed. All raw checkpoints and source/binary hashes
are summarized in [results](memory31-results.json).

After normal teardown, core allocations/bytes are zero and free heap is 390228 B,
equal to Memory30, but the largest block is 221184 B versus 245760 B. Equal
free bytes do not guarantee an equal largest block: placement/fragmentation of
remaining SDK allocations still matters. This is a measured limitation, not a
claim that fragmentation is eliminated. Under load, the minimum largest block
improves by 7168 B versus Memory30. No SDK allocation failure occurs.

Compiler frames are Read report_chunk 48/process 48/release_consumed 16 B;
Subscribe chunk 80/capture 80/process 32/release_consumed 16 B; reserve_at 32 B,
find 0 B. The observed task usage is 80 B greater than Memory30, equal to
Memory29. Stack reservation remains 12800 B. Per-function frames and observed
watermarks do not prove a complete worst-case nested stack bound.

## Selective-update oracle and OOM

The same new public-API fixture was compiled against Memory30 and Memory31:
512 catalog paths, only attributes 17/255/512 changed, six-byte inline values.
At captured report output on the 64-bit Windows host, tracked live memory falls
22240 -> 10640 B and blocks 68 -> 39: 11600 B and 29 allocations saved. These
are host measurements, not C6 bytes or a whole-system peak. Original catalog
order and all 512 initial values are checked; later chunks must retain original
content/version despite provider scratch mutation.

The fixture also changes attribute 512 to a multi-packet ARRAY, requires one
REPLACE and subsequent ADDs across sparse ordinal gaps, and alternates both
ACK/IM-status orders. All 56 allocation ordinals in a 48-path update with
30-byte complex values are failed individually: each produces ResourceExhausted,
no partial successful ReportData and zero live allocations at cleanup. The
Memory30 baseline has 57 ordinals. The generic helper test checks arbitrary
insertion, missing groups, alignment/zeroing, all 512 stable addresses, short
tail and failed insertion preserving all links/cache/capacity and existing data.

An initial prototype OOM test failed because it assumed allocation 7 occurred
before any provider read. The selected value block now follows the first
successful read. The test retains exact expectations: ordinals 1..6 read zero
values, ordinal 7 reads one, all require ResourceExhausted and complete cleanup.
The full final native suites, sparse oracle and physical tests include this
corrected expectation; the original failed attempt is retained in ignored logs.

## Separate allocation attribution

A separately built observer runs the same fixed profile with 2048 live-record
and 128 site slots. Its 18956 B metadata changes memory layout/timing, so its
system heap is not a comparable normal-image measurement. Its binary and exact
debug ELF are fingerprinted, and the public allocation_decode.py validates all
dump sums, no duplicate/missing sites, zero observer overflow and zero-live
complete drain. This run uses 125 sites and reaches 1131 live blocks; tracked
peak is 251096 B. Normal source and observer differ only by the documented
allocation hooks/dump calls.

At that separate peak, DWARF translation units distinguish the private helper's
three allocation sites:

|Block group at observer peak|Bytes|Allocation blocks|
|---|---:|---:|
|Persistent Subscribe item catalog (dense reserve)|39792|156|
|Selected Subscribe current values (reserve_at)|28256|107|
|Read result/value blocks (dense reserve)|25104|52|
|Read compact chunk plans|4800|4|

The first three groups total 93152 B, compared with 99764 B in Memory29's
separate observer. Read plans fall 9600 -> 4800 B. These maps show where
allocations remain, but their peaks are distinct observations, not an exact
byte-for-byte decomposition of the normal-image difference. Fabric image
15552 B, Diagnostics 8488 B, ACL 6384 B and Fabric object 4224 B still remain
possible future work. No such unrelated refactoring is included here.

## Executed validation

* Windows Debug build and CTest: 102/102 definitions pass in 167.89 s.
  The final test_im_subscribe_alloc --memory-sparse command confirms the exact
  before/after capture numbers and 56-position OOM sweep. Targeted helper and
  Subscribe tests also pass 3/3 in the isolated prototype.
* All six Windows native wire scenarios pass: before/after and single lost ACK
  with original/corrected peer in both loop orders. The inherited original
  peer requires the known 14/15 outcome; corrected peer requires 15/15. These
  tests preserve strict wrong-role rejection and check all 15 CASE Reads,
  RX reorder, three OOM positions, held reliable completion, ACK ordering,
  reconnect and zero-live actual-completion drain.
* C6 normal fixed profile passes in 297.35 s, with 51 Reads, 15 snapshots,
  three publication rounds, four live removals and zero healthy-operation
  errors/unexpected subscription closures/SDK allocation failures.
* Separate C6 OOM/loss/reconnect run passes in 465.39 s, including 268.57 s
  sustained work, 76 full Reads, 45 snapshots and 30 CASE pairs/resumptions.
  One OOM loses one subscription and explicitly rebuilds 15/15; injected RX
  loss requires no subscription rebuild. One reconnect and one held completion
  are exercised. Stop waits 3.720 s and ends at zero core live allocations/bytes.
  The 13 intentional boot core-OOM fixtures are separate from the one runtime
  OOM; SDK allocation failures remain zero.
* Separate observer profile passes; all decoded sums/overflow/end-live checks
  pass. Final original-peer RGB smoke on normal firmware passes with exactly
  one original fabric and zero-live drain.
* Linux normal and separate sanitizer builds each pass 99/99 native tests.
  The complete two-instance scenario passes 6/6 under Memcheck and separately
  ASan/UBSan/LSan. All six wire scenarios pass under each tool, including both
  peers/both loop orders, OOM3, held completion, ACK/RX loss, reconnect and
  zero-live drain. Every Memcheck process ends with zero errors/exit bytes/blocks;
  pair stderr is empty and sanitizer wire logs have no diagnostic. Both Linux
  build logs contain no compiler warning/error lines. All 825 exported-file
  hashes are verified on the VM; affected production/test LF hashes also match
  the final checkout and C6 source snapshot.

Commands: cmake --build and ctest -E runtime_wire for Windows and both Linux
builds; test_im_subscribe_alloc --memory-sparse for each matched core; Linux
runtime-pair-host with chip_tool_three_phase.py --source-registers
--meter-services; runtime_wire.py (all six cases), with --memcheck only for
the normal Linux build; distinct MATTER_SANITIZE=ON build with leak detection
and halt-on-error enabled; IDF 6.1 normal/observer builds; fixed
MATTER_SOAK_MEMORY_PROFILE=1 and ordinary fault/reconnect soak; allocation_decode.py
with source-matched ELF; RGB smoke; check_test_map.py and git diff --check.
No new C compiler warning was observed locally; existing SDK Kconfig and
include-export notices remain. No official CSA campaign, new Apple/Google
Home pairing or newly matched ESP-Matter comparison was performed.

## Files and cleanup

* model/matter_im_blocks_internal.h: selective stable-group reservation and safe
  lookup across holes, shared with the existing typed block helpers.
* model/matter_im_subscribe.c: allocate selected groups after capture/selection,
  safely encode status rows and release absent records through existing gates.
* tests/test_im_blocks.c: alignment, stability, holes, bounds and atomic OOM.
* tests/test_subscribe_memory.h and test_im_subscribe.c: same-baseline memory
  oracle, immutable sparse/ARRAY snapshots, ACK orders and full OOM sweep.
* tests/test_subscribe_selectors.h: precise allocation-7 provider-read expectation.
* doc/runtime.md, README/status and this report/results: current storage contract,
  evidence and remaining limits.

Original task-start NVS and normal Memory31 firmware are restored. COM23 is
released, own temporary Wi-Fi profile/XML removed, Windows IPv6 left enabled.
COM24 and AP configuration are untouched. Raw logs, keys, controller/NVS state
and SDK builds remain ignored and are not part of the public source exports.

Next candidate: make the Diagnostics encoded-value workspace temporary, after
checking provider-value lifetime and OOM behavior. Its current encoded[4096]
alone reserves 4096 B per Diagnostics object; this is a structural opportunity,
not a measured peak saving. No implementation of that next step is included.
