# Memory16: RGB laboratory and lower concurrent-report peak

Baseline: `a2ea657`. The owner selected an RGB light instead of the planned
three-phase C6 model, prioritizing peak memory. Baseline/final use the same
application model. Public APIs/DTOs, quotas, wire/checkpoint encodings, fabric
publication/fail-safe and transport ACK/drain remain unchanged.

## Storage and lifetime

Read/Subscribe borrow a private snapshot index from their owner-thread
dispatcher. Every report still authorizes, reads its provider and validates its
own frozen value. Only identical immutable encoded bytes are shared. Versions,
permissions, membership, cursors and cumulative 16384-byte budgets remain per
report. This is not a provider-read cache. Different fabric-filtered bytes
cannot alias; hash matches require equal length and `memcmp`.

References retain the existing BOTH-MRP-and-IM, final-tail and cancel/drain gates.
The last reference unlinks/frees its value. Dispatcher deletion rejects live
transactions/indexed values. Report cleanup retains the pool binding for later
Subscribe captures. Standalone engines remain private unless internally bound
before RX. No global mutable pool, public field or new scheduler is introduced.

The 32-bucket index holds at most 128 values of at least 32 encoded bytes. At most
112 entries hold values below 256 bytes, reserving 16 for larger values. A full
index uses the original private copy; it never reduces report admission or stops
sharing existing entries. Indexing a unique value costs 20 B extra requested
metadata on C6, bounded to 2560 B, plus 136 B per dispatcher and 8 B per engine.
Allocator headers/alignment are additional. All-unique data and empty owners
are not claimed to shrink. Small/unindexed payload nodes keep their old layout.
Candidate/reference OOM preserves old references, counters, budgets and the
caller's value. Publication has no intervening application callback.

Read results retain only the validated privilege needed by continuation, rather
than the full attribute-description DTO. Private status/privilege codes use
bytes and a value-first layout avoids padding. Fabric/authorization checks still
run during capture and continuation. Subscribe keeps full-width path IDs beside
status and four private C99 Boolean bitfields; common path adapters reconstruct
the unchanged provider DTO. Versions, ordering, flags and stable result blocks
are preserved. No live result is reallocated.

## Experimental RGB application

Opt-in `CONFIG_MATTER_C_RUNTIME_RGB` adds EP1: 171 attributes total, 38 on EP1.
OnOff, LevelControl and ColorControl serve On/Off/Toggle,
MoveToLevel/WithOnOff, Stop/WithOnOff, MoveToHueAndSaturation and StopMoveStep.
The application advances independent level/color transitions and notifies the
runtime. The portable model and IDF RMT adapter have separate ownership. IM never
waits for the LED; GRB remains borrowed until actual RMT completion.

GPIO8 follows the
[DevKitM-1 documentation](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32c6/esp32-c6-devkitm-1/user_guide.html).
WS2812-compatible timing uses 10 MHz, one RMT transaction and no LED task. The
C6 model/LED owners are 280/20 B, excluding registries/SDK resources. Command
parser/validation scratch lives on the heap, with OOM before model mutation.

This is an **incomplete development light profile**, not a conforming Extended
Color Light implementation. Target type 0x010d/rev5 is declared, but
Identify/TriggerEffect, Groups, Scenes, XY/CT, other HS commands, mandatory
lighting details/writes and durable light settings remain unimplemented. Options
are read-only lab defaults; commands accept mask/override. Selected commands and
transitions are tested; complete lighting semantics, calibrated/visually verified
color, commercial-controller UI acceptance and certification are not claimed.
The controller retains the public TEST identity/development attestation policy.

## C6 layouts and stack

Linked IDF 6.1/GCC 15.2.0 DWARF and `-fstack-usage`, same application:

| Private layout/frame | Baseline | Final |
| --- | ---: | ---: |
| Read result |48 B|32 B|
| Subscribe persistent result |24 B|16 B|
| Read / Subscribe owner |304 /360 B|312 /368 B|
| Dispatcher |8160 B|8296 B|
| Indexed header / report reference |absent|16 /8 B|
| Snapshot-copy frame |112 B|128 B|
| Read / Subscribe process frames |48 /32 B|48 /32 B|
| RGB command / decoder frames |64 /80 B|unchanged|
| App pump / LED process frames |32 /48 B|unchanged|

The snapshot helper adds 16 B to that frame. These are not whole call-chain/RTOS
bounds; physical high-water observations follow below. No large parser, packet
or value buffer moves onto a stack.

## Host component measurements

Fresh baseline/final Windows GCC 16.2.0 builds run fifteen 512-value subscriptions
and five nine-array Reads. Frozen bytes, chunk order and both ACK/status orders
are checked. Requested production bytes exclude libc metadata, tracker/fixture
storage, other runtime/SDK resources and the fixture's 272-byte x86_64 index.

| Checkpoint | Baseline | Final shared |
| --- | ---: | ---: |
| Fifteen captured reports |718080 B|583408 B|
| Plus five outstanding Reads |833345 B|635249 B|
| Halfway through delivery |676475 B|520179 B|
| Idle subscriptions, Reads deleted |218610 B|157410 B|
| Allocation-event peak |835673 B|637577 B|
| Largest request |4800 B|4800 B|

Including the 272-byte index, peak saving is 197824 B (23.7%). Final code without
sharing peaks at 773833 B; the other saving comes from result compaction. Linux
normal and separate sanitizer builds produce the same shared counts. This
synthetic 512-result workload still exceeds C6 RAM before other node resources.

The separate event-heavy envelope falls 461558 ->411508 B (10.8%). Its 512-result
Read pre-provider growth peak falls 33458 ->25282 B. It does not bind the value
index. Its fully drained checkpoint grows 704 B on x86_64 from extra fields in
44 live engines; this quiescent tradeoff is retained in the results.

## Physical measurements

| Same 171-attribute application | Sampled internal heap peak | Tracked allocation-event peak | SDK failed attempts | Outcome |
| --- | ---: | ---: | ---: | --- |
| Baseline core |403016 B|310120 B|25|healthy concurrent Reads fail|
| Sharing only |397596 B|305112 B|25|healthy concurrent Reads fail|
| Sharing + compact results, final run |362480 B|269696 B|0|load/recovery/drain pass|

The observed system-heap reduction is 40536 B (10.1%); tracked peak falls 40424 B
(13.0%). Failed runs ended early, so these are observed maxima of the same
requested envelope, not equal-duration statistical or exhaustive peak bounds.
The earlier final-firmware attempt had healthy traffic/zero SDK failures, but
failed the old stop oracle and missed its scheduled reconnect; its separate
record remains FAIL. The successful repeat uses the identical firmware hash.

The final 437.332 s load/fault/recovery window includes 121 full Reads/20691
attribute reports and 60 initial/rebuilt Subscribe snapshots, with five fabrics
and 15 protected sessions/subscriptions verified after rebuilding. Two tracked
OOM injections and one 3-second RX-loss window are consumed; one ended
subscription is detected in each fault category. Rebuilds are counted, not
presented as uninterrupted delivery. Healthy operation errors and unexpected
subscription closures are zero. A real Wi-Fi stop/start and full workload
rebuild pass; all five reconnect-window Reads complete. The periodic branch is
exercised. The new fallback enforcing a reconnect after the timed window is
statically reviewed but not separately forced in this successful repeat.

Stop observes a held accepted TX, waits 3.581 s and drains to zero tracked live
allocations/bytes with SDK heap integrity passing. The final Read is deliberately
rejected after stop and reported separately. The successful run observes 2616 B
owner stack use of 12288 B reserved; both attempts of this final firmware together
observe 2696 B. Baseline observes 2728 B. Minimum sampled largest free block
improves 8448 ->30720 B; final teardown has 390104 B free,303104 B largest block
and 31680 B in SDK/global resources. This is not a global zero-heap claim.

All four fixture fabrics are removed with acknowledged responses; the original
fabric and durable label are restored. C6 is left in its controlled stopped
loop after `RUNTIME_PASS`; resetting starts the RGB lab again. COM23 is released.
Windows returns to disconnected Wi-Fi, with the temporary profile/private XML
removed. IPv6 remains enabled as requested; router configuration is unchanged.

Platform: C6FH4 rev0.0, 4 MiB/no PSRAM, native IDF 6.1, Mbed TLS 4.1.0 software ECC,
mDNS 1.12.0, Matter.js 0.17.9. All compared RGB images use the optional Memory15
Wi-Fi flash-code profile. Driver pools, 128 events, 56 slots, five fabrics, three
protected sessions/subscriptions per fabric, packet and persistence ceilings
remain unchanged. Project defaults are not silently changed.

Owner heap sampling is nominally 100 ms; blocking crypto/SDK widens gaps. Tracked
allocation-event peaks include instrumented library/ports/RGB, excluding SDK/PSA
and uninstrumented fixtures. System heap already includes task stacks; never add
these peaks together. SDK regional low-water sums are not coincident samples.
Largest block depends on regions. Neither this model nor this window establishes
universal RAM/fragmentation bounds or a fresh one-hour endurance result.

## Validation and reproduction

Final Linux CTest 97/97 passes normally and 97/97 separately under
ASan/UBSan/LSan. Focused snapshot/shared-report/RGB Memcheck cases each have zero
errors/live blocks. Two-instance three-phase/meter-services network acceptance
passes 6/6 under Memcheck and separately 6/6 with sanitizers; stderr is empty.
Final Windows focused IM/dispatch/runtime/RGB passes 17/17. Before compaction,
full Windows CTest passes 97/100 in the sandbox; the exact three UDP failures
pass 3/3 with local network access. An initial Clang 23 attempt stops on an upstream
pinned Mbed TLS `x509_crt.c` diagnostic; GCC builds do not patch that dependency.
Final C6 RGB/soak and default non-RGB/non-soak compatibility builds compile.
New GCC diagnostics are absent; SDK CMake/Kconfig notices remain in raw logs.

Coverage includes both snapshot allocation sites, old references/budgets on OOM,
reference overflow, a real hash collision, saturated-index fallback and reserved
large-value slots. Shared-engine delivery checks 7680 subscription values,
45 arrays/2475 list entries, overwritten provider scratch, frozen read counts
and both ACK/status orders. Existing tests retain ACL/fabric revocation,
status/list chunking, cancel/timeout, atomic publication and fail-safe coverage.
RGB faults every constructor allocation and command scratch, verifies atomic
invalid-command rejection, transitions/stop/pixels and pinned-owner lifetime.
Those constructor faults are the portable model's four allocations, not a
sweep of every internal SDK/RMT allocation.

Use ordinary CMake/CTest, plus `test_im_subscribe_alloc --memory-profile` and
`--memory-shared`. Run a separate sanitizer build, never under Valgrind; retain
the two-instance fixture for real dispatcher/crypto/storage coverage.
For C6 follow the [runtime recipe](../../examples/esp32-runtime/README.md), with
`sdkconfig.defaults;sdkconfig.soak;sdkconfig.wifi-flash;sdkconfig.rgb`, fresh build/
config and private Wi-Fi header. Set `MATTER_SOAK_ATTRIBUTES=171`. Images/backups,
controller state, UART and machine-specific commands stay in ignored directories.

Earlier baseline/pool-only failures and the old final-stop oracle's false
negative remain recorded. Its fixed 300 ms send assumption is replaced with a
warm CASE path and observation of an actually held completion. Short run-mode
windows require a real reconnect afterwards if recovery consumed its scheduled
slot. No change excuses unexpected traffic failures or force-frees pending TX.

Next: consider inlining very short complex values inside existing captured-value
storage, measuring peak/OOM/ACK lifetime before accepting the representation.

## Changed files

- `model/matter_im_snapshot_internal.h` and new
  `model/matter_im_snapshot_pool_internal.h`: shared immutable bytes, bounded
  index/private fallback and common reference/OOM cleanup.
- `model/matter_im_read.c`, `model/matter_im_subscribe.c`: internal pool binding
  and smaller stable result records, preserving existing delivery gates.
- `runtime/matter_dispatch.c`: per-runtime pool ownership, binding and deletion
  guard; `cmake/sources.json` records the new private header.
- `examples/esp32-runtime/main/rgb_light.[ch]`, `rgb_led.[ch]`, `app_main.c`,
  `Kconfig.projbuild`, `CMakeLists.txt`, `sdkconfig.rgb`: optional model, owner
  scheduling, GPIO8/RMT lifecycle and allocator profiling.
- `examples/esp32-runtime/tests/rgb.mjs`, `soak.mjs`: independent selected-command
  oracle, 171-attribute envelope, deterministic reconnect and held-TX observation.
- `tools/matter/tests/test_im_snapshots.c`, `test_im_subscribe.c`,
  `test_subscribe_memory.h`, new `test_rgb_light.c`, `cmake/test-cases.json` and
  `cmake/tests/CMakeLists.txt`: storage/model/OOM/ACK tests and registration.
- Root/runtime READMEs, status, test inventory and this report/results: measured
  scope, reproduction, earlier failures and remaining lighting limitations.
