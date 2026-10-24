# Memory36: settled heap and SDK allocation islands after fault teardown

This investigation compares the unchanged Memory34 (`b7289d2`) and Memory35
(`38519e9`) cores on C6 COM23. It changes offline analysis and optional laboratory
attribution only; there is no core protocol change, normal-image allocator
change, Matter resource-limit change or new SDK cleanup. Existing ACK/MRP, accepted-TX
completion and drain stay intact.
Source-matched final measurements are collected in [results](memory36-results.json).

The reproduced large drop is explained by a **16-byte lwIP timeout node**, not
retained Opcreds workspace. Exact-ELF pool attribution identifies
`MEMP_SYS_TIMEOUT` from `sys_timeout_abs`. It separates two large free spans for
at least five seconds after Matter has fully drained. Between the 5 s and 15 s
samples it disappears, total free increases only 20 B, and the largest allocable
block rises **147456 -> 286720 B**. Three other SDK timeout nodes remain live.
SDK timer lifetime/placement and persistent SDK locks therefore need separate
accounting from core live bytes. The historical 151552 B snapshot has no map;
this run proves the mechanism rather than identifying that old address retroactively.

## Controlled comparison

Each run restores the same fresh pre-test NVS and matching private controller
state. Normal images are the exact retained Memory34/35 binaries. Separate
diagnostic builds use pristine exports of the committed sources, the same
IDF 6.1 SDK/configuration and TL-MR3020, with UART at 1000000 baud. COM24 is not
used. The baseline exports contain 836 and 839 tracked files respectively;
their C/H content matches the previously tested normal-image source copies
after newline normalization. Source and binary/ELF hashes are retained.

The workload uses five fabrics, 15 CASE sessions, 15 wildcard subscriptions,
full 171-attribute Reads, one global OOM, RX loss, reconnect and explicit held-TX
completion at final stop. Its corrected diagnostic peer and all existing limits
are unchanged. Final stop pumps the original runtime retirement/MRP drain before
deleting runtime, transport, mDNS, backend, Wi-Fi and the SDK event loop.

Diagnostic profiles are kept separate:

* Heap-map builds enable only `MATTER_C_RUNTIME_HEAP_AUDIT`. They sample after
  teardown immediately and at nominal 20/100/500/2000/5000 ms, then paginate the
  heap with eight descriptors at a time. Writable static sections do not grow
  relative to their normal image. Actual elapsed times are recorded.
* Owner-attribution builds additionally enable the existing
  `MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS` wrappers. Their static metadata adds
  1544 B of BSS. They record queue/mutex initialization or first lock callers,
  with explicit table overflow detection. They identify owners, not normal-image
  headline RAM use; their changed layout must not be mixed into that comparison.
* Small-allocation owner builds additionally enable
  `MATTER_C_RUNTIME_HEAP_SMALL_OWNERS`, default off. The same table grows to
  1024 entries (12296 B BSS relative to normal) and records callers of requests
  up to 32 B through malloc/calloc/realloc and their corresponding caps APIs.
  Both free APIs remove identities; successful resize replaces the old identity,
  failed nonzero resize preserves it. Addresses are saved as integers before
  realloc, avoiding use of freed pointer values. No tracked payload is read.
  The final probe adds small lwIP pool identity (kind `64 + memp_t`), reading only
  static pool descriptors. This build uses heap-backed pools without an overflow
  prefix, so returned pool payloads match the walked allocation addresses.
* One additional Memory35 fault run enables
  `MATTER_C_RUNTIME_HEAP_SETTLE_LONG`, default off: samples at 15/30/65 s and
  maps at 5 s, 65 s and after owner cleanup. It has the same 12296 B BSS cost.
  No SDK/protocol timer is shortened or cancelled by the diagnostic.

The first map exposes a 16-byte allocation between large free spans, so the
final owner images extend the optional wrappers to record pthread's per-task
TLS list head (kind 5), not only queues/locks. IDF 6.1's inspected
`pthread_local_storage.c` owns FreeRTOS TLS slot 0. After successful
`pthread_setspecific`, the diagnostic records that head and its first setter's
return PC, never keys, values or payload contents. A `free` wrapper forgets
records before address reuse. The same bounded table/guard is reused, with no
allocation/formatting inside it. Normal/map builds exclude these wrappers.
The two provisional queue-only owner builds are retained. TLS-only owner runs
locate their tracked list heads elsewhere and leave the critical 16-byte block
unattributed, so two additional small-allocation runs are required. An initial
small-owner build is retained before the integer-address realloc refinement;
only the refined small-owner binaries are flashed. These diagnostic tables
affect placement and timing; none supplies a normal-image peak comparison.

Within each paired profile Memory34/35 SDK defines and writable allocated sections
match. No global SDK mutex is manually deleted. The existing public
`lwip_socket_thread_cleanup()` still runs only after the owner's last network use
and full teardown. Diagnostic `q` completion includes the extra five-second
settle/map interval (65 s in the last probe); it is not protocol drain latency alone.

## Reproducible map validation

`examples/esp32-runtime/tests/heap_audit_decode.py` consumes completed UART event
logs without touching the board. It rejects missing/duplicate footers, orphaned
pages, count mismatches, unstable/incomplete maps, invalid block ranges/flags,
duplicate/overlapping blocks, inconsistent region bounds, fingerprint mismatch
and queue-attribution overflow. It recomputes the firmware's FNV fingerprint in
captured walk order, rather than trusting only the printed stable flag.

For each region it identifies allocated islands between consecutive free spans,
and reports the actual walked spans separately from the SDK largest-free-block
API. With the exact ELF/toolchain it resolves recorded return PCs (one byte back
on RISC-V) to their SDK caller. ELF hashes and source-root normalization are
included; symbol resolution alone cannot prove the ELF was flashed.

The offline unit suite covers separating mutexes, malformed/truncated/unstable
maps, fingerprint corruption, invalid ranges/flags, duplicates/overlap, missing
footers, orphaned pages, inconsistent regions, attribution overflow and settled
deltas, stale attribution and owner-thread cleanup differences (14 test methods).
The long-settle test keeps the 5..65 s SDK changes separate from subsequent
owner-thread cleanup.
It also decodes the existing Memory21 complete/owner-cleaned
maps using their retained exact ELF/binary pair, resolving all 26 recorded SDK
call sites, including RMT and MPI. Raw
heap addresses, full UART, controller/device states and AP information stay in
ignored lab output; public summaries use region-relative offsets and sizes.

## Results

Original normal binaries complete the full fault workload with no healthy
operation errors, no unexpected subscription closures, no SDK allocation failures
and zero core live bytes after ACK/drain. Each global OOM ends one subscription
and rebuilds full 15 load. The repeat is not a fixed 151552-byte outcome:

| Image/run | Cleaned whole free | Largest free block |
| --- | ---: | ---: |
| Historical Memory34 fault | 390200 B | 258048 B |
| Memory36 repeat of exact Memory34 binary | 390200 B | 233472 B |
| Historical Memory35 fault | 390188 B | 151552 B |
| Memory36 repeat of exact Memory35 binary | 390216 B | 221184 B |

Thus a smaller largest block is a real per-run fragmentation observation, but
is not a fixed retained allocation equal to the historical difference. Total
free and core ownership must be checked separately. These finite repeats do not
establish a statistical distribution or exclude effects of core allocation order
on SDK placement. The same workload includes fresh commissioning randomness and
SDK task scheduling, rather than an identical allocator call trace.

Historical Memory35's 151552-byte post-fault largest block remains valid; a later
run cannot retroactively attribute its unrecorded heap map. The normal-repeat
comparison above is separate from the instrumented measurements below.

The map-only fault runs both complete successfully. Waiting for SDK tasks does
not coalesce the largest region:

| Map-only run | Elapsed settle | Immediate free -> settled free | Largest immediate / settled | After owner cleanup free |
| --- | ---: | ---: | ---: | ---: |
| Memory34 | 5007 ms | 390076 -> 390080 B | 180224 / 180224 B | 390196 B |
| Memory35 | 5007 ms | 390076 -> 390104 B | 212992 / 212992 B | 390216 B |

Both have five tasks after teardown and zero tracked core live allocations.
There is some small deferred SDK activity (4/28 B), rather than a delayed return
of tens of kilobytes. Supported owner-thread cleanup subsequently recovers
116/112 B respectively, removing two walked allocations (92+16 or 92+12 B,
plus allocator headers), with no change in largest free block. The declared
lwIP semaphore address matches the removed 92-byte block. The other removal is
consistent with the inspected pthread TLS value-entry cleanup; its allocation
caller is not directly traced in the map-only image.

The largest walked free span is 183440 B in Memory34 and 214732 B in Memory35,
distinct from the API's 180224/212992 B. IDF `multi_heap_get_info_impl` passes
the walked maximum through `tlsf_fit_size`, which rounds it to the allocator's
usable GoodFit interval. This is not evidence of extra leaked bytes.

In both map-only captures a 16-byte used block separates the largest span from
another large free span (52056 B in Memory34, 47824 B in Memory35). Waiting and
lwIP owner cleanup leave that separator allocated. Exact-ELF TLS/queue owner
attribution comes from the separate diagnostic images; a 16-byte block must
not be labelled as a 92-byte mutex merely because Memory21 found mutex islands.

## The separating allocations

The long Memory35 probe reproduces the low-largest-block shape at 5 s and directly
tags its critical allocation as `MEMP_SYS_TIMEOUT` (pool enum 12, recorded kind 76).
DWARF confirms `struct sys_timeo` is 16 B. The allocation caller is
`sys_timeout_abs` at `components/lwip/lwip/src/core/timeouts.c:192` in the pinned
IDF. This identifies the object by its pool, caller and location; other 16-byte
SDK allocations from task-watchdog initialization are elsewhere in the same map.

```mermaid
flowchart LR
    A["free: 138184 B"] --> T["lwIP timeout: 16 B"] --> B["free: 148884 B"]
```

After that node is released, the adjacent spans coalesce to 287092 walked bytes,
including recovered allocator headers. The API reports 286720 B. This is why
freeing 20 B of allocation accounting can improve the largest block by 139264 B.

| Long probe phase | Actual elapsed after immediate | Whole free | Largest allocable | Allocated blocks |
| --- | ---: | ---: | ---: | ---: |
| Immediate | 0 ms | 377752 B | 147456 B | 99 |
| 5 s | 5007 ms | 377752 B | 147456 B | 99 |
| 15 s | 15007 ms | 377772 B | 286720 B | 98 |
| 30 s | 30007 ms | 377772 B | 286720 B | 98 |
| 65 s | 65007 ms | 377772 B | 286720 B | 98 |
| Owner thread cleaned | 65350 ms | 377884 B | 286720 B | 96 |

The maps are complete/stable with recomputed fingerprints. The three remaining
`MEMP_SYS_TIMEOUT` allocations are still present at 65 s. The exact-ELF compiled
cyclic table contains TCP 250 ms and ARP/DHCP-coarse/ND6 at 1000 ms. The generic
header's 60-second DHCP default is not the compiled period in this image. The
65-second observation is a longer stability check, not proof that every possible
SDK timeout is bounded by 65 s. No individual handler/deadline was read from the
released timer payload, so its precise expiration/cancellation path is not
assigned from this data.

Other identified SDK islands include:

| Observed walked size | Owner/site | Lifetime/impact observed |
| --- | --- | --- |
| 92 B | `rmt_acquire_group_handle`, `esp_driver_rmt/src/rmt_common.c:30` | Global platform mutex survives channel/group release; separates 43052/248760 B in Memory34-small and 39024/250332 B in Memory35-small. |
| 92 B | `esp_crypto_mpi_lock_acquire`, `esp_security/src/esp_crypto_lock.c:117` | Persistent SDK MPI lock in a smaller lower-region island. |
| 24 B | `get_desc_for_int`, `esp_hw_support/intr_alloc.c:201` | IRQ registry descriptor next to that lower-region island; SDK interrupt free retains the vector registry. |
| 12 B in captured examples | `pthread_key_create`, pthread TLS list/value sites | Separate small SDK objects; the TLS-head hook alone did not identify the critical 16-byte object. |

Queue/TLS attribution has no overflow; small/pool attribution also has no
overflow or stale free-block identity. Some larger/special SDK objects remain
outside this targeted tracer (for example an unassigned 60-byte lower-region
allocation). This is attribution of the consequential splits, not an exhaustive
inventory of every SDK allocation. SDK source confirms RMT/MPI locks persist as
platform resources; there is no attempt to delete them or global lwIP timers.

## Regression and restoration

All nine full fault runs pass the oracle and final zero-live drain: two exact
normal-image repeats, two map-only, two queue/TLS owner, two small-owner and one
long/pool probe. Every run uses the original limits and injected core OOM/RX
loss/reconnect/held completion. Healthy-operation errors, unexpected subscription
closures and SDK allocation failures are zero. Counts/timing differ across the
instrumented runs: Memory35-small retains subscriptions through its global OOM;
other runs rebuild one after OOM. The long probe also rebuilds one subscription
after deliberate RX loss. Those expected recovery branches are retained in the
results instead of assuming every diagnostic trace has identical timing.

Both final conditional configurations compile: all diagnostic hooks off, and
the 128-entry queue/TLS mode. Off-mode DRAM data/BSS match the normal baseline;
128-entry mode adds 1544 B, and the 1024-entry modes add 12296 B. No compiler
warnings/errors are present in the completed builds. The SDK tracked tree stays
clean at commit `fff9895c82d744c7237be8847347bdd1b07c6643`.

All profiles reserve 12800 B for the owner task; maximum observed use across the
matrix is 3288 B. The long probe uses 3272 B. Compiler frames include 240 B for
the diagnostic map, 96 B for long settling, and at most 32 B per new wrapper/helper.
The bounded page assertion still limits the descriptor structure to 224 B;
compiler spill/call frames are additional. No new large task-stack buffer or
trace-buffer heap allocation is introduced. These are observed watermarks and
individual frames, not a full worst-case stack proof.

Normal Memory35 firmware and the fresh pre-Memory36 NVS are restored. Original
controller RGB verification passes, exactly one original fabric remains, and
final accepted-TX/ACK drain reaches zero core live allocations. COM23 and the AP
are free; COM24 is untouched. The temporary Wi-Fi profile/XML are removed and
Windows IPv6 remains enabled.

## Scope, validation and limits

Changed files:

* `examples/esp32-runtime/tests/heap_audit_decode.py`: checked offline map/owner
  decoder, needed to identify and compare the separating allocations.
* `examples/esp32-runtime/tests/heap_audit_decode_test.py`: corruption and
  settled-delta checks without device/SDK dependencies.
* `examples/esp32-runtime/main/heap_queue_owners.c`, main CMake and Kconfig:
  optional TLS-head/small-allocation attribution and stale-record removal
  alongside existing queue tracing, needed to identify the non-queue separator.
* `examples/esp32-runtime/main/heap_audit.h`: optional post-drain 65-second
  observation, retaining the original five-second default and callback bounds.
* `examples/esp32-runtime/README.md`: commands, exact-image requirement and
  diagnostic interpretation.
* README, status, this report and results JSON: measured comparison, provenance,
  limitations and follow-up.

Commands used include the workspace IDF wrapper for seven measured diagnostic variants
(plus retained provisional queue-only and pre-refinement small-owner builds),
`python -m esptool ... read-flash/write-flash`, UART capture at 1000000 baud,
`rgb.mjs`, `soak.mjs ... 180 Wi-Fi run wildcard`, the offline unit suite and
decoder, test inventory checking and Git diff checking. Complete per-run
arguments and logs remain in ignored output. Initial sandbox SDK tool discovery
failed to load dfu-util's DLL before compilation; the same builds completed
outside the sandbox without SDK/tool installation or configuration changes.

No runtime host implementation changes are made, so the Memory34/35 full host
Memcheck/separate ASan/UBSan/LSan results are inherited, not rerun or relabelled
as new Memory36 host tests. There is no new official CSA, Apple/Google Home
pairing or reference ESP-Matter comparison. Finite samples and paginated maps
are not an exhaustive allocator trace or specification-wide memory bound.

Next task: evaluate a supported, bounded startup order for the persistent RMT
platform allocation before large Matter allocations, then measure serving peaks
and long-settled largest blocks again. The timeout-node result changes the
measurement baseline; it does not justify cancelling SDK timers or freeing
foreign global resources.
