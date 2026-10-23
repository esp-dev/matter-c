# Memory29: normal C6 peak and allocation-site attribution

Memory28 is committed as `9fd7ead`. Production core C, resource limits,
persistence format, snapshots and ACK/drain behavior are unchanged here.
The shared physical controller gains a fixed-workload memory profile and a
common own-fabric-removal operation; the allocator observer is generated only
into an isolated laboratory copy. COM24/reference firmware is untouched.

## Workload and normal image

IDF 6.1, ESP32-C6-DevKitM-1 on COM23, UART 1000000 and TL-MR3020 use the RGB
profile with five fabrics, 15 CASE sessions and 15 wildcard subscriptions of 171
attributes. The explicitly corrected diagnostic Matter.js 0.17.9 peer is labelled
in every result; the initial RGB smoke and final restore use the unmodified peer.
After setup the fixed profile runs three rounds of five parallel full Reads,
three UpdateFabricLabel publications on a disposable fabric concurrently with
five Reads, then four own-fabric removals with live sessions/subscriptions and
Reads on the surviving fabrics. Every phase verifies target counts and health.
The shared close/trim path and actual held-TX stop still drain before deletion.

The normal profile passes 296.303 s:51 full Reads, 15 initial subscription
snapshots,45 updates, three parallel-read rounds, three publication rounds and
four live removals. There are zero healthy-operation errors, unexpected
subscription closures and SDK allocation failures. Stop waits 3.591 s for actual
completion. The fixed-operation profile does not use the duration argument as
a timed soak; no OOM is injected here. Memory28 supplies the physical OOM/loss/
reconnect regression on this unchanged production core.

|Normal image metric|Bytes|Meaning|
|---|---:|---|
|Whole internal 8-bit heap peak, SDK timer|357652|Maximum observed at 100 ms sampling|
|Minimum free heap, SDK timer|58520|Minimum sampled, not a guaranteed reserve|
|SDK minimum-free watermark|57288|Separate region watermark aggregate|
|Minimum sampled largest free block|33792|Contiguous allocation headroom at worst sample|
|Owner-loop heap peak|354388|Misses some blocking SDK/crypto peaks|
|Tracked C-core block peak|262884|Application allocator, excludes unrelated SDK allocations|
|Owner task reservation|12800|12288 configuration plus 512 IDF bytes|
|Owner minimum unused stack|9512|Observed watermark|
|Owner observed stack use|3288|Reservation minus watermark|
|Post-cleanup free heap|390212|After the full profile and owner cleanup|
|Post-cleanup largest free block|237568|After the full profile|
|Post-cleanup tracked core allocations/bytes|0|Full drain|

These **whole-heap** observations include Wi-Fi/lwIP, SDK task stack allocations
and other dynamic SDK activity in the same internal 8-bit capability set. Static
D/IRAM is separate. The core counter is a subset and cannot be added to the
whole-heap number. Neither subtracting a region watermark from total heap nor
subtracting independent maxima yields a measured simultaneous SDK/core split.
The timer can miss sub-100 ms peaks; the task watermark covers observed paths,
not all possible call chains or an allowed stack-size reduction.

Earlier owner-loop peaks around334–335 kB use different traffic and sampling;
the present figure is not a matched before/after optimization delta.
This workload is broader than the earlier small-path ESP-Matter comparison.
It is not a new matched C-versus-ConnectedHomeIP measurement and not a
specification-wide worst-case bound. Full concurrent PASE/CASE crypto with all
Read buffers, production Lighting/PICS, other model sizes and SDK configurations
still need separate qualification.

## Separate allocation observer

The first 1024-live-record attempt completed the protocol profile but overflowed
434 times. Its allocation map is **invalid**, retained in the results, and is
not used below. The final compact observer has 2048 live records, 128 call sites
and explicit overflow rejection for any tracked block above 65535 bytes. Its
18956 bytes of static metadata change heap layout/timing, so the normal image
above supplies headline memory figures. Hooks do not allocate, format or inspect
payloads. Dump/decoding happen on the owner thread at phase boundaries.

The repeat passes the same fixed protocol operations294.964 s. All 18 audit dumps
have zero overflow. Each decoded current/peak site sum equals its corresponding
allocator total; final live count/bytes are zero. The exact ELF hash is recorded.
It observes **262332 bytes at the tracked-core byte peak**, a maximum of 1176 live
allocations and 124 call-site slots used. DWARF compilation units disambiguate the
two static block-reserve functions from the shared header.

|Allocation site at simultaneous core-byte peak|Bytes|Live blocks|
|---|---:|---:|
|matter_im_blocks_reserve|74660|288|
|matter_im_blocks_reserve|25104|52|
|matter_fabric_host_image_new|15552|1|
|matter_cluster_new|10488|15|
|report_chunk|9600|4|
|rx_capacity|8988|7|
|matter_im_snapshot_copy|8600|344|
|matter_diagnostics_new|8488|1|
|prepare_packet|8124|15|
|matter_dispatch_new|7064|1|
|matter_acl_new|6384|1|
|matter_ota_requestor_new|5704|1|
|matter_im_subscribe_new|4512|12|
|new_transaction|4488|16|

The first block-reserve group is Subscribe 74660 bytes, the second Read 25104 bytes;
together 99764 bytes. They include result metadata and current captured values,
not only disposable payloads. Counts are allocation blocks, not attributes.
The peak map has twelve Subscribe instances and four Read instances during live
fabric removal; it does not mean every peak contains all fifteen subscriptions.
`report_chunk`9600 bytes is **four Read chunk plans**, not the shared TLV output
pool. Each plan currently has 150 entries of 16 bytes on C6.
The 344 snapshot-copy allocations total 8600 bytes; inline short values already
avoid separate payload allocation.

The unchanged normal-ELF layouts also expose Diagnostics 8488 bytes, ACL 6384 bytes
and Fabric 4224 bytes, each with an encoded 4096-byte array. These three buffers
alone total 12288 bytes. FabricHostImage is 15552, dispatcher 7064. Dispatcher compiler
frames from the source-matched build are process_rx 16, dispatch_process 176,
public process16, process_transaction 144 and send_ack 64 bytes. UDP callback/
process frames are 32 bytes. Per-function frames do not sum into a worst-case task
bound; the normal task watermark above is the separate dynamic observation.

## Reproduction, regressions and cleanup

See the [runtime guide](../../examples/esp32-runtime/README.md) for the opt-in
fixed profile and isolated observer. Executed: IDF 6.1 normal/observer builds,
the normal fixed profile and two observer runs (valid attribution only on
the second observer version),
Python/Node syntax checks, public allocation_decode.py against the complete
C6 trace (exact match to the initial decoded map), explicit overflow, incomplete
dump and missing-site negative controls, DWARF/addr2line sum checks,
check_test_map.py and git diff --check. No new C warning was observed; existing
SDK include-export/Kconfig notices remain. Native 99/99 per Linux build and full
pair 6/6 under Memcheck and separately sanitizers are reused from source-matched
Memory28 because portable C is unchanged. The current shared controller additionally
passes the baseline wire case under each tool variant, with zero-live drain and
zero Memcheck errors/exit allocations. The complete final six-case Memory28
matrix remains the production regression. Windows native102/102 and six wire
cases also remain applicable.

The first normal capture's LOAD_PASS logger counted removed context objects in
its descriptive fabrics/session fields. Target subscription counts, explicit
survivor assertions and protocol operations were correct. The subsequent change
uses active contexts for those two log fields only; source snapshots distinguish
the normal and observer controller revisions. No protocol claim relies on the
old descriptive fields. The first gated Memory29 VM worker stopped when Memory28's
initial ACK-timing coverage check failed; the final worker waited for the repaired
complete matrix and then ran the two current-controller checks. That gate failure
is retained, not reported as a test of this profile.

The original NVS/fabric state and normal image were restored after the observer.
Final RGB smoke with the unmodified peer passes, exactly one original fabric
remains, tracked core allocations/bytes reach zero, and COM23 is released.
The last smoke ends with 390196 bytes free heap and 245760 bytes largest block; it
is a different lifecycle/load from the full profile's cleanup values. The temporary
Windows Wi-Fi connection/profile/XML are removed, Windows IPv6 remains enabled,
TL-MR3020 is unchanged/free and COM24 untouched. Firmware/ELF hashes, counters,
layouts, decoded site map, cleanup and validation provenance are in
[results](memory29-results.json). Raw logs, keys and device states remain ignored.

## Changed files

* `examples/esp32-runtime/tests/soak.mjs`: shared removal/cleanup, active-context
  log counters and explicit fixed-profile selection.
* `memory_profile.mjs`: repeatable overlapping Reads/publication/live-removal load.
* `allocation_trace.py`, `allocation_decode.py`: isolated allocator instrumentation
  and checked symbolization; no production hook/configuration is enabled by default.
* Runtime guide, README/status and this report/results: measured provenance,
  limitations, cleanup and remaining work.

## Remaining work and selected next task

1. **Next selected: common compact Read/Subscribe chunk plans.** Read currently
   stores three size_t indices/offsets plus a bool in 16 bytes per entry on C6.
   Limits 512 results and 4096 bytes/value suggest an 8-byte private representation,
   subject to all assignments and continuation sentinel checks. Four observed
   plans could save 4800 bytes; five concurrent Reads about 6000 bytes, plus small
   Subscribe-work savings. These are gross estimates, not measured savings yet.
   Use a shared private type/helper where meaningful, compile-time bounds and
   explicit conversions. Keep ordering, full attribute IDs, max limits, immutable
   snapshot references, OOM atomicity and ciphertext ACK/drain lifetime. Repeat
   the fixed profile and both host tool variants before claiming a gain.
2. **Sparse Subscribe current-value blocks.** capture currently reserves count
   values before knowing which paths are omitted. The persistent SubItem table
   must remain for path/version bookkeeping. Selectively retaining value blocks
   could save roughly 10–24 kB in sparse update phases; full initial/all-changed
   reports may save nothing. This requires new stable lookup/release invariants,
   OOM and partial-list continuation checks; do not claim the entire 100 kB group
   can disappear.
3. **Cluster encoding/parser workspace lifetimes.** The three 4096-byte arrays
   offer up to 12288 bytes of resident-workspace reduction, with additional tag/
   parser storage worth auditing. Borrowed provider data, reentrant callbacks,
   snapshot capture and publication rollback prevent freeing by callback return
   alone. Peak gain depends on how many workspaces overlap.
4. **Stack calibration and stronger peak envelope.** Observed main-task reserve
   suggests headroom, but do not lower it before exhaustive constructor/OOM,
   crypto/cache and large-value paths. Add concurrent full CASE/PASE and Fabric
   publication coverage; repeated profiles are needed for a credible resource
   budget, not a single maximum sample.
5. **Interoperability/CSA backlog.** Historical Memory23 first-loss attribution
   remains unproven; trace any recurrence. Full Lighting model/PICS, phone-app
   pairing after optimization and formal CSA campaigns remain separate work.
   No new official CSA or certification result is claimed here.
