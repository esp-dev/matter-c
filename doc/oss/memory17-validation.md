# Memory17: inline short snapshots and packet-buffer audit

Baseline: `16fe40d` (committed Memory16). Public APIs, provider DTOs, wire and
checkpoint formats, admission ceilings, fabric/fail-safe logic and scheduling
ownership are unchanged. This is laboratory validation, not CSA acceptance.

## Snapshot representation and publication

Validated anonymous TLV values of at most eight **encoded** bytes live in the
existing captured-value union. This includes empty ARRAY/STRUCTURE, UTF8/BYTES
with at most six payload bytes, and small containers. The private type/inline
length fit beside DataVersion; C6 records remain 16 B (Read item 32 B, Subscribe
item 16 B). Scalars retain full signed/unsigned 64-bit storage and versions.
Values of nine or more encoded bytes retain the private/shared allocation path.
The existing sharing threshold, bounded index and full-index fallback are intact.

Read and Subscribe use the same copy/store/load/release helpers. Each transient
heap workspace adds eight bytes of encoding scratch, never a per-value heap
allocation or shared static buffer. Encoding and validation precede publication;
only success advances the cumulative byte count. Every report still accounts
for inline bytes against its unchanged 16384-byte budget, independently of the
512-result and 4096-byte/value ceilings. OOM on the larger-value fallback leaves
published snapshots and accounting intact. Error/omitted provider results do
not copy unvalidated bytes into captured storage.

The caller immediately transfers short bytes from scratch into its stable result
record. Loading derives the data address from the current record: Read compaction
cannot retain a self-pointer to an old cell. Packing and list continuation also
use the common data/size accessors, including tiny ARRAYs split into REPLACE/ADD
reports with small output capacities. Provider/scratch overwrite therefore
cannot alter the report. Subscribe retains captured records through its existing
MRP-plus-IM gates, cancellation and drain/delete. Read continuation releases only
consumed values after both gates. On final Read sent, the existing metadata release
also releases inline bytes: no continuation can use them and independent immutable
MRP ciphertext already owns transmission/retries. External value/event references
retain their confirmation/cancel/drain lifetime. The temporary provider view is
cleared when those final records are discarded. No TX retention gate is weakened.

## Packet-buffer audit

| Storage | Current use/lifetime | Decision |
| --- | --- | --- |
| Dispatcher inbox, 1232 B | Copies a borrowed UDP callback datagram until process admits/authenticates it | Keep separate from work/TX buffers |
| Secure RX plaintext, exact allocation | Authentication plus synchronous admission; cleared/freed after RX copies it | Already on demand; no global replacement |
| RX service bytes, 1232 B | Owns admitted protocol bytes while ACK/admission may defer delivery across process calls | Keep unchanged; public receive contract permits caller reuse |
| Dispatcher delivery, 1232 B | Owns the payload beyond the RX deliver callback, through synchronous dispatch/handler receive | Keep unchanged; public callback only lends bytes during the call |
| Dispatcher plain, 1232 B | Temporary header/body composition before sealing each transaction packet | Candidate for phase reuse with delivery, after handler consumption and reentry guards are tested |
| Unsecured standalone ACK | Exactly 10 protocol bytes plus the existing 16-byte ephemeral-ID envelope | Shrink 1232 ->26 B; retain separately through actual UDP completion |
| Secure channel control buffer, 38 B | ACK/CloseSession ciphertext through actual UDP completion | Keep unchanged |
| Transaction ciphertext, exact allocation | Immutable across MRP retries, peer ACK/cancel and outstanding UDP completion | Keep existing ownership/drain gates |
| IDF RX FIFO | Application-owned stable demand-grown slots, maximum eight; idle trim | Keep existing policy/limits |

The ACK sender's sole producer emits a ten-byte standalone ACK. The dispatcher
now explicitly checks that size before unsecured framing/counter consumption.
The ordinary 1232-byte datagram limit is unchanged. ACK remains available without
a new allocation/OOM site. C6 dispatcher falls 8296 ->7096 B: the raw byte-array
reduction is 1206 B, while structure alignment makes the actual saving 1200 B.

No simple union of inbox/delivery/plain/ACK is introduced. Pending ACK can
coexist with new ingress and normal TX preparation. RX and delivery currently
cross different callback contracts. Secure seal writes its envelope before
calling the crypto port, whose API requires disjoint input/output;
direct/in-place composition needs explicit backend tests and contract work.
The audit establishes possible follow-up work, not a proven additional 1232-byte
saving. In particular, delivery/plain phase reuse need not require in-place
crypto: output can remain the independent transaction packet. PASE/CASE and
server IM receive paths copy their input; client parsing/BDX consume it
synchronously. A follow-up must cover every callback/early return, avoid reuse
until dispatch returns, and guard reentry before accepting that union.
Transaction bindings are outside this change; TimedRequest currently
constructs Invoke and Write together, so a blanket union would be unsafe.

## Component measurement

Same fresh baseline/final host harness: fifteen 512-value subscriptions across
five fabric identities plus five simultaneous Reads, each containing nine large
arrays (55 list entries per array). Providers are poisoned after capture; all
results, ordering and both ACK/status orders are checked. Requested bytes exclude
libc allocation headers, tracker/fixtures, other runtime/SDK owners and the same
272 B fixture index in both versions. Thus these are component peaks, not C6 RAM
requirements.

| Short workload (8 encoded bytes/value) | Memory16 | Memory17 |
| --- | ---: | ---: |
| Captured subscriptions |472560 B|349680 B|
| Plus five outstanding Reads |524401 B|401521 B|
| Halfway through delivery |461491 B|401251 B|
| Idle subscriptions |157410 B|157410 B|
| Allocation-event peak |526729 B|403857 B|
| Live captured allocations |8700|1020|

Peak saving is 122872 B (23.33%). Capture removes 7680 individual payload
allocations; result blocks still allocate on demand. This reduces allocation
pressure without claiming a platform-independent fragmentation percentage.
The original 32-byte shared-value workload remains 637577 ->637585 B peak
(+8 B temporary workspace), with identical capture/idle values and allocation
counts. All-long values do not benefit from the inline path; that small transient
cost is explicit. Largest host allocation remains 4800 B.

## Target layout and stack

Linked C6 DWARF verifies Read/Subscribe owners remain 312/368 B, captured value
16 B, Read item 32 B and persistent Subscribe item 16 B. Their heap workspaces
change 1712 ->1720 B and 1912 ->1920 B. Snapshot-copy frame remains 128 B;
Read/Subscribe process frames remain 48/32 B. Final ACK/dispatcher process frames
are 80/160 B. These individual compiler frames are not complete call-chain or
RTOS stack bounds. No new packet/value array is allocated on the task stack.

## Physical C6 comparison

COM23, existing TL-MR3020 AP, native IDF 6.1 and the same 171-attribute RGB model.
The existing Memory16 binary is verified byte-for-byte against the backed-up
application region before its run. Memory17 replaces only the application at
0x50000; NVS/partition layout is retained. Both runs execute the same pinned
RGB and concurrency oracles, with five fabrics, 15 protected CASE sessions and
subscriptions, five concurrent full Reads, tracked OOM, three-second deliberate
RX loss, actual radio reconnect and an observed held accepted-TX completion.

| Observation | Memory16 | Memory17 |
| --- | ---: | ---: |
| Maximum sampled internal heap allocated |362408 B|358332 B|
| Allocation-event tracked peak |269832 B|266120 B|
| Minimum sampled heap free |54704 B|59604 B|
| Minimum sampled largest free block |31232 B|35840 B|
| Maximum allocated blocks at SOAK checkpoints |1254|1018|
| Maximum free blocks at SOAK checkpoints |106|105|
| Observed owner stack used / reserved |2616 /12288 B|2616 /12288 B|
| SDK failed allocation attempts |0|0|
| Final tracked live allocations / bytes |0 /0|0 /0|

Observed sampled heap saving is 4076 B (1.12%), tracked saving 3712 B (1.38%).
This is a smaller whole-node gain than the synthetic all-short-value component
because most actual model values are scalars or longer values. The minimum
largest free block increases 4608 B; this and observed block counts are allocator
pressure indicators, not a certified fragmentation percentage or general bound.
Final SDK/global heap still owns 31660 B in both runs; tracked zero is not global
heap zero. SDK heap integrity succeeds before each `RUNTIME_PASS`.

Both runs complete 71 full Reads (12141 attribute values), one consumed tracked
allocation fault at position 1, one loss window, one radio reconnect, a protected
fourth-session rejection and one held-TX stop. Reconnect-window Reads are 5
fulfilled/0 rejected in each. Stop waits 3.783/3.746 s for actual completion.
The final intentionally outstanding Read rejects after stop; it is not counted
as a healthy-operation error. Healthy errors, unexpected subscription closures
and recovery BUSY retries are zero.

The nominal load window is 180 s, extended by fault recovery/reconnect to
351.360 s baseline and 277.530 s final; controller runs take 550.334/475.628 s.
OOM loses one subscription in each run and the oracle rebuilds the full load.
Deliberate packet loss loses one baseline subscription and none in the final
run: that extra baseline rebuild yields 60 vs 45 initial/rebuilt snapshots,
40 vs 30 full CASE pairs and 40 vs 30 resumptions. These are consecutive short
runs, with different recovery timing, not equal-duration statistical peak or
latency guarantees. Both explicitly exercise the post-window reconnect fallback
which remained unforced in Memory16's previous successful run. This is not a
new one-hour endurance qualification.

The four fixture fabrics are removed with acknowledged replies; original fabric
and durable label are restored. Windows returns to its initially disconnected
Wi-Fi state, temporary profile and private XML are removed, and IPv6 remains
enabled. The router configuration is not changed. Collector exits successfully,
releasing COM23; C6 stays stopped after `RUNTIME_PASS`, and reset starts the new
RGB laboratory firmware again. The AP is released for other tests.

## Validation

Final Linux CTest passes **98/98** in the normal build and **98/98** separately
with ASan/UBSan/LSan. Four focused Memcheck executables (snapshot storage,
Read allocation/chunking, Subscribe allocation/chunking and dispatcher ACK/TX)
finish with zero errors, zero live bytes/blocks and no suppressions. The complete
two-instance three-phase/meter-services network scenario passes **6/6** under
Memcheck and independently **6/6** with sanitizers; node stderr is empty.

Windows full CTest passes **101/101** with the final production sources. A later
fixture-only CASE change is rebuilt and checked separately **2/2** (CASE and
its allocation variant). The final two memory-profile CTest cases also pass.
Native IDF 6.1 RGB/soak and default non-RGB/non-soak builds both pass. GCC logs
contain no new compiler warning/error diagnostics; existing SDK CMake/Kconfig
notices remain. The inventory check passes: 257 mapped files, 98 native
manifest definitions, 59 core sources and 75 closed public headers. Platform
exclusions and extra profile/package/inventory registrations account for the
different CTest totals.
All 511 applicable frozen VM build/test inputs match local hashes; 187 public
C6 inputs are recorded separately. There is no remote push or CSA reclassification.

Earlier failed allocation-count assertions are retained in ignored evidence:
they expected payload nodes now removed by the inline representation. Corrected
assertions still check MRP/IM gates, cancellation, timeout and cleanup. Final
review additionally found raw span access in list continuation; shared accessors
and tiny ARRAY REPLACE/ADD regressions repair that intermediate implementation.

An intermediate Linux CTest run fails at the existing CASE resumption fixture
(`resume_cache_tests`, old line 174). It copied a random ID and assigned byte zero
0xfe for another fabric: if the original byte was already 0xfe, the supposed new
ID collided and production correctly rejected it. Assigning first bytes 0..4 in
the later eviction fixture could collide too. Only the test now flips byte 15;
that creates a separate namespace for every random source ID, leaving the
intentional collision-rejection test intact. A private baseline fixture forcing
the original first byte 0xfe deterministically reproduces the old failure and
passes with the corrected fixture, using the same unchanged CASE product code.
Failed/intermediate harness logs are preserved; they are not reported as passes.

## Changed files

- `model/matter_im_snapshot_internal.h`, `matter_im_read.c`,
  `matter_im_subscribe.c`: common inline capture/access/release, heap scratch,
  list continuation and final-view cleanup, preserving public DTOs and limits.
- `runtime/matter_dispatch.c`: bound standalone ACK storage to its producer's
  fixed encoded envelope and preserve pending-send ownership.
- `test_im_snapshots.c`, `test_im_complex.h`, `test_im_values.h`,
  `test_subscribe_complex.h`, `test_subscribe_lists.h`, `test_subscribe_memory.h`,
  `test_im_subscribe.c`, `test_dispatch.c`: lifetime/OOM/8-to-9-byte boundaries,
  tiny-list reconstruction, stronger ACK checks and identical baseline/final
  workload measurements. No new product default is selected.
- `test_case_resumption.h`: deterministic fixture identities after a real
  regression-suite failure, without changing resumption implementation.
- `cmake/tests/CMakeLists.txt`: register the short-report profile. Root README,
  status, test inventory and this report/results record scope and actual evidence.

## Reproduction and limits

- Configure/build with the repository CMake instructions; run CTest, including
  `test_im_short_reports` (`test_im_subscribe_alloc --memory-short`).
- Compare the same `--memory-short` and `--memory-shared` harness against Memory16
  core sources; do not compare different provider sizes/models as one workload.
- Run Linux two-instance `chip_tool_three_phase.py` with source registers/meter
  services under Memcheck and separately ASan/UBSan/LSan. Preserve credentials and
  controller state in ignored/private laboratory directories.
- Build `examples/esp32-runtime` with native IDF 6.1 and the same defaults, soak,
  wifi-flash and RGB configuration as Memory16. Flash only the application at
  0x50000 after a full private backup, retaining NVS/partition layout. Use COM23,
  the existing test AP and the pinned Matter.js 0.17.9 oracle with 171 attributes.

Sampling can miss blocking crypto/SDK transients. Stacks are already counted in
system heap. Tracked OOM does not enumerate every SDK allocation. The synthetic
512-result workload is not promised to fit C6 internal RAM. The RGB profile is
still incomplete, with no full lighting-conformance/certification claim.

**One next task:** implement guarded phase reuse of dispatcher delivery/TX
plaintext storage, proving handler consumption, callback reentry, immutable
ciphertext and ACK/drain before accepting the additional saving.
