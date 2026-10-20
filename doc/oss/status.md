# Development status

**Memory11: stable demand-allocated Read/Subscribe result blocks.**
Read results, Subscribe persistent results and report-only values share typed
blocks of at most16 entries. Growth stages new blocks atomically and never copies
or reallocates old storage. Indexed lookup uses an owner-local cache;512-result
limits, filtering/report order, independent immutable packets and ACK/drain
remain unchanged. ESP32 largest Read result requests fall24576 ->776 B, Subscribe
12288 ->392 B, captured-value table8192 ->264 B. Read growth table payload falls
38400 ->24840 B; full steady tables and owners grow slightly. The x86_64
pre-provider512-result Read peak falls54142 ->38558 B (28.8%), node component
625602 ->620266 B, while fifteen full subscription reports plus Reads increase
819313 ->835673 B (2.0%). The largest report request in that workload falls
12288 ->4800 B. These tradeoffs and scoped compiler-derived envelopes are in the
[report](memory11-validation.md) and [results](memory11-results.json).
Windows CTest94/97 plus3/3 local socket retries and7/7 focused checks; Linux
CTest94/94 per build, two-instance6/6 per memory variant, separate saturated
sanitizers and dedicated Memcheck pass. The new block test faults all64 staged
OOM positions and checks old addresses/data/cache/links/capacity and cleanup.
All27 ESP32 probes have no diagnostics. Process frames stay144/192 B; Read's
encoder/compaction and Subscribe's reserve specialization grow16 B each, with
additional nested32-byte accessors. No target stack high-water claim.
Both full-host capacity runs pass50/50; Massif observes389010 B heap,6688 B maximum
sampled used stack and401048 B maximum combined, a small increase over Memory10.
Next: demand-sized event path/selector metadata, now the largest allocation in
the node component. No linked/physical ESP32 or official CSA rerun.

**Memory10: shared event records, compact final Read tails and node reporting budget.**
Private snapshots retain immutable event-node references, preserving bytes and
membership through eviction/removal. OOM/reference overflow preserve old captures;
confirmed prefixes release only after the existing MRP+IM gate. Final Read sent
releases result/selector/plan/RX/TX metadata after the independent packet copy;
remaining snapshots wait for confirmation or owner cancellation/drain. Public
APIs, formats, limits, fail-safe and admission remain unchanged. The heavy
24-subscription/replacement, six-active-Read, fourteen-Read-tail component plus52
explicit packet leases falls2444160 ->625602 B peak (74.4%); full128-record logs
pay1024 B more for references. ESP32 snapshot vectors fall29696 ->512 B, but
different generations retain different nodes. A compiler-derived conservative
reporting/event/dispatcher/TX subtotal is2307996 B with a shared evicted generation,
3672988 B for44 distinct generations, excluding other node/platform resources;
these are additive envelopes, not measured peaks or total/normative RAM bounds.
Linux CTest93/93 per build, two-instance6/6 per memory variant, dedicated Memcheck,
separate component sanitizers and16/1024-capacity4/4 checks pass. Windows93/96 plus
3/3 socket retries and5/5 final focused checks. Both whole-host drivers pass50/50;
Massif observes388288 B heap,6680 B maximum sampled stack and399720 B combined,
essentially unchanged from Memory09 in this ordinary workload. See
[report](memory10-validation.md) and [results](memory10-results.json).
Next: stable demand-allocated expanded-result blocks to reduce contiguous result
allocations/growth overlap. No linked/physical ESP32 or official CSA rerun.

**Memory09: compact report values, consumed-chunk cleanup and transient secure RX.**
Read results use a private scalar/span representation. Subscribe separates
persistent paths/versions from its report-only value table. Complete attributes
release only after their chunk's IM Success and MRP confirmation; partial lists
stay immutable and the16384-byte cumulative report cap is unchanged. Secure
receive allocates exact temporary plaintext, erases/frees it after admission and
preserves replay/time on OOM. Public APIs, admission/default limits and ACK/drain
remain unchanged. ESP32 Read items fall72 ->48 B, Subscribe persistent items
72 ->24 B plus16 B per captured value, secure owners1552 ->320 B.
The saturated fifteen-report/five-Read component peak falls1127553 ->819193 B;
idle subscriptions fall701370 ->210090 B. This excludes other host/platform
allocations and remains larger than a small target RAM budget. Linux CTest92/92
per build, two-instance checks6/6 per memory variant, focused Memcheck and separate
saturated sanitizers pass. Windows92/95 plus3/3 local socket retries and9/9 final
focused checks. [Report](memory09-validation.md) and [results](memory09-results.json)
separate configured-cap arithmetic, component demand and whole-host samples.
Native capacity checks pass50/50 at3 seconds and Massif checks50/50 at30 seconds;
the whole-host sample is388317 B heap,6752 B maximum sampled stack and399176 B
maximum heap+metadata+used-stack combined (different stack-maximum snapshot).
Next: application-specific whole-node event/reporting and delivery-tail budgets
before ESP32 RAM sizing; no physical ESP32 or official CSA rerun.

**Memory08: PASE/CASE buffers follow handshake phases.**
Exact RX, process-only parsers, exact PASE parameter transcripts and temporary
CASE Sigma work replace embedded buffers. TX releases at sent after the owner's
MRP copy; terminal statuses allocate nothing. Limits, fail-safe notifications,
resumption, one-shot transfer and PASE ACK/CASE sent gates are unchanged. ESP32
owners fall6384 ->744 B and14112 ->2440 B; the all-buffer ceilings add32/56 B plus
allocator overhead, while measured phase lifetimes reduce actual peaks.
Linux CTest91/91 per build and two-instance checks6/6 per memory variant pass;
phase/OOM Memcheck is clean. Windows91/94 plus3/3 socket retries. A native
five-fabric/fifteen-session/fifteen-subscription workload passes50 checks at a
3-second report interval. [Report and memory-budget limitations](memory08-validation.md)
and [results](memory08-results.json) separate sampled whole-host heap/stack from
ESP32 layouts and normative resource guarantees: one-node Massif with30-second
reports observes413884 B heap,6744 B sampled stack,424368 B combined peak including
allocator overhead;50 checks pass. Host discovery/resolver groups alone account
for94920 B at the heap sample. No physical ESP32 or CSA rerun.
Next: bound whole-node reporting/snapshot demand and persistent secure RX storage.

**Memory07: Fabric publication stages metadata and sizes TLV output exactly.**
The guarded Fabric candidate is borrowed during synchronous encoding; the live
image, complete rollback, schemas1..7, five-fabric/storage limits, fail-safe and
ACK/drain ordering remain unchanged. The same writer measures and encodes, and
shared field/validation operations avoid a second schema implementation.
Tracked host publication peak falls 64,632 -> 32,313 B; ESP32 staging falls
16,160 -> 648 B. For the measured blob, the image/rollback/staging/output subtotal
falls 80,016 -> 47,681 B. Dense image/rollback and populated-blob restore remain.
Linux CTest is 90/90 and two-instance checks 6/6 per memory variant; focused
committed/pending seed/load Memcheck cases are clean. Windows is 90/93 in the
sandbox plus 3/3 socket retries. ESP32 probes have no compiler diagnostics.
[Report](memory07-validation.md) and [results](memory07-results.json) distinguish
heap measurements, layout subtotals, stack growth and remaining limits.
Next: phase-sized PASE/CASE buffers with handoff, fail-safe and ACK/drain preserved.
No physical ESP32 or official CSA rerun.

**Memory06: IM parser/tag/selector workspaces and CASE cache allocate on demand.**
Read/Subscribe erase temporary parser state after work; Subscribe also releases
its temporary chunk plan, and exact attribute selectors release after expansion.
Invoke retains parser/writer state through async effects. Limits and independent
snapshot/result/output ACK/drain ownership remain unchanged. ESP32 owner sizes:
Read 280 B, Subscribe 328 B, Invoke 224 B, Write 232 B, client 56 B; the five owners
save 8024 B. Empty Fabric host saves 1552 B with bounded live MRU nodes.
Linux CTest 90/90 and two-instance checks 6/6 per memory variant; full request,
Read, Subscribe and CASE/cache allocation suites are clean under Memcheck.
Windows 90/93 in sandbox plus 3/3 socket retries; no parser frame grows.
[Report and larger-allocation audit](memory06-validation.md) records active
costs, stack frames and evidence. Fabric image still uses 15552 B; publication
coexists with backup/staging/TLV storage for an 80016-byte payload subtotal.
PASE/CASE attempts are already per-handshake and disappear after handoff/drain.
Next: reduce Fabric publication's peak and adapter work, then phase-sized
PASE/CASE buffers. No device or official CSA rerun.

**Memory05: Invoke/Write/client requests, replies and results allocate on demand.**
Accepted RX, normalization scratch, declared command bodies, bounded replies and
validated Write IB descriptors/results replace embedded buffers/tables. Handler
allocations precede all model effects; per-IB atomicity, limits and ACK/drain
ownership remain unchanged. ESP32 owners: Invoke 5600 -> 1536 B, Write 4288 ->
1800 B, client 2968 -> 936 B, with operation buffers counted separately. Linux
CTest 89/89 and two-instance checks 6/6 per memory variant; all 16 allocation OOM
sites and lifetime tests pass, Memcheck reports no leaks/errors. Windows 89/92
in sandbox plus 3/3 socket retries with network access. Client receive's compiler
frame grows 32 B; allocator/peak tradeoffs are recorded in the
[report](memory05-validation.md). No device or official CSA rerun.
Next: inspect fixed parser/tag/path/result workspaces and their lifetime.

**Memory04: Read/Subscribe share demand-sized immutable value storage.**
Each encoded value owns a stable allocation; the 4096/16384-byte payload budgets
and result ceilings are unchanged. Subscribe frees after the whole report's
IM/MRP gates, Read on delete; cancellation/timeout retain values through owner
drain. ESP32 owner sizes remain unchanged; an 8-byte string requests 14 B instead
of a 16384-byte arena, while 512 saturated values add 2048 B of link metadata.
Linux CTest 88/88 and two-instance checks 6/6 per memory variant, snapshot OOM
Memcheck and 16/1024-capacity tests are clean. [Report](memory04-validation.md).
No device or official CSA rerun. Next: inspect Invoke/Write/client allocations.

**Memory03: event-log retention and batch staging allocate on demand.**
Stable event nodes replace both fixed arrays, preserving number reservations,
oldest lowest-priority eviction, same-batch protection and atomic prepare/finish.
Read/Subscribe retain independent immutable snapshots. ESP32 compiler layouts:
empty log 60,184 -> 808 B; full 128-record retention 31,528 B; full-log/full-batch
peak 62,248 B before allocator overhead. Linux CTest 87/87 and two-instance
scenario 6/6 per memory variant; event OOM Memcheck and sanitizer tests at
capacities 16/1024 are clean. [Report and limits](memory03-validation.md).
No physical ESP32 or official CSA rerun. Next: bounded shared value snapshots
for Read/Subscribe, preserving references and report/ACK ownership.

**Memory02: transactions and TX packets allocate on demand in the isolated memory checkout.**
Memory01 is committed as `5355e02`. Stable live nodes and exact encoded TX sizes
preserve the existing admission ceilings, ACK/retry and UDP drain lifetimes.
ESP32 compiler layouts show 78,200 B less idle reservation; full 52 x 1232 B TX
costs 424 B more before allocator overhead. Linux CTest 86/86 per memory variant,
two-instance scenario 6/6 per variant, and focused OOM/drain Memcheck are clean.
Transport 128 dispatcher regression also passes under sanitizers.
[Report and limitations](memory02-validation.md). No device or official CSA rerun.
Next: demand-sized event retention/staging with atomic publication preserved.

The continuing campaign uses an [execution plan](csa-campaign-plan.md) and
[generated current queue](csa-campaign-status.md). Execute all possible applicable
tests first, retain explicit external blockers, then repair attributed native
defects and rerun the original failures. Local commits are made per batch;
the owner performs the eventual push. Check the queue with
`python tools/matter/csa_campaign.py`; earlier entries below remain historical.

**CSA69: TC_DA_1_2 is blocked by the development VID, not a demonstrated signature defect.**
Historical FAIL171 stops at step6.2 on0xFFF1; installed source is unchanged.
Current public CD still has VID0xFFF1/PID0x8001/type0. Type0 test CD is permitted
for certification testing; that does not bypass the separate VID requirement.
[Analysis and rerun prerequisites](csa69-validation.md). No full rerun, native
change or trust/signature bypass; later test assertions remain unverified.
Counts stay122 PASS/28 FAIL/5 prerequisites; FAIL is retained, not reclassified.
Next:CSA70, TC_DA_1_7 and distinct-device attestation prerequisites.

**CSA68: existing automatic TC_SU_2_5 test behavior reconfirmed.**
Installed test/helper hashes still match CSA24a/24b; archived FAIL450 and local
corrected PASS451 retain their exact logs/results. Existing offline regression:
original fails the same three controls, corrected11/11. No new full rerun or
native change. [Report](csa68-validation.md) and [CSA question draft](csa68-csa-question.md).
Official FAIL stays open pending accepted test correction; local PASS is historical,
not acceptance of the current binary. Counts remain122 PASS/28 FAIL/5 prerequisites.
Next:CSA69, TC_DA_1_2 attestation/provisioning attribution. Paired nodes untouched.

**CSA67: resolver offline latch after fatal receive repaired.**
Old library reproduces permanent OFFLINE after one ENETDOWN. New valid requests
reopen sockets without background retries or losing old results. API33/35 checks,
full OTA25/25 and focused CTests8/8 pass per memory variant. Memcheck zero errors/
live blocks; separate ASan/UBSan/LSan clean. [Report](csa67-validation.md).
Actual local address replacement and Windows execution remain unverified.
Original CSA verdicts unchanged:122 PASS/28 FAIL/5 prerequisites. Next:CSA68,
review remaining automatic TC_SU_2_5 using prior evidence before another rerun.
Paired Windows nodes untouched.

**CSA66: same-instance recovery from an injected resolver send failure passes.**
Independent full OTA checks25/25 per memory variant: one ENETUNREACH, preserved
120020/120027ms retry intervals, full CASE, signed BDX/apply/reboot/Notify and
version2 readback. Memcheck has zero errors/live blocks; separate ASan/UBSan/LSan
is clean. [Report](csa66-validation.md). No native change or original CSA rerun;
counts stay122 PASS/28 FAIL/5 prerequisites. Actual link/address replacement and
fatal receive-error recovery are not covered. Next:CSA67, bounded resolver
receive-error recovery with first-result capture. Paired Windows nodes untouched.

**CSA65: VM network outage identified during the early sanitizer failure.**
Historical journal confirms link down/address removal during the estimated
attempt around10:01:46 UTC; delayed reports arrived after network return.
Four independent diagnostic full updates pass27 checks each; three include
ASan/UBSan/LSan, while GDB explicitly disables LSan. Exact historical errno is
unknown; no native fix is justified. [Report](csa65-validation.md). Preserve
CSA64 functional FAIL and original607; counts remain122 PASS/28 FAIL/5 prerequisites.
Next:CSA66, controlled same-instance network-failure/recovery with first-error
capture, without disconnecting the shared VM. Paired Windows nodes untouched.

**CSA64: recovery completes under Memcheck; sanitizer variant retains FAIL.**
Normal host passes27 checks: real backoff, new resumed CASE, exact signed BDX,
apply/reboot/Notify and version2 readback. Two boots have zero Memcheck errors/live
blocks. Separate sanitizers retain a functional FAIL: after240024ms, Querying
returns to Idle/Failure in32ms without a new CASE reaching the provider; no
sanitizer diagnostics, but no full update acceptance. [Report](csa64-validation.md).
The first full-only oracle FAIL is retained;13 corrected oracle controls pass.
No native/original-test/PICS change; counts stay122 PASS/28 FAIL/5 prerequisites.
Next:CSA65, bounded attribution of that early failure before further long reruns.
Paired Windows nodes remain untouched.

**CSA63: QueryImage provider handoff and backoff attributed; original FAIL retained.**
Unforced original607 accepts UpdateAvailable from the old provider before its
handoff and fails step2 in Downloading. Separate deliberate-loss608 proves unknown
CASE-session drops, MRP timeout and240s backoff beyond step3; it is not a new
ordinary CSA outcome or retrospective proof of605. No production change justified.
Actual NotAvailable passes13 checks per memory variant, with zero errors/leaks;
clean focused CTests2/2 each. [Report](csa63-validation.md). Counts unchanged:
122 PASS/28 FAIL/5 prerequisites. Next:CSA64, observe permitted post-restart retry,
fresh CASE and full signed OTA recovery. Existing paired Windows nodes untouched.

**CSA62: Applying event drain repaired before simulated OTA reboot.**
Old host min5s reproduces lost events. The new owner-only readiness barrier lets
normal reporting finish before stop, with a bounded30s host wait. Full updates
pass21 checks per memory variant; prior Busy180 passes24. A60s negative control
logs ready0 at30005ms and retains its expected raw live-event FAIL. Memcheck has
zero errors/live blocks, separate sanitizers are clean and focused CTests11/11
pass each. [Report](csa62-validation.md). No original CSA rerun or Windows build.
Counts remain122 PASS/28 FAIL/5 prerequisites. Next: CSA63, provider-restart/query
failure attribution from CSA60. Existing paired nodes remain untouched.

**CSA61: OTA initial-report/callback boundary confirmed; original FAIL retained.**
Original TC_SU_2_7 run606 repeats CSA26's startup ordering: default-provider query
starts before step1 callback; first callback event is already Downloading.
A separate late subscription receives the earlier Querying event.14 checks per
memory variant pass; Memcheck has zero errors/live blocks and separate sanitizers
are clean. Native code/binaries remain CSA60-identical. [Report](csa61-validation.md).
Counts remain122 PASS/28 FAIL/5 prerequisites. Next: CSA62, attribute Applying
capture across fast simulated reboot; this run fails before that boundary.

**CSA60: explicit application query added; original OTA FAIL retained.**
The new owner-only query action preserves rate limits, urgent jitter and retry
backoff. Original TC_SU_2_2 run605 now reaches step3, where the provider restart/
query-failure boundary retains a backoff beyond its120s observation. Step2 PASS
is not decoded NotAvailable proof. Full signed-update memory scenarios pass;
instant-reboot event capture misses Applying in one sanitizer scenario and stays
open. Focused CTests8/8 each. [Report](csa60-validation.md).
Counts remain122 PASS/28 FAIL/5 prerequisites. Next: CSA61, original TC_SU_2_7 and
fast-reboot event attribution. Existing paired Windows nodes are untouched.

**CSA59: Timed Write timing assumption identified; original FAIL preserved.**
Actual Write arrives 1.56 ms after Success, inside the 700 ms window: the first
TimedRequest had hit pending RX and needed an MRP retry after 1.414 s. Original
TC_IDM_5_2 still fails (run 603); no native behavior/test/PICS workaround was added.
Independent truly late writes, unchanged-value readback, expired-duplicate and
recovery controls pass: 41 checks per memory variant, clean full Memcheck and
separate ASan/UBSan/LSan, plus 4/4 clean-build CTests each.
[Report](csa59-validation.md). Counts remain 122 PASS/28 FAIL/5 prerequisites.
Next: CSA60, deterministic QueryImageResponse fixture and original TC_SU_2_2,
reusing the CSA28 investigation before further changes.

**CSA58: complete automatic rerun; repeatable Timed Write failure reopened.**
All 99 previously passing positions rerun on one frozen native build: initially
96 PASS/3 FAIL. Corrected Wi-Fi test-mode and live-QR inputs pass; unchanged
TC_IDM_5_2 fails step 4 twice (runs 560/595). Effective result: 98 PASS/1 FAIL;
102 original executions, 104 clean native lifetimes, no native/test/PICS changes.
[Report](csa58-validation.md). Campaign: 122 PASS/28 FAIL/5 prerequisites;
older failures and manual outcomes are not rerun. Exact-build memory evidence
is reused from CSA56/57, with no fresh native build or sanitizer claim.
Next: CSA59, actual packet-time/status/side-effect repro for Timed Write, then
only a confirmed standards-correct fix and unchanged original test acceptance.

**CSA57: actual stalled BDX recovery passes; original optional-ACK question remains.**
Same requestor, real300s idle expiry, provider restart, explicit reason0, new CASE,
full offset0 transfer, signed simulated apply/reboot and Notify all pass.
24 checks per memory variant; clean Memcheck/sanitizers and four CTests per build.
Original TC-BDX-2.3 run495 retains FAIL only for ordinary BlockAck wording.
[Report](csa57-validation.md). Counts unchanged:123 PASS/27 FAIL/5 prerequisites.
Next:CSA58, bounded stable automatic-suite rerun grouped by lifecycle.

**CSA56: UDP RX starvation repaired; full load scenarios pass.**
Both host pollers receive peer ACKs even while TX completions stay queued.
399 actual-controller checks per variant across four resets pass under Memcheck
and separate sanitizers. Original TC-IDM-7.1 retains only its overflow-status
question. Earlier BDX no-query failure traced to reason1/daily scheduling.
[Report](csa56-validation.md). Counts unchanged:123 PASS/27 FAIL/5 prerequisites.
Next:CSA57, actual BDX recovery with an explicit appropriate trigger.

**CSA55: GroupKeyMap write-status defect repaired; original positive test retains FAIL.**
Actual statuses change from[80,80] to[00,89] for declared zero-group capacity.
Unsupported optional Leave confirmed as EventStatusc7.53 independent checks per
variant, clean Memcheck/sanitizers and five CTests per build.
[Report](csa55-validation.md). Counts unchanged:123 PASS/27 FAIL/5 prerequisites.
Next:CSA56, remaining BDX recovery/load-dependent subscription attribution.

**CSA54: original automatic TC_SC_7_1 PASS with two actual setup codes.**
Run492 passes6 steps; two simultaneous native nodes, actual PASE/empty roots,
different configured factory inputs, no original/PICS or native change.
[Report](csa54-validation.md).99 automatic PASS/18 FAIL/1 BLOCKED;
manual24 PASS/9 FAIL/4 BLOCKED. Total123 PASS/27 FAIL/5 prerequisites.
Next:CSA55, GroupKeyMap/optional Leave wire status attribution.

**CSA53: remaining assertions grouped; bounded GroupKey/BINFO reruns retain FAIL.**
Zero-group profile/write status and optional Leave result handling remain explicit
review items. Prior ACL/root/Revoke/scan/Wi-Fi/identity analysis reused.
[Report](csa53-validation.md). Counts unchanged; native unchanged.
Next:CSA54, actual two-device setup-code fixture for TC_SC_7_1.

**CSA52: authenticated IM R=0 admission repaired; original TC-SC-1.2 PASS.**
Run489 passes7 steps. Five actual A0/R1 data replies, ACK/duplicate controls,
Memcheck and separate sanitizers pass; eight CTests per build.
[Report](csa52-validation.md). Manual24 PASS/9 FAIL/4 BLOCKED.
Next:CSA53, assertion-level grouping and bounded remaining automatic rechecks.

**CSA51: terminal PASE failure delivery repaired; original TC-SC-2.3 PASS.**
Run488 passes9 steps. Real retry/ACK/exhaustion/stop regressions, full Memcheck
and separate sanitizer commissioning recovery pass; five CTests per build.
[Report](csa51-validation.md). Manual23 PASS/10 FAIL/4 BLOCKED.
Next:CSA52, authenticated IM R=0 admission and original TC-SC-1.2.

**CSA50: original DA1.1 PASS; GroupKey2.2 FAIL on an existing keyset ID.**
Actual capacity fill, isolated operator, factory reset/recommissioning and
independent persistent restart accepted; original FAIL retained for clarification.
[Report](csa50-validation.md).150 completed applicable positions,5 prerequisites.
Next:CSA51, native terminal PASE error delivery and original procedure rerun.

**CSA49: original TH run484, event Read and fabric isolation PASS; Subscribe FAIL.**
Six selectors, EventMin, chunking, urgency/timing and real two-fabric raw privacy
covered. Two all-denied Subscribe expectations need CSA clarification; no native
change. Tester boundary corrections replayed on immutable traces; see
[report](csa49-validation.md). Manual22 PASS/11 FAIL/4 BLOCKED/0 not run.
Next:CSA50, keyset-fill/reset boundaries and earlier BLOCKED review.

**CSA48: TC-IDM-7.1 original manual FAIL, TH run483.**
Five fabrics/15 live three-path subscriptions and four-path support confirmed.
Memcheck misses a second Identify update after overflow and actor2 CASE times
out; faster separate sanitizer passes all four phases. Literal original
INVALID_ACTION80 differs from capacity89. Attribution remains open; no native
change. See [report](csa48-validation.md). Next:CSA49, remaining three IM cases.

**CSA47: applicability/prerequisite review, no new test run.**
Original predicates and current TH API exclude NFC/concatenated onboarding under
unchanged PICS: two old MANUAL positions corrected to NA. Four manual blockers
now have explicit prerequisites and remain visible. See [review](csa47-validation.md).
Totals:155 applicable +707 NA; MANUAL20 PASS/9 FAIL/4 BLOCKED/4 not run.
**Next: CSA48, remaining IM event/resource/fabric server procedures.**

**CSA46: TH run482, DGGEN2.2/DGWIFI2.2/GRPKEY5.4 manual PASS; CNET4.13 FAIL.**
BootReason, simulated network reorder/rollback/commit and unsupported policy
rejection pass50 Memcheck and47 separate sanitizer checks. Optional physical fault
and Wi-Fi event steps are NOT APPLICABLE from frozen PICS. CNET retains absent
BLE precondition and add-loop arithmetic discrepancy. See [report](csa46-validation.md).
MANUAL:20 PASS,9 FAIL,10 without outcome. **Next: CSA47 applicability/prerequisite review.**

**CSA45: TH run481, BDX1.2/2.2 and IDM1.1 manual PASS; BDX2.3 FAIL.**
Fresh complete transfer and genuine DUT Invoke evidence pass under Memcheck and
separate sanitizers. Stalled transfer expires safely, but provider restart does
not start a new download in the bounded observation. Attribution is pending;
fresh positive nodes do not waive recovery failure. See [report](csa45-validation.md).
MANUAL:17 PASS,8 FAIL,14 without outcome. **Next: CSA46 diagnostic/network/group-key coverage.**

**CSA44: original TC-DESC-2.1 manual FAIL, TH run480.**
Two distinct causes: literal flat PartsList wording conflicts with permitted phased
hierarchy, and whole-cluster acceptance is still incomplete. Independent Descriptor
inventory/catalog checks pass 117 per variant; no native changes. Root TagList is
NOT APPLICABLE from frozen PICS. See [report](csa44-validation.md).
**Next: CSA45, BDX receiver transfer/restart procedures.**

**CSA43: original TC-SC-1.4 manual PASS, TH run478.**
Original reliable PBKDF input and three exact repeats receive matching ACKs;
duplicates produce only empty standalone ACKs and no repeated application reply.
Both full scenarios pass32 checks under Memcheck/separate sanitizers, followed by
two-fabric commissioning/CASE without restart. Memory is clean:43506 matched
allocations/frees; three focused replay/RX CTests pass per variant. No native,
PICS or original-test changes. MANUAL now has14 PASS,6 FAIL,19 without an outcome;
category totals are unchanged. See [receipts/limits](csa43-validation.md).
**Continue with CSA44, TC-DESC-2.1**, and then the remaining campaign queue.

**CSA42: original TC-SC-1.3 literal manual FAIL, TH run477; Core retries PASS.**
Step4 says total MAX-1 messages. At max5, Core requires five total sends/four
retries; both wire scenarios do exactly that. The original FAIL is retained for
wording clarification, not justification to change the native count. All four
gaps per run fit Core margin/backoff/jitter bounds, without receive tolerance.
No peer replies during12-second loss; retries stop beyond final wait+guard and
late ACK does not restart them. Fresh two-fabric commissioning/CASE works without
DUT restart. Independent acceptance passes32 checks per Memcheck/sanitizer run;
43530 matched allocations/frees, zero errors/live bytes, clean DUT exits/stderr.
Existing table/sender CTests pass 2/2 per variant. No native/PICS/test mutation or
new host compilation. TH idle, disposable nodes stopped; Windows pairings intact.
Totals stay **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL now has
**13 PASS, 6 FAIL, 20 without an outcome**. See [scope/clarification](csa42-validation.md)
and [receipts](csa42-results.json). **Next: CSA43, TC-SC-1.4 MRP counters and
duplicates. Continue initial coverage; earlier native repairs remain deferred.**

**CSA41: original manual TC-SC-1.2 FAIL, TH run476: R=0 requests rejected.**
Reliable PBKDF data replies piggyback the correct ACK; exact duplicates receive
only standalone ACKs. Five independently authenticated R=0 VendorID ReadRequests
receive no data reply, while the same R=1 read succeeds before/after. Runtime
admission rejects new requests without R before handler creation; lower MRP/IM
layers support the flow. This native defect is deferred; no C/H/PICS change.
TH has six passed entries and one failed. Both full scenarios retain FAIL;
52 functional/four conformance checks pass, ten required-data assertions fail.
Memcheck has48333 matched allocations/frees and zero errors/live bytes; separate
ASan/UBSan/LSan and DUT exit/stderr are clean. Five focused ACK/RX/IM tests build/
pass per variant. Full subsequent commissioning/CASE works without DUT restart.
TH idle, disposable nodes stopped; paired Windows nodes untouched. Totals stay
**97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL now has **13 PASS,
5 FAIL, 21 without an outcome**. See [cause/evidence](csa41-validation.md) and
[record](csa41-results.json). **Next: CSA42, TC-SC-1.3 MRP Retransmissions.
Continue initial coverage; native repairs remain deferred.**

**CSA40: original manual TC-SC-1.1 PASS, TH run475: MRP size boundary.**
Core4.4.4/4.15 limit is the complete IPv6 MTU1280: base IPv6 header40 + UDP8 +
Matter1232. At1279/1280 bytes the DUT returns matching ACK/PBKDF replies; at
1281/1328/1329 it is silent. Valid small PBKDF requests use skip-only Matter MX
padding; no IPv6 extensions or native/PICS changes. Both full two-fabric
scenarios pass32 checks under Memcheck and32 under separate ASan/UBSan/LSan.
Memcheck has43533 matched allocations/frees and zero errors/live bytes; node
exits/stderr are clean. Five focused UDP/MRP targets build/pass per variant,
without observed compiler warnings. TH idle, disposable nodes stopped; paired
Windows nodes untouched. This is original manual operator acceptance, not an
automatic test or certification. Totals stay **97 PASS, 18 FAIL, 3 BLOCKED,
39 MANUAL, 705 NA**; MANUAL now has **13 PASS, 4 FAIL, 22 without an outcome**.
See [evidence](csa40-validation.md) and [record](csa40-results.json).
**Next: CSA41, TC-SC-1.2 MRP Message Flows. Continue initial coverage;
CSA39's native error-reply defect and earlier failures remain deferred.**

**CSA39: original manual TC-SC-2.3 FAIL, TH run474: missing PASE error replies.**
Invalid passcodeID and Pake3.cA receive ACKs but no required StatusReport1/0/2.
PASE prepares the correct error output; the runtime dispatcher closes on the
returned error before submitting that output. This is a confirmed native
integration defect, not a test/spec discrepancy; repair is deferred as requested.
Seven TH entries pass and two fail. In each Memcheck/separate-sanitizer scenario,
26 functional checks pass and two required-status assertions fail; overall FAIL
is retained. Late valid-shaped messages do not revive the failed exchanges;
fresh full commissioning/CASE and a second fabric work without DUT restart.
Memcheck has 48294 matched allocations/frees, zero errors/live bytes; both node
stderr files are empty. Two existing tests pass per build. No native/PICS changes
or new compilation. TH idle, disposable nodes stopped; Windows pairings untouched.
Totals remain **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL now has
**12 PASS, 4 FAIL, 23 without an outcome**. See [evidence/cause](csa39-validation.md)
and [record](csa39-results.json). **Next: CSA40, TC-SC-1.1 MRP size boundary.
Continue initial coverage; return to failures later as requested.**

**CSA38: original manual TC-SC-2.2 FAIL, TH run473; bad-MIC recovery passes.**
Four bidirectional encrypted PASE steps and log upload pass; Step5 requires
session termination/key clearing, but both receivers retain their session after
dropping the damaged message. Core1.6.1 4.8.3 requires failed-message processing
to stop, without mandating session destruction. The original FAIL is retained
for clarification. Full scenarios pass 25 checks under Memcheck and 25 separately
under ASan/UBSan/LSan, including four actual bad-MIC deliveries, unchanged-counter/
session recovery and full commissioning/CASE. Memcheck has 43536 matched
allocations/frees, zero errors/live bytes; both node stderr files are empty.
Two existing PASE/secure targets were built and pass 2/2 CTests per build;
no compiler warnings observed. No native source/API/PICS change or live key dump.
TH is idle, disposable nodes stopped and paired Windows nodes untouched.
Totals remain **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL now has
**12 PASS, 3 FAIL, 24 without an outcome**. See [evidence](csa38-validation.md)
and [record](csa38-results.json). **Next: CSA39, TC-SC-2.3 invalid passcodeID/cA.
Continue initial coverage; failures remain deferred as requested.**

**CSA37: original manual TC-SC-2.1 FAIL, TH run472; Core wire checks pass.**
Five original steps conflict with Core1.6.1 addressing/boolean/byte-size rules;
the final success verification and evidence upload pass. The literal FAIL is
retained for clarification without changing test/PICS or the native stack.
Full first-fabric CASE/enhanced-window/second-fabric scenarios pass 20 checks under
Memcheck and 20 separately under ASan/UBSan/LSan, with four complete PASE exchanges.
Memcheck has 43510 matched allocations/frees, zero errors/live bytes; both node
stderr files are empty. All 362 native source/header entries match the previously
built CSA35 inputs. TH is idle and disposable nodes stopped; paired Windows nodes
untouched. Totals remain **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**.
MANUAL now has **12 PASS, 2 FAIL, 25 without an outcome**. Continue the initial
coverage pass (25 manual plus 3 blocked); return to failures later as requested.
See [evidence/discrepancies](csa37-validation.md) and [record](csa37-results.json).
**Next: CSA38, TC-SC-2.2 bidirectional PASE/error handling. CSA30 remains deferred;
CSA32 remains open.**

**CSA36: Commissioner Discovery / UDC declaration corrected; TC-SC-4.7 is NA.**
Core1.6.1 4.3.3 makes this feature optional; the reference runtime has no
`_matterd._udp` commissioner discovery or UDC protocol0x0003 implementation.
`MCORE.DD.COMM_DISCOVERY` is now false. Commissionable/operational discovery,
PH/Extended Discovery and the limited OTA controller role remain unchanged.
The unmodified TH applicability endpoint removes only TC-SC-4.7 (164 to 163
eligible titles in the root project); the original project is preserved.
No new test execution or PASS is claimed. Five actual endpoint CLI exports
preserve every other PICS/project value. Current cumulative totals are **97 PASS,
18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL has **12 PASS, 1 FAIL, 26 without
an outcome**. No native/runtime changes or paired-node restart. See
[audit and limits](csa36-validation.md) and [record](csa36-results.json).
**Next: CSA37, TC-SC-2.1 manual PASE exchange acceptance. CSA30 remains deferred;
CSA32 remains open.**

**CSA35: PH/privacy policy fixed; original discovery rechecks PASS.**
Automatic TC_SC_4_1 run469 passes 21 entries (9 NA), TC_SC_4_3 run470 passes 15;
manual TC-DD-2.1 run471 passes 11 (15 NA). The host supplies PH1 before commissioning
and PH4 afterward. Per-Node Extended Discovery defaults to 900 seconds; explicit
CLI values disable, bound or allow unlimited CM=0 advertising. Expiry withdraws
only commissionable discovery; CASE/operational discovery and new windows work.
Six full Memcheck/separate-sanitizer scenarios pass 209 functional checks and 26
PH assertions; two restored disabled boots pass fresh CASE and nine checks.
Four accepted Memcheck processes have 83076 matched allocations/frees, zero errors/
live bytes. Five CTests pass per Linux build, installed consumer and five CLI
rejections pass; Windows node/desktop build and three discovery tests pass.
Discovery PICS now declares Extended Discovery/PH; original test sources are
unchanged. TH is idle, disposable nodes stopped and temporary public PAA removed;
paired Windows instances untouched. MANUAL now contains 12 PASS, 1 FAIL and 27
without an outcome; category totals are unchanged. See [evidence](csa35-validation.md)
and [record](csa35-results.json). **Next: CSA36, Commissioner Discovery/UDC PICS
and TC-SC-4.7 applicability. CSA30 stays deferred; CSA32 remains open.**

**CSA34: original TC-DD-2.1 manual FAIL, TH run468.**
Eight entries pass, seventeen are not applicable and Step15a fails: the actual
CM=0 Extended Discovery record lacks PH, which Core1.6.1 4.3.1.11 requires.
This is a confirmed implementation gap, separate from CSA32's text discrepancy.
Discovery works in basic, closed and enhanced modes: records/IPv6 addresses,
service enumeration, discriminator subtypes, conditional _CM, fresh instance on
reopen and unmodified chip-tool browsing all pass. Full runs pass 37 Memcheck
and 36 separate sanitizer functional checks, but both overall conformance results
remain FAIL. Memcheck has 23960 matched allocations/frees, zero errors/live bytes;
both host stderr files are empty. Original YAML/PICS and runtime C/H are unchanged.
Frozen PICS omits Extended Discovery despite actual CM=0 publication; customer
timeout/disable policy also needs review. TH is idle and disposable processes are
stopped; paired Windows nodes untouched. MANUAL now contains 11 PASS, 2 FAIL and
27 without an outcome; category totals remain unchanged. See
[evidence](csa34-validation.md) and [record](csa34-results.json).
**Next: CSA35, truthful PH and customer Extended Discovery policy/PICS, followed
by the affected discovery rechecks. CSA30 stays deferred; CSA32 remains open.**

**CSA33: original TC-DD-3.19 manual PASS, TH run467, seven entries.**
The full commissioning/RemoveFabric/recommissioning cycle passes with the same
live controller and unchanged credentials. Both pairings scan the same supplied
C-generated QR bitmap, pass attestation and SendComplete, then advertise CM=0.
After removal the old operational record is withdrawn; explicit same-store CLI
restart opens CM=1 with _CM, and the same fabric/node identity returns only after
recommissioning. Independent acceptance passes 37 Memcheck and 35 separate
sanitizer checks; 47881 matched allocations/frees, zero errors/live bytes and
four empty host stderr files. No C/H, original test or PICS changes. Two fixture
failures are retained: an example-specific VP check and an asynchronous timeout
from the controller's old subscription. The final fixture explicitly releases
that subscription after removal, preserving the same live controller. TH is idle;
paired Windows nodes untouched. MANUAL now contains 11 PASS, 1 FAIL and 28 without
an outcome; category totals are unchanged. See [evidence](csa33-validation.md) and
[record](csa33-results.json). **Next: CSA34, TC-DD-2.1 announcement verification.
CSA32's discrepancy remains open; CSA30 remains deferred.**

**CSA32: original TC-OPCREDS-3.6 manual FAIL, TH run466.**
Commissioning, successful final RemoveFabric response and operational discovery
withdrawal pass; the evidence upload also passes. Step4 fails its literal
CM=0/no-_CM verification: the stopped CLI has no advertisements, and an explicit
restart opens CM=1 with _CM and permits fresh commissioning. The heading instead
mentions CM=2/BLE; this discrepancy is retained for CSA clarification, without
changing the original test, PICS or runtime defaults. Independent final lifecycle
acceptance passes 27 Memcheck and 25 separate sanitizer checks: active subscription
at removal, successful response, goodbye, no old operational identity, same-store
restart and new independent fabric. Memcheck has 47890 matched allocations/frees,
zero errors/live bytes; all four host stderr files are empty. No C/H changes.
Post-recommissioning root/ACL/group-map reads check expected defaults, not seeded
non-default dataset deletion. TH is idle and paired Windows nodes untouched.
Category totals are unchanged; MANUAL now has 10 PASS, 1 FAIL and 29 without an
outcome. See [evidence and discrepancy](csa32-validation.md) and
[record](csa32-results.json). **Next: CSA33, TC-DD-3.19 commissioning/unpair/
recommission. CSA30 remains deferred.**

**CSA31: original TC-DD-1.1 and TC-DD-1.2 PASS, TH run465.**
The QR case passes 9 steps; the manual case passes 3 with its 21-digit branch
not applicable. Three operator inputs come from a scanned C-generated QR bitmap,
captured live mDNS and a CHIP-generated development manual card. Original
test/support sources and profile PICS are unchanged. Independent acceptance
passes 24 checks; the existing C payload boundary self-test passes Memcheck.
No C/H, runtime/API or persistence changes were needed. Physical labels, native
GUI rendering, DCL certification and a native manual-code display are not
accepted by this run; known official-helper coverage gaps are documented.
The evidence node is stopped and TH idle. Both matrix rows remain MANUAL with
manual_result=PASS: category counts stay unchanged, documented manual PASS
increases from 8 to 10. See [evidence and limits](csa31-validation.md) and
[record](csa31-results.json). **Next: CSA32, TC-OPCREDS-3.6, last-fabric removal
and discovery. CSA30 stays unsuccessful/deferred; no more long retry this pass.**

**CSA30 retry: original TC-DGGEN-2.1 ERROR, TH run464.**
Commit `5c3e730` preserves the implementation fixes and run463 ERROR. The idle
laboratory was restarted cleanly; the original WebSocket runner passes command
checks before and after 165.047 seconds of idle time. Run464 uses unchanged test,
PICS, binary and full wait durations. It completes the 2h05 wait and verifies
TotalOperationalHours **0 to 2**. After factory reset, Step10b commissioning hits
a controller WebSocket keepalive timeout. The 1h05 segment is not executed.
Final states: **30 passed, 6 not applicable, 1 error, 9 pending**. The control
capture shows ping/pong through the long wait and an unanswered ping after reset;
the exact stall mechanism is not proven. Final evidence is collected, the node
stopped, its port released, PAA removed and TH idle. **No complete PASS**; matrix
counts remain unchanged. Existing paired Windows instances are untouched.
See the [retry and retained error](csa30-validation.md) and
[record](csa30-results.json).

**CSA30: original semi-automated TC-DGGEN-2.1 ERROR, TH run463.**
The host now supplies Node-relative monotonic time instead of OS uptime, and an
optional application callback supplies actual selected transport NIC diagnostics.
Independent chip-tool acceptance passes 31 Memcheck and 28 sanitizer checks;
Memcheck has 59140 matched allocations/frees, zero errors/live bytes. Six focused
Linux CTests pass per build, the installed consumer passes, and Windows host/
desktop builds plus four focused CTests pass. Runtime regressions cover network
callback failure, oversized/invalid data, recovery and instance isolation.
Original test/PICS and both 2h05/1h05 waits are unchanged. Final states are
28 passed, 5 not applicable, 1 error and 12 pending. After the first full 2h05
wait, the next read encountered a TH/chip-tool WebSocket keepalive timeout;
no second hours value was received. The second long wait was not executed.
This does not establish a wrong DUT hours value. **No official PASS.** Counts remain
**97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA**, inherited from CSA29.
The disposable TH node is stopped, its temporary PAA removed, port released and
TH idle; final evidence was collected. Existing paired Windows instances
were not replaced/restarted. Type is Unspecified; NIC addresses are a startup
snapshot. See [fixes, execution error and limits](csa30-validation.md) and
[record](csa30-results.json).
**Campaign unsuccessful; further investigation deferred by the owner. No more
long-duration retries in this pass. Next: CSA31, TC-DD-1.1/1.2 onboarding
QR/manual pairing payload tests.** The controller stall stays open for a later
short reproduction; this decision does not change the official ERROR results.

**CSA29: original semi-automated TC-I-2.2 PASS, TH run460, 15/15 step entries.**
Two agent-evaluated operator prompts use live callbacks under IdentifyType0
(None, no physical presentation), followed by evidence upload. This is not a
fully automatic case or physical indicator acceptance. Independent chip-tool
passes 18 Memcheck and 16 separate sanitizer checks: real countdown, explicit
stop, natural expiry, quiet subscription and fresh CASE after clean restart.
Memcheck has 35219 matched allocations/frees, zero errors/live bytes; all host
stderr is empty. Four captured conditions and six negative controls check the
test predicates. No C/H or official test/PICS changes were needed. Docker
networking and existing TH services are restored after the laboratory outage;
frontend HTTP200, API responsive, TH idle. The isolated node is stopped and
its temporary public PAA removed. User-paired Windows nodes are unchanged.
Counts: **97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA**; other rows inherited.
See [evidence, setup attempts and limits](csa29-validation.md) and
[record](csa29-results.json). No certification is claimed.
General Diagnostics execution and its infrastructure error are recorded in CSA30 above.

**CSA28: original automatic TC_SU_2_2 FAIL, TH run457, step1.**
The test announces a new provider with UpdateAvailable but does not arrange the
initial normal query; the host's daily policy remains Idle, and the 120-second
DelayedOnQuery wait expires. Later original assertions were not executed. Core
11.20.7.4 recommends the next normal query for that reason; production timing,
C/H, PICS and official test sources are unchanged. The independent laboratory
adds `--default-provider`: configure/read back a default before reason1
announcements, preserving actual retry floors and provider delays.
Seven independent scenarios pass 134 checks. Busy/60 re-queries after 120203 ms;
Busy/180 waits 180198 ms after the response. Memcheck has 55235 matched
allocations/frees, zero errors/live bytes; separate ASan/UBSan/LSan is clean.
Seven captured response predicates, six negative and two boundary controls pass.
Counts: **97 PASS, 18 FAIL, 4 BLOCKED, 39 MANUAL, 704 NA**; only this row changes.
See [actual scenarios, memory evidence and limits](csa28-validation.md) and
[record](csa28-results.json). This is not an automatic PASS or certification.
Identify acceptance follows in CSA29 above.

**CSA27: original automatic TC_SU_4_1 FAIL, TH run456, step5.**
The host returns Success for clearing its list, Success for the first append
and ConstraintError for the second append. The test checks only the first
status. Core 8.7.3.3/8.7.3.4 require per-operation status generation; no response
or official assertion was changed to force PASS. Independent chip-tool
acceptance passes 29 Memcheck and 27 sanitizer checks across two fabrics,
including partial write/readback, clearing one fabric and persistence after
restart. Memcheck has 190974 matched allocations/frees, zero errors/live bytes;
ASan/UBSan/LSan host stderr is empty. The final parser passes 34 capture rechecks
and rejects eight negative controls. C/H and PICS are unchanged.
Counts: **97 PASS, 17 FAIL, 5 BLOCKED, 39 MANUAL, 704 NA**; only this row changes.
See [evidence and limits](csa27-validation.md) and [record](csa27-results.json).
QueryImageResponse acceptance follows in CSA28 above.

**CSA26: TC-SU-2.7 manual PASS, run455; TC_SU_2_7 automatic FAIL, run454.**
Direct Querying/Downloading/Applying handoffs and known DownloadError progress
are fixed. Seven independent scenarios pass 156 checks, including real BDX Idle
failure after 300.327 s with MRP alive and successful recovery. Full Memcheck
has 55192 matched allocations/frees and zero errors/live bytes; separate
sanitizers are clean. Fifteen focused CTests pass per build. The manual procedure
has six PASS verifications, consent NOT APPLICABLE and a passed evidence upload.
The unchanged Python test fails at step1 after missing the query transition that
occurred during its setup; later steps are not claimed. This is not certification.
Counts: **97 PASS, 16 FAIL, 6 BLOCKED, 39 MANUAL, 704 NA**; other rows inherited.
See [evidence and limits](csa26-validation.md) and [record](csa26-results.json).
Attribute acceptance follows in CSA27 above.

**CSA25: TC-SU-2.6 manual PASS in TH run452.** One verification step plus evidence
upload pass, evaluated against real CHIP Provider traces; this is not automatic
CSA assertions or certification. Two independent signed simulation updates to
versions 2 and 3 pass 15 checks each: Notify token/version binding, restart and
fresh CASE version/BootReason readback. Full Memcheck has 55118 matched
allocations/frees, zero errors/live bytes; separate ASan/UBSan/LSan is clean.
Six negative oracle controls are rejected; two journal CTests pass per build.
No C/H, PICS or official test changes were needed. Only this manual row moves
from BLOCKED to MANUAL/PASS. Counts are **97 PASS, 15 FAIL, 8 BLOCKED, 38 MANUAL,
704 NA**. Other rows, including the original TC_SU_2_5 FAIL, are inherited.
See [evidence and limits](csa25-validation.md) and [record](csa25-results.json).
Event acceptance follows in CSA26 above.

**CSA24b: full local-corrected TC_SU_2_5 PASS, run451, budget three/transport 56.**
The patch consumes progress FIFO reports once under one monotonic deadline and
cleans up scenario subscriptions so the intended live set fits the default
budget of three. The original predicate and every original assertion remain.
The original source fails three regression controls; the corrected source passes
all 11 on Windows and Linux, repeated on TH before this run. All six TH steps
pass, including both delay/provider-loss scenarios and Discontinue: actual
progress through 100 then null, one Apply request, image disposal, Idle and
unchanged version. The original SDK source is restored exactly, its helper is
unchanged, and the isolated node is stopped with empty stderr. No C/H changes
were needed. This is **LOCAL-PATCH PASS**; the original official result/counts
are unchanged pending CSA approval of the test correction. See
[patch, full-run evidence and limits](csa24b-validation.md) and
[record](csa24b-results.json).
Notify acceptance is recorded in CSA25 above; retain the local correction for CSA review.

**Memory target: 128 kB device RAM.** The CSA24a transaction table still reserves
the entire configured budget at construction. This is an interim host mechanism.
The planned embedded migration must allocate individual live contexts/buffers
on demand and free them after drain; a configured limit is an admission ceiling,
not an upfront allocation count. This applies to other large pools as well.
See the [memory-stage requirements](../roadmap.md#3-memory-and-code-size-optimization).

**CSA24a: configurable per-instance subscription budget implemented.** Root's
advertised CapabilityMinima provisions a dynamically allocated transaction table;
per-fabric admission uses the same value. Transport feasibility is checked before
startup, table OOM releases the context, and callback addresses stay stable until
drain/delete. The host adds `--subscriptions-per-fabric N`; defaults remain three
and 56 transport slots. Acceptance selects eight with a 128-slot transport build.
Thirteen CTests pass in normal and sanitizer builds; two compatibility tests pass
with 56 slots. Full Memcheck and separate ASan/UBSan/LSan OTA/restart scenarios
pass 22 checks each; Memcheck has 55267 matched allocations/frees and no errors
or live bytes. Run450 accepts the fourth subscription and passes both delays,
but remains **FAIL**: the test replays an earlier null after 1% and checks Apply
before any request exists. Original-method/predicate reproduction confirms false
completion for `[null, 0, 1]`; CSA has not confirmed a correction. No official
script, PICS or progress semantics were weakened. Counts remain **97 PASS,
15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA**; other rows are inherited, not rerun for
the larger budget. See [evidence and limits](csa24a-validation.md) and
[delta](csa24a-results.json).
**Next: CSA24b — prepare the progress-predicate report for CSA and agree an
accepted correction/test version.**

**CSA24: automatic TC_SU_2_5 FAIL, run449.** Both AwaitNextAction/provider-loss
scenarios pass. The Discontinue step fails before OTA assertions when creating
the fourth live subscription; two obsolete UpdateState subscriptions remain
active in the unmodified script. The host declares/supports three per fabric,
the Core minimum. This resource assumption needs clarification; it is not a
CSA-confirmed test defect. No PICS, capacity or assertions were changed for PASS.
Query errors now wait in Idle with unchanged retry limits, and an optional OTA
callback provides real download progress. Ten focused Linux tests pass in each
build. Full Memcheck and separate ASan/UBSan/LSan retry/update/restart scenarios
pass; Memcheck has 55265 matched allocations/frees and zero errors/live bytes.
Counts: **97 PASS, 15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA**. Only the Python row
changes; manual CSA23 and other results are inherited. See
[evidence and limits](csa24-validation.md) and [delta](csa24-results.json).
The capacity follow-up is recorded in CSA24a above.

Native Windows desktop is implemented in C/Win32: independent node processes
from one EXE, per-user state, integration selection/removal, ±10 kW slider and
runtime-gated QR/status. The interface is English and includes a transparent
slate/teal icon embedded at nine sizes; its presentation update retains existing
settings and pairings. Two concurrent workers pass CHIP under Memcheck (three
boots, 59064 matched allocations/frees, zero errors/live bytes) and separately
ASan/UBSan/LSan. Eight focused Linux tests pass per build; Windows QR CTest passes.
GUI choice/QR/slider and restore were inspected; exhaustive Win32 memory stress
and ecosystem UI acceptance remain unperformed. REST sources are not implemented.
The desktop changes did not alter CSA counts. See [usage](../desktop.md) and
[evidence](desktop-validation.md).

The minimal sensor now optionally adds EEM with `--sensor-energy`: separate
cumulative import/export registers (initial synthetic 12.345/2.345 kWh) and
CumulativeEnergyMeasured. Import grows coherently with +123 W; export is fixed
history. CHIP verifies mixed subscriptions/events and retention across restart
under Memcheck and separate sanitizers; seven focused CTests pass on Windows
and both Linux builds. Only the paired minimal sensor was updated; other nodes
kept running. Apple visibility of the preceding EPM-only value under `Energia`
was confirmed. With EEM added, the user still sees only `123 T`, including
after successful removal/re-addition. A read-only decode of the running node's
stored state confirms distinct cumulative registers; no separate energy fields
were observed in Apple Home. The cause is unresolved. CSA counts
are unchanged. See [energy-register acceptance](sensor-energy-validation.md).

The minimal `--power-sensor-only` node contains Root and one 123 W Electrical
Sensor (endpoint 1), with no On/Off or EEM. It is separate from the earlier
`--test-power-only` full-profile experiment. A dedicated mDNS host label avoids
sharing the physical interface's host name with other simulated nodes. Exact
inventory, Read/Subscribe, restart/fresh CASE and removal are checked by the
optional CHIP runner. The user confirmed a value under `Energia` for this
EPM-only snapshot; that experiment did not alter CSA counts.
See [minimal profile](sensor-only-validation.md).

The optional `--test-power-only` host mode adds Electrical Sensor endpoint 6
with Descriptor/EPM/Power Topology, 123 W and no On/Off or EEM. The socket and
existing endpoint numbers remain. Full CHIP Read/Subscribe, socket-state
independence, restart and removal pass under Memcheck and separate sanitizers;
seven focused CTests pass on Windows and both Linux builds. The paired Windows
node runs both experiments with its fabrics retained. Apple Home shows only
the socket, with no separate 123 W sensor. A second isolated instance was then
freshly paired: the user again reports only On/Off and 600 with unit `T`.
Its log confirms fabric advertisements and a socket On command, with endpoint 6
active; the original instance remains running. This reproduces the UI result
after fresh pairing, but does not establish the cause or behavior of a node
containing only the sensor. Controller path tracing was not performed.
CSA results are unchanged. See
[power-only validation](power-only-validation.md).

The optional metered socket now exposes EPM/EEM/Power Topology on the On/Off
endpoint, using an independent synthetic 600 W / 0 W source and persistent
cumulative import. A whole-profile Read reproduced the former 320-result
ceiling; Read/Subscribe results now grow dynamically to an application limit
of 512. Seven focused CTests pass on Windows, Linux and separate Linux
sanitizers. Full CHIP commissioning/Read/Subscribe/On/Off/restart/RemoveFabric
passes under Memcheck and separately ASan/UBSan/LSan, including corrupt-state
startup rejection. Manual Apple Home on iOS 27.0.1 recovered online and showed
600 after On; the user reports its unit as `T`, unresolved UI labeling.
Energy totals in that UI are not confirmed. These are interoperability results,
not new CSA acceptance; that experiment did not alter CSA counts.
See [metered socket evidence and limits](plug-energy-validation.md).

**CSA23: TC-SU-2.5 manual PASS, run446**, five verification steps and evidence
upload. The previous binary returns Idle after Discontinue but retains the
verified download; an optional application discard callback now removes the
host candidate. Failed removal revokes candidacy and logs failure. The existing
Apply action/timer policy is unchanged. Peer traces and monotonic logs confirm
Proceed/180 at 180.001 s, Await/60 at 120.208 s
and Await/180 at 180.267 s, with exact token/version and request-count checks.
Five full scenarios pass under Memcheck: nine host boots, 260,130 matched
allocations/frees, zero errors/leaks. Separate Await/retry/update/restart and
Discontinue ASan/UBSan/LSan scenarios pass; each build passes eight focused
CTests. Counts: **97 PASS, 14 FAIL, 10 BLOCKED, 37 MANUAL, 704 NA**; this is manual
acceptance, not automatic CSA coverage or certification. Other rows are inherited.
Consumers must rebuild for the appended optional OTA port callback. See
[CSA23 evidence and limits](csa23-validation.md) and [delta](csa23-results.json).
The separate automatic Python case is now recorded in CSA24 above.

**CSA22: TC-SU-2.4 manual PASS, run445**, with its required verification step
and evidence upload. Peer JSON traces prove ApplyUpdateRequest uses the latest
QueryImageResponse token and the authenticated image version, for separate
version 1-to-2 and 1-to-3 simulations. A valid signature with a different version
is rejected before Apply/Notify and keeps the installed version unchanged.
The OTA engine already enforced this binding; the change strengthens its oracle
and native copied-context regression. Counts are now **97 PASS, 14 FAIL,
11 BLOCKED, 36 MANUAL, 704 NA**; manual PASS is separate from automatic coverage.

Read/Subscribe now allocate input at actual received length and output according
to configuration. RX supports 1202 application bytes; TX supports 1198, reserving
four additional wire bytes for a piggyback ACK. These follow the 1280-byte IPv6
UDP ceiling, not a larger transport. Native cases cover 83 filters, 1025/1198/1202
byte requests, oversize rejection and allocation failure. Linux passes 11 focused
tests in normal and sanitizer builds; Windows passes five. Full IM and OTA
scenarios pass under Memcheck and separately ASan/UBSan/LSan. See
[CSA22 evidence, commands and limits](csa22-validation.md).
**Next: CSA23 — TC-SU-2.5, ApplyUpdateResponse actions and real delay/retry timing.**

DataVersionFilters recovery fixes a reproduced Apple Home resubscription failure:
the old 16-entry table rejected a 547-byte SubscribeRequest with ResourceExhausted.
Read/Subscribe now allocate exactly the validated filter count, bounded by the
existing request byte budget, with no allocation for empty lists. Native tests
cover 70 filters, malformed tails, conflicting versions and allocation failures;
the added Subscribe allocation variant checks cleanup. Four focused tests pass
on Windows, Linux and separate Linux ASan/UBSan/LSan builds. Independent CHIP
scenarios pass under Memcheck and separately under sanitizers: 17 cluster filters,
fresh CASE, filtered priming, live On/Off reports and RemoveFabric. Memcheck has
31,177 matched allocations/frees, zero errors and zero live bytes. The preserved
Windows pairing recovered; the user confirmed Apple Home online and On/Off.
This is local interoperability evidence; the CSA matrix is unchanged.
See [details and limits](im-version-filters-validation.md). Next remains CSA22.

CSA21 fixes OTA recovery after a provider process restart: exhausted outbound
MRP retries retire only that peer's operational session, so a later operation
establishes CASE. The preceding binary reproduces unknown-session drops and
fails the full retry scenario; the new native regression fails with the old code.
**TC-SU-2.3 passes as a manual TH procedure in run444**: complete transfer and
interruption/retry, evidence upload, consent/HTTPS/resumption N/A. The fixed
interruption scenario waits 301.021 real seconds, independently reads Idle /
version 1, and completes a new transfer from offset zero without restarting or
recommissioning the requestor before retry. Uninterrupted and interrupted OTA
pass under Memcheck: four requestor boots, 111,042 allocations/frees, zero
errors/leaks. Each build passes 13 focused CTests with no compiler warnings.
A separate ASan/UBSan/LSan interruption/retry run waits 301.053 seconds and
completes both requestor boots with clean exits and empty stderr.
Latest matrix: **97 PASS, 14 FAIL, 12 BLOCKED, 35 MANUAL, 704 NA**;
this manual PASS does not increase automatic coverage. Other official rows are
inherited. See [CSA21 evidence](csa21-validation.md), [delta](csa21-results.json)
and [fixture contract](../ota-host.md). Host simulation is not firmware installation
or certification; Windows, hardware and Home UI acceptance remain unperformed here.
**Next: CSA22 — TC-SU-2.4, ApplyUpdateRequest fields and token/version binding.**

CSA20 fixes an early OTA retry after repeated AnnounceOTAProvider: the
conservative 120-second floor now survives asynchronous CASE setup and starts
from Invoke completion. The old binary reproduces 119.862/119.858-second
intervals; the new native regression fails with the old code and passes with
the fix. **TC-SU-2.2 passes as a manual TH procedure in run443**: six evaluated
steps, optional HTTPS N/A and evidence upload. Actual provider responses cover
UpdateAvailable, Busy/60, NotAvailable, Busy/180, both same/older versions and
an invalid BDX URI. Busy limits pass at 120.239 s between queries and 180.247 s
from the response respectively. All seven scenarios pass under Memcheck:
10 C requestor boots, 315,962 allocations/frees, zero errors/leaks. Separate
ASan/UBSan/LSan update/restart and 11 focused CTests per build pass.
Latest matrix: **97 PASS, 14 FAIL, 13 BLOCKED, 34 MANUAL, 704 NA**;
the changed row stays MANUAL with recorded PASS, not automatic CSA coverage.
See [CSA20 evidence](csa20-validation.md), [result delta](csa20-results.json)
and [fixture contract](../ota-host.md). Other official rows are inherited.
**Next: CSA21 — TC-SU-2.3, applicable OTA image-transfer procedures and failure paths.**

CSA19 prepares the official CHIP OTA provider, a signed simulation image and
restart orchestration. **TC-SU-2.1 passes as a manual TH procedure in run442**:
three evidence-based prompt decisions and the attached log, not automatic CSA
assertions. Run441 is retained as cancelled at the CLI upload step. The single
row moves BLOCKED to MANUAL with a recorded manual PASS; latest matrix:
**97 PASS, 14 FAIL, 14 BLOCKED, 33 MANUAL, 704 NA**. Other rows are inherited.
The MANUAL count includes this completed procedure and otherwise unexecuted work.
Full BDX/authentication/simulated restart/fresh CASE scenarios pass normally,
under Memcheck (55,065 allocations/frees, zero errors/leaks) and separately under
ASan/UBSan/LSan. C/H sources and binaries are unchanged from CSA18. This is not
executable firmware installation or certification. See [CSA19 evidence](csa19-validation.md),
[result delta](csa19-results.json) and [fixture contract](../ota-host.md).
Manual Home removal/re-add remains pending; user fabrics are not lab fixtures.

The entries below retain preceding campaigns; the newest entry supersedes
their next-task pointers without changing inherited results or limitations.

CSA18 completes the targeted energy fixture for the existing three-phase host.
Unchanged official **TC_EPM_2_2 passes on EP1/3/4/5 (runs435–438)** and
**TC_EEM_2_2/2_3 pass on EP1 (runs439/440)** after baseline run434 reproduces
the missing trigger route. Latest matrix: **97 PASS, 14 FAIL, 15 BLOCKED,
32 MANUAL, 704 NA**; only those six previously blocked rows change classification.
Optional ActiveCurrent/aggregate Voltage steps stay N/A. Normal and separate
ASan/UBSan/LSan focused tests pass 9/9; full pair memory/controller results and
source/binary identities are in [CSA18 evidence](csa18-validation.md) and its
[result delta](csa18-results.json). Default non-fixture behavior, public core
API and PICS are unchanged. This is Linux x86 acceptance, not certification.
Manual Home removal/re-add remains pending;
no user-paired state is used for laboratory campaigns.

The CSA17 review is resolved by enabling the existing DataVersion reporting
policy for Meter Identification attributes. **TC_MTRID_3_1 PASS (run336)** and
**TC_MTRID_2_1 PASS (run337)** on unchanged official scripts. Latest matrix:
**91 PASS, 14 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows are inherited.
Full pair Memcheck and separate ASan/UBSan/LSan pass, as do single-host
restart/recommissioning and selective/last-fabric removal. Last-fabric removal
returns SUCCESS before the host exits; the other fabric survives selective
removal and restart. Manual Home UI acceptance was not repeated.
See [review and limits](csa17-review-validation.md) and
[current delta](csa17-review-results.json). **Next: manual Home removal/re-add
acceptance on a running node, keeping existing user fabrics separate from lab
state.** No node was left running after this laboratory campaign.

The following entry preserves the earlier handoff; the follow-up above supersedes
its STOP status and outstanding tests.

CSA17 is **STOP for review**, with **TC_MTRID_3_1 still FAIL**. Pre-existing
official run334 rejects SET; run335 accepts it but step10 compares the first
queued pre-SET MeterType=2 against the saved base value. The origin of that
unchanged report remains unresolved. The two-unsuccessful-fixes gate prevents
a third correction/attempt. The opt-in host fixture and stricter local oracles
are retained; current Linux normal/sanitized builds and eight focused tests
per variant pass. Current full pair memory/controller acceptance and MTRID2.1
rerun remain outstanding. Matrix stays **90 PASS, 15 FAIL, 21 BLOCKED,
32 MANUAL, 704 NA**. See [CSA17 evidence](csa17-validation.md) and
[delta](csa17-results.json). **Next: main-reviewer decision on the pre-SET
subscription callback before any further implementation/campaign.**

CSA16 reproduces **TC_CADMIN_1_10 FAIL (run 333)** on the unchanged CSA14
binary: step 9 awaits a RevokeCommissioning response over PASE. Core 1.6.1
11.19.8.3 says the PASE caller SHALL NOT expect a response because revocation
terminates the session. This confirms the CSA02 discrepancy; implementation
work stops for review with no workaround, C/test/PICS changes or new build.
Latest matrix stays **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**.
See [CSA16 evidence and decision](csa16-validation.md) and
[baseline delta](csa16-results.json). CSA17 above records the subsequent
Meter Identification fixture work and its unresolved subscription acceptance.
The known step 9 discrepancy awaits consolidated CSA/test resolution and does
not block independent work. Later-stage commissioning failure counting
remains unassessed; successful PASE alone is not successful commissioning.

CSA15 corrects the TH Wi-Fi parameter fixture: **TC_CNET_4_9 passes (run 332,
25 records)** on the unchanged CSA14 binary. Run 331 preserves the initial
empty-effective-SSID failure. **TC_CNET_4_11 was not rerun**: the TH VM has no
Wi-Fi interface/wpa_supplicant for the script's two-AP transition. Its historical
official FAIL remains; the new environment blocker is recorded separately.
Latest matrix: **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**, with other
rows inherited. The extended pair oracle covers simulated network migration,
authentication errors, rollback, commit and instance isolation.
Full Memcheck and separate ASan/UBSan/LSan runs pass; Memcheck reports zero
errors/leaks, 49,628 allocations/frees and no suppressions. C/binary identities
match CSA14; native builds/CTest were not repeated for this Python-only change.
See [CSA15 evidence and fixture limits](csa15-validation.md) and
[result delta](csa15-results.json). No C source, API, PICS or official assertion
changed. CSA16 above records the subsequent TC_CADMIN_1_10 normative review.
Retain CNET 4.4 pending CSA resolution and 4.11 pending its network fixture.

CSA14 adds explicit `--wifi-sim-connected` startup for the host, preserving
saved settings and the existing empty-network default. **TC_CNET_4_1 passes
(run 329)** after baseline run 327 fails on the missing connection.
**TC_CNET_4_4 remains FAIL (run 330)**: it now reaches ScanNetworks but omits
ArmFailSafe, receiving the FAILSAFE_REQUIRED required by Core 1.6.1 11.9.7.1.
No test assertion or server protection was relaxed; no CSA waiver was obtained.
Latest matrix: **89 PASS, 16 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited. Six focused tests pass normally and with ASan/UBSan/LSan.
Two-instance Memcheck and separate sanitizer scenarios pass, including connected
Wi-Fi, guarded/armed scans, Breadcrumb and rollback; zero Memcheck errors/leaks.
See [CSA14 evidence and discrepancy](csa14-validation.md) and
[all attempts](csa14-results.json).
CSA15 above records the subsequent removal/migration fixture work.

CSA13 removes the premature full-table error from RCAC admission. A verified
pending root uses the existing journal slot; **AddNOC returns TableFull** when
all five fabric slots are occupied. **TC_CADMIN_1_19 passes (run 325)** after
baseline run 324 reproduces IM ResourceExhausted at AddTrustedRootCertificate.
**TC_OPCREDS_3_1 also passes (run 326)** with its unchanged official assertions.
Latest matrix: **88 PASS, 17 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited. Six focused tests pass normally and with ASan/UBSan/LSan; the
old-code control fails. Full two-instance Memcheck and separate sanitizer runs
pass, with zero Memcheck errors/leaks. No pool, API or storage-schema expansion.
See [CSA13 evidence and limits](csa13-validation.md) and
[all attempts](csa13-results.json).
CSA14 above records the subsequent Wi-Fi fixture acceptance and open discrepancy.

CSA12 closes the initial/enhanced commissioning window after 20 failed PASE
attempts. Notifications are one-shot, counters belong to each runtime/window,
and existing CASE administration survives. **TC_CADMIN_1_9 passes (run 322)**
after baseline run 321 reproduces acceptance of the correct PIN after twenty
failures. **TC_CADMIN_1_11 also passes (run 323)**; four Basic Commissioning
feature records remain N/A. Latest matrix: **87 PASS, 18 FAIL, 21 BLOCKED,
32 MANUAL, 704 NA**; other rows are inherited. Five focused tests pass normally
and with ASan/UBSan/LSan, and the old-runtime control fails as expected. Full
two-instance Memcheck and separate sanitizer runs pass, with zero Memcheck
errors/leaks. See [CSA12 evidence and limits](csa12-validation.md) and
[all attempts](csa12-results.json). Counting failures after successful PASE is
outside this repair and remains for separate acceptance.
CSA13 above records the subsequent full-table commissioning acceptance.

CSA11 fixes excess unchanged Operational Credentials reports, empty attribute-only
updates before MaxInterval, and premature cancellation on late heartbeat wakeups.
**TC_RR_1_1 passes (run 319)** with five fabrics, three controllers/subscriptions
each and the optional unchanged-CASE-session-ID check. **TC_IDM_4_3 also passes
(run 320)**. Session/subscription limits and public function signatures are unchanged.
Latest matrix: **86 PASS, 19 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited, not rerun. See [CSA11 evidence](csa11-validation.md) and
[all seven attempts](csa11-results.json), including intermediate failures and
the limits of RR group-resource coverage.
Seven focused tests pass normally and with ASan/UBSan/LSan. Full two-instance
Memcheck reports zero errors/leaks; the separate sanitizer scenario also passes.
CSA12 above records incorrect-passcode and window-lifecycle acceptance.

CSA10 adds missing host DNS-SD service/subtype enumeration, including the subtype
listing used by CHIP/TH. **TC_SC_4_1 passes (run 312)** for enhanced commissioning
and Extended Discovery; its 9 Basic Commissioning Window records remain N/A for
the existing profile. **TC_SC_4_3 also passes (run 313)**. Baseline run 311 and
the independent wire regression reproduce the missing listing before repair.
Latest matrix: **85 PASS, 20 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**, with other
rows inherited. Six focused tests pass normally and with ASan/UBSan/LSan;
35 wire checks and both full two-instance memory scenarios pass. Memcheck
reports zero errors/leaks. See [CSA10 evidence](csa10-validation.md) and
[all attempts](csa10-results.json).
CSA11 above records the subsequent resource/subscription acceptance.

CSA09 fixes delivery of required CASE failure StatusReports: the engine rejected
invalid input correctly, but the dispatcher closed before sending its output.
Reports now retain their MRP lifetime without creating a secure session or
continuing the handshake. The unchanged **TC_SC_3_4 passes all 13 recorded steps
(run 310)** after baseline run 309 reproduced the timeout. Latest matrix:
**84 PASS, 21 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows are inherited.
Seven focused tests pass normally and with ASan/UBSan/LSan, including a new
regression that fails against the previous dispatcher. Full two-instance
Memcheck reports zero errors/leaks; the separate sanitizer scenario also passes.
See [CSA09 evidence](csa09-validation.md) and [all attempts](csa09-results.json).
CSA10 above records the subsequent Commissionable Node Discovery repair/recheck.

CSA08 fixes General Diagnostics at the runtime boundary: TimeSnapshot now uses
the attached Time Synchronization UTC, and DeviceLoadStatus reflects actual IM
traffic and established subscriptions. Both unchanged official cases fail on
the previous binary and pass after repair: **TC_DGGEN_2_4 and TC_DGGEN_2_5,
2/2 PASS**. Latest matrix: **83 PASS, 22 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**;
unselected rows are inherited. Six focused native tests pass normally and with
ASan/UBSan/LSan. Full two-instance Memcheck reports zero errors/leaks; the separate
sanitizer scenario also passes. See [CSA08 evidence](csa08-validation.md) and
[all attempts](csa08-results.json).
CSA09 above records the subsequent invalid CASE input repair and recheck.

CSA07 fixes a reproduced host discovery race: closing and reopening the same
commissioning window before asynchronous withdrawal completed could leave mDNS
stopped. The host now drains the transition and selects a fresh DNS-SD instance
per new window, as required by Core 1.6.1 section 4.3.1. Real CASE command/capture
reproduction fails before the fix and passes after it; the new native lifecycle
regression agrees. Final official results: **4/4 PASS** (three TC_ACL_2_8 runs
and TC_CADMIN_1_25). Nine old-binary official repetitions also passed, so the
specific cause of historical run 289 remains unproven. Latest matrix unchanged:
**81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Six focused tests pass
normally and with sanitizers; full two-instance Memcheck and separate
ASan/UBSan/LSan scenarios pass. See [CSA07 evidence](csa07-validation.md) and
[all attempts](csa07-results.json).
CSA08 above records the subsequent General Diagnostics repair and rechecks.

CSA06 reruns all four applicable Access Control cases. Latest results: **2 PASS,
2 FAIL**. TC_ACL_2_4 expects ProxyView despite its D conformance in Core 1.6.1;
TC_ACL_2_6 checks only the first status of a legacy clear/add/add write, whose
actual response is Success/Success/ConstraintError. Both remain FAIL pending
explicit CSA resolution. No production behavior was changed. Negative write
regressions verify rejection without invalid storage/events and fabric isolation.
TC_ACL_2_8 first timed out in discovery, then passed unchanged; its intermittent
failure remains open. The latest-status matrix stays **81 PASS, 24 FAIL,
21 BLOCKED, 32 MANUAL, 704 NA**, with unselected results inherited.
Six focused tests pass normally and separately with sanitizers; full two-instance
Memcheck and separate ASan/UBSan/LSan scenarios pass. See
[CSA06 evidence and limitations](csa06-validation.md) and
[all attempts](csa06-results.json).
CSA07 above records the subsequent discovery investigation and bounded fix.

CSA05 passes **3/3 official rechecks**: TC_IDM_2_2, TC_IDM_4_2 and TC_IDM_4_3,
with no skipped steps. Shared Read/Subscribe validation rejects a specific
non-global attribute without a concrete cluster before callbacks or subscription
reservation. Global wildcard paths remain valid. The native grammar tests also
correct a previously incorrect wildcard expectation. Combined matrix:
**81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; unselected rows are inherited.
Six focused tests pass normally and separately with ASan/UBSan/LSan. Full
two-instance scenarios pass under Memcheck (zero errors/leaks) and separately
with sanitizers. See
[CSA05 evidence](csa05-validation.md) and [all attempts](csa05-results.json).
CSA06 above records the subsequent Access Control validation.

CSA04 passes **5/5 official rechecks**, including the previously failing
TC_IDM_4_3 and TC_CADMIN_1_25. Root no longer repeats unchanged values on meter
notifications, attribute-only subscriptions accept up to 32 selectors with
bounded capture/chunking, and committed fabric removal updates the open window's
AdminFabricIndex while preserving VendorID and window state. Combined matrix:
**80 PASS, 25 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Unselected rows are inherited.
Six focused tests pass normally and separately with ASan/UBSan/LSan. Full
independent-instance scenarios pass under Memcheck (zero errors/leaks) and
separately with sanitizers. See [CSA04 report](csa04-validation.md) and
[all attempts](csa04-results.json).
These CSA04 totals precede the CSA05 rechecks above. Timer/deadline
consolidation stays in the post-acceptance optimization stage of the roadmap.

CSA03 corrects Descriptor composition: Root includes OTA Requestor; opt-in
meter services include the identity-only Electrical Utility Meter and its
Meter Reference Point base alongside Electrical Sensor. No tariff condition or
billing device type is advertised. Official rechecks: **12 PASS, 1 FAIL** (test
VID in TC_IDM_10_1); TC_IDM_10_5 now passes. Combined matrix: **78 PASS, 27 FAIL,
21 BLOCKED, 32 MANUAL, 704 NA**. Full two-instance Memcheck and separate
ASan/UBSan/LSan scenarios pass; unselected CSA results are inherited.
See [CSA03 evidence and limits](csa03-validation.md) and [result delta](csa03-results.json).
These CSA03 totals precede the CSA04 rechecks above.

CSA02 fixes host clock scanning after removal from a sparse fabric table and
fail-safe cleanup waiting for a peer ACK after the commissioner has evicted PASE.
The expiry response now drains its local UDP operation before session-context
retirement and rollback. See [lifecycle acceptance](csa02-validation.md) and
[recheck evidence](csa02-results.json). The original CSA01 matrix below remains
the historical baseline; unselected tests have not been rerun.
The seven final rechecks yield **4 PASS and 3 FAIL**, moving the combined matrix
to **77 PASS, 28 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**. The three remaining
selected failures are documented test/specification discrepancies, not waived
results. Full two-instance Linux scenarios pass under Memcheck (zero errors and
zero live allocations at exit) and separately ASan/UBSan/LSan. These are the
historical CSA02 totals, before the CSA03 rechecks above.

CSA01 establishes the complete installed-catalog matrix for the current x86
profile: `--three-phase --source-registers --meter-services`, endpoints 0/1/3/4/5.
Final matrix: **73 PASS, 32 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**; no PLANNED
entries. There were 112 official runs for 109 entries, including retained attempts.
The [acceptance report](csa01-validation.md) and [matrix](csa01-matrix.json) retain
official results, endpoint-local PICS, versions, evidence hashes, manual procedures
and missing fixtures. This is a first broad acceptance pass, not certification.
All four historical failures reproduced; additional failures affect composition,
fabric/session lifecycle, reporting, discovery, diagnostics and resource pressure.
Some failures instead concern lab prerequisites, development identity or possible
test/specification discrepancies; none is silently waived.

MP04a: startup discovery failure traced to the pinned chip-tool `onnetwork-long`
selection path, which accepts an unrelated unsolicited announcement. Captured
PTR/SRV/TXT records have the correct discriminator/instance/port relationships.
The pair oracle uses unmodified chip-tool's `pairing code` path, which checks the
returned discriminator. The startup regression begins browsing before both full
runtimes start, without an announcement-settling sleep. The legacy tool path
remains unreliable in this situation; the C responder/API is unchanged.
See [MP04a evidence](mp04a-validation.md).
Discovery/commissioning selected the correct ports in all four final QR-path
runs. Three complete pair scenarios passed; the Memcheck A-then-B run failed
later at RemoveFabric (request ACK received, Invoke response timed out). That
independent acceptance failure remains open alongside the CSA01 failures;
it is not relabelled as a full-pair PASS.
CSA02's two final full-pair rechecks did not reproduce that timeout. Its cause
remains unestablished, so the historical issue is not considered fixed.

MP04 implemented: opt-in `--three-phase --meter-services` adds Identify and
Meter Identification on EP1 and Time Synchronization on EP0. Each instance owns
its callbacks/clock; the host persists Last Known Good time in an atomic sidecar.
Focused official CSA tests passed; this is not complete utility-meter support.
See [MP04 report](mp04-validation.md), [contracts](../meter-services.md) and the
[ordered acceptance roadmap](../roadmap.md).

MP03 implemented: opt-in `--three-phase --source-registers` adds a configurable
manufacturer-specific source cluster. It preserves tariff/quadrant/demand
registers, directional values, metadata and volume channels with explicit
units/provenance/nullability. Complete host and two-instance controller runs
passed under Memcheck and separate ASan/UBSan/LSan. Official TC_DESC_2_1 passed
with the new cluster attached; private schema checks remain separate.
See [MP03 report](mp03-validation.md)
for actual coverage, RAM cost and limitations. No firmware integration.

MP02 implemented and accepted for the x86 complete-pair simulator: opt-in
three-phase profile, Descriptor/TagList, multi-measurement EPM and explicit
EEM register mode. The default profile and constructors remain available.
Focused official CSA acceptance: 10/10 PASS. Independent chip-tool Read/Subscribe,
restart and two complete instances passed, including separate full Linux
Memcheck and ASan/UBSan/LSan runs. See [MP02 report](mp02-validation.md) for
commands, native tests, source-availability limitations and storage migration.

Protocol work targets Matter 1.6.1; this is an experimental partial implementation.
Complete callback-driven runtime, PASE/CASE/IM, commissioning, ACL, diagnostics,
power/energy measurement and simulated OTA are present. Linux/Windows host
adapters and an installable CMake package are included. Hardware integration and
a production OTA bootloader are outside the current validated scope.

The four historical official CSA failures remain unresolved and are reproduced
in CSA01. They are no longer the complete failure list:

- TC_CGEN_2_2: trusted-root count during the fail-safe scenario.
- TC_OPCREDS_3_4: RevokeCommissioning response timeout over PASE.
- TC_ACL_2_4: deprecated ProxyView behavior/profile expectations.
- TC_ACL_2_6: legacy ConstraintError expectation.

Later focused OPCREDS3.8/ACL2.8 runs passed, including separate Memcheck and
ASan/UBSan/LSan scenarios. These historical results do not constitute a complete
CSA matrix, certification or a fresh acceptance run of this public snapshot.
See validation.md for the publication snapshot and mp02-validation.md for the
subsequent three-phase acceptance; neither is a full-stack certification.

**Historical CSA01 follow-up: CSA02 - commissioning, fail-safe and selective fabric/session teardown.**
Full applicable CSA acceptance takes priority over new tariffs. Work proceeds in
successive passes over the [roadmap](../roadmap.md), with explicit coverage gaps,
evidence and follow-up actions. Address the connected CGEN/OPCREDS/CADMIN lifecycle
failures as one coherent implementation pass, including the independent
concurrent-subscription RemoveFabric regression from MP04a. Retain the remaining
CSA01 failures and blocked/manual coverage for subsequent passes.
