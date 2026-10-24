# Completing the CSA campaign

The goal is to execute every applicable test for the declared x86 profile, then
repair confirmed native defects and rerun the original failed procedures. This
is not a claim of product certification. Hardware/provisioning, external lab
requirements and unanswered CSA questions remain explicit open dependencies.
The owner performs the eventual GitHub push; this campaign makes local commits.

## Resume without losing state

1. Read `AGENTS.md`, this plan and [generated progress](csa-campaign-status.md).
2. Run `python tools/matter/csa_campaign.py`. It validates a reviewed CSA42
   checkpoint initially classifying157 applicable positions and705 NA, then applies later public
   classification changes. Historical outcomes are inherited, not rerun by this
   command. Older CSA report formats cannot all be replayed uniformly, which is
   why the checkpoint is explicit in [campaign data](csa-campaign.json).
3. Verify Git status and current lab state before starting any process. Preserve
   paired desktop nodes. Use disposable state, provider images and controller
   credentials for each scenario; raw traces and secrets stay in ignored folders.
4. Select the first executable item from the coverage queue. Read its original
   source and PICS plus the relevant Core/cluster/device requirements. Reuse prior
   investigation and fixtures; do not restart solved diagnosis or duplicate code.

## First pass: coverage before repairs

Run related cases in batches where one setup can produce independent, complete
evidence for each procedure:

- MRP counters and duplicate delivery: TC-SC-1.4, next as CSA43.
- Descriptor composition and device-type requirements: TC-DESC-2.1.
- BDX/OTA receiver: TC-BDX-1.2,2.2,2.3 using the existing OTA provider and image.
- Network list/reorder and diagnostic events: TC-CNET-4.13, DGGEN-2.2, DGWIFI-2.2.
- IM commands, read/write/subscription paths, events, resource/fabric isolation
  and group-key operations: IDM-1.1,5.1,6.1,6.2,7.1,8.1 and GRPKEY-5.4.
- Onboarding artifact/physical presentation: DD-1.3,1.4,1.6,1.7. Execute software
  checks where possible; actual label dimensions/material/placement require
  the real artifact and instruments, not a synthetic operator confirmation.
- Reassess SC-4.4 controller-role applicability and the three BLOCKED positions:
  DGGEN-2.1, GRPKEY-2.2 and DA_1_1. Check prerequisites before long runs. The
  previous CSA30 infrastructure timeout is retained; do not repeatedly launch
  multi-hour runs on an unverified harness.

A procedure may be executed even if it ends FAIL. Record original TH verdict,
actual wire/controller observations, skipped PICS steps and independent local
checks separately. An unavailable fixture or required human operation gets a
specific blocker, prerequisite and next action. Do not silently mark it NA,
claim it ran, or change the profile to remove inconvenient coverage.

## Coverage checkpoint after CSA50

Of155 applicable positions,150 have completed outcomes. Five prerequisites remain:
two final label artifacts, two limited-client fixtures/applicability questions and
DGGEN2.1's deferred long reset/controller run. There are no MANUAL/NOT_RUN entries.
Original DA1.1 factory reset/recommissioning passes. GroupKey2.2 completes with one
FAIL because its hardcodedID3 already exists; Core requires overwrite success.
Independent overflow/restart/reset acceptance passes; do not turn it into CSA PASS.

Available first-pass coverage is exhausted at these boundaries. CSA51 repaired terminal PASE failure replies; original TC-SC-2.3 is now PASS.
CSA52 repaired authenticated IM R=0 admission; original TC-SC-1.2 is now PASS.
CSA53 groups remaining assertions using original sources and earlier reports; bounded
GroupKey/BINFO reruns retain FAIL. CSA54 supplies actual two-device setup codes;
original automatic TC_SC_7_1 passes. CSA55 repairs GroupKeyMap admission/status
and confirms optional Leave EventStatus; original positive-capacity test remains
FAIL. CSA56 repairs host RX starvation; all four resource scenarios pass under
Memcheck and separate sanitizers. Original overflow-status question remains.
Earlier BDX no-query failure is a reason1/daily-schedule fixture mismatch.
CSA57 proves actual same-node BDX recovery with an explicit reason0 trigger; the
original optional BlockAck wording remains a CSA question. Continue CSA58 with a
bounded stable rerun of previously passing automatic suites, grouped by reset and
commissioning lifecycle. Retain the owner's deferred multi-hour DGGEN run and physical/client prerequisites explicitly;
do not loop on an unverified harness. After attributed fixes, triage remaining
FAILs by actual assertion and rerun originals where meaningful.

## CSA58: frozen automatic regression sweep

Rerun all 99 positions currently classified automatic PASS, using exact
case/endpoint/collection identities. Keep the 18 existing automatic FAILs,
37 manual procedures and deferred DGGEN 2.1 outside this regression queue; their
outcomes and prerequisites remain visible in the campaign.

The execution order is YAML (9), composition (13), measurements (18),
interaction/security (34), commissioning (20), setup codes (3) and resource tests (2).
Use the frozen CSA56/57 native host, verify all 362 current C/H inputs and the
binary hash, then freeze original test/support sources and current per-endpoint
PICS snapshots. Supply actual energy/Meter Identification test triggers and two
real setup-code instances where the original procedure needs them.

Each position gets a new native process and empty state; do not reuse a previous
commissioning snapshot. Actual in-test factory-reset requests restart only the
disposable instance. Keep the same binary across every lifetime. The temporary
local PAA is scoped to the run and removed on completion. Record original TH run
IDs, step outcomes, source/PICS/receipt hashes, cleanup and any setup faults.

Per-case deadlines bound the run; longer commissioning-window and resource
procedures retain their full observation periods. Stop on a harness/fixture
boundary, inspect it and resume from completed receipts instead of blindly
repeating or converting an ERROR into a DUT FAIL. Preserve every superseded
attempt. Paired desktop nodes and controller stores remain outside this run.
No publication or change to original tests is part of this stage.
After the complete frozen sweep, allow one unchanged confirmation of a newly
failing position to distinguish a repeatable failure from instability. Preserve
the first FAIL and report the confirmation separately, rather than replacing
the sweep outcome with a later green result.

CSA58 completed all 99 primary positions (96 PASS/3 FAIL). Two original tests
pass after correcting the Wi-Fi in-test mode and the live QR input. The unchanged
Timed Write case fails twice, so effective acceptance is 98 PASS/1 FAIL; this is
not a stable green sweep. All 102 original receipts remain in
[the report](csa58-validation.md), including setup mismatches and confirmation.
Next: CSA59, capture actual Timed Write packet times, response status and
attribute side effects, separate native lifecycle/deadline behavior from peer
busy-wait scheduling, and fix only an attributed native defect. Keep the original
case unchanged; require focused timed/error-path and full memory acceptance
before returning to the older failure-closure queue.

## CSA59: Timed Write attributed; original FAIL retained

Completed: [CSA59 receipt](csa59-results.json) and [analysis](csa59-validation.md).
First TimedRequest admission hits a pending RX; MRP retries it about 1.414 s later.
Success is sent only then. Actual Write arrives 1.56 ms after that response, within
700 ms, and correctly changes NodeLabel. Original test 603 still fails; its busy
wait does not establish that the native interval expired. No native workaround,
original-test patch, PICS change or automatic-PASS reclassification was made.

Independent real-delay PASE probes require global TIMEOUT, unchanged NodeLabel,
no window restart on an expired duplicate, and a different successful recovery
label. Full two-fabric commissioning/CASE follows. 41 checks plus 2 existing
conformance controls pass per memory variant; Memcheck has zero errors/live
blocks, separate ASan/UBSan/LSan is clean, and clean focused builds pass 4/4 each.
The probe does not claim delayed CASE write coverage or a new full-suite PASS.

Next: CSA60, revisit CSA28 before preparing a deterministic provider fixture for
original TC_SU_2_2 QueryImageResponse scenarios. Preserve earlier outcomes and
separate fixture/infrastructure faults from native defects. Keep the Timed Write
CSA clarification and the general ingress-load/queue-efficiency question open.

## CSA60: explicit OTA query; original step3 FAIL retained

Completed: [receipt](csa60-results.json) and [analysis](csa60-validation.md).
The local query API advances an application opportunity while retaining mandatory
spacing, provider delay, urgent jitter and growing failure backoff. No original
CSA/PICS/default-policy edits. Original605 fails step3 after provider restart and
query failure; step2 PASS alone does not prove NotAvailable was received.
Full signed-update memory scenarios pass, but one fast-reboot sanitizer event
scenario misses Applying. Keep that functional failure separate from clean
memory diagnostics and the different delayed-apply scenario that passes.

Next: CSA61, unchanged TC_SU_2_7 using the explicit local query fixture. Attribute
Applying event generation/delivery/capture across simulated reboot before fixing
only a confirmed native defect. Do not rerun already-attributed TC_SU_4_1 status
vector assumptions without new evidence. No full-suite/certification claim.

## CSA61: original event startup-order failure confirmed

Completed: [receipt](csa61-results.json) and [analysis](csa61-validation.md).
Original606 fails step1 before Applying. This is the same default-provider query
before event callback issue documented in CSA26. Checkout helper does not queue
initial reports; a separate late subscriber proves the earlier Querying event is
available. Independent14 checks per memory variant pass, with no memory errors
or leaks. Native sources/binaries match CSA60; no new build or policy change.

Next: CSA62, attribute the instant-reboot Applying capture gap from CSA60. Trace
state-event generation, queued reliable reports, shutdown and restart boundaries.
Fix only an attributed native or host-lifecycle defect, preserve correct polling
and original tests. Do not repeat the known original startup-order failure until
observation prerequisites change. Keep external questions and untouched original
outcomes visible; successful alternative-delay cases do not close this gap.

## CSA62: Applying drain repaired; memory and timeout controls accepted

Completed: [receipt](csa62-results.json) and [analysis](csa62-validation.md).
The frozen old host reproduces lost events at a5s subscription minimum. New
runtime readiness observes confirmed event cursors; the existing host loop waits
until ready or its30s policy deadline. No allocation, thread or library timer.
Full update passes21 checks under Memcheck and separately sanitizers. Prior
Busy180 passes24; a60s negative control deliberately retains raw FAIL while
proving bounded ready0 shutdown. Focused CTests11/11 each, no memory errors/leaks.
Original FAIL606 is not rerun because it stops before Applying; counts unchanged.

Next: CSA63, attribute actual QueryImage response reception and preserved retry
backoff at the provider-restart boundary retained in CSA60 TC_SU_2_2. Use the
existing trace rather than repeating known preconditions; fix only a confirmed
native defect and preserve the original test/PICS and actual timing requirements.

## CSA63: provider handoff attributed; original FAIL retained

Completed: [receipt](csa63-results.json) and [analysis](csa63-validation.md).
Unforced original607 receives a valid UpdateAvailable from the old provider before
its shutdown; step2 inherits Downloading. Separate injected-loss608 confirms old
CASE-session drops, MRP timeout and transport failure followed by240s backoff.
Step2 PASS is not an actual NotAvailable response; step3's120s wait then expires.
This diagnostic is consistent with605 but does not prove its historical cause.
No production correction or test/PICS workaround is justified. Original FAIL stays.

Independent decoded NotAvailable acceptance passes13 checks per memory variant;
Memcheck zero errors/live blocks, separate sanitizers clean. Clean query CTests2/2
each include a public-API Busy/error/backoff/actual-response failure-reset chain.
Temporary processes and PAA are cleaned up; paired Windows nodes remain untouched.
Clarification questions about provider lifecycle, actual responses and permitted
retry observation windows are drafted locally, not sent. Counts stay unchanged.

Next: **CSA64**, extend the controlled provider restart through the next permitted
retry, prove fresh CASE and complete signed OTA recovery. Do not infer recovery
from a scheduled deadline, accelerate native timing or relabel diagnostics as
original CSA PASS. Keep the deferred long DGGEN and external prerequisites open.

## CSA64: full normal recovery; sanitizer pre-handshake failure remains

Completed: [receipt](csa64-results.json) and [analysis](csa64-validation.md).
Normal Memcheck passes27/27 through the actual240s backoff, new resumed CASE,
signed BDX/apply/reboot/Notify and fresh version2 readback. Both native boots have
zero errors/live blocks. First full-only verifier FAIL is retained; the corrected
oracle accepts the normative full/resumed paths and passes13 offline controls.

Separate sanitizer execution fails after9 passing checks: events prove240024ms
before its next attempt, then32ms to Idle/Failure. No new CASE or decoded QueryImage
reaches the replacement peer. Empty sanitizer stderr is not full OTA acceptance.
Root cause is not attributed; no native/original-test/PICS workaround or result
reclassification. Cleanup completes, paired Windows nodes untouched, counts unchanged.

Next: **CSA65**, add scoped diagnostics at resolver admission/completion, outgoing
preparation and CASE creation, then make a bounded repro of the early failure.
Reuse the failed trace and avoid blind multi-minute repeats. Change production
code only after attribution; require complete memory acceptance for a fix.

## CSA65: historical VM outage correlated; no native fix justified

[Receipt](csa65-results.json) and [analysis](csa65-validation.md) retain the
CSA64 functional FAIL and original607. The supplied journal confirms a VM link/
address outage spanning the estimated failed attempt around10:01:46 UTC. The
10:01:53 receipt was delayed delivery of earlier monotonic-timestamped events.
Exact native branch/errno was not captured; no speculative production fix.

Four distinct diagnostic full updates pass27 checks each; three include LSan,
while the GDB run explicitly disables it under ptrace. Instrumentation/timing
limits remain. All362 tracked C/H files and original binaries retain identity;
no original test/PICS, paired-node or campaign classification change.

Next: **CSA66**, controlled same-instance transient-network recovery with
first-error capture. Isolate the fault to the test process, preserve real retry
guards and do not disconnect the shared VM/SSH interface. Fresh-state diagnostic
passes do not establish recovery of the same instance after interface loss.

## CSA66: controlled resolver send failure and full recovery pass

[Receipt](csa66-results.json) and [analysis](csa66-validation.md) prove one
ENETUNREACH followed by same-instance full CASE and signed simulated OTA, without
recommissioning or provider restart. Independent25 checks per memory variant;
actual event retry gaps120020/120027ms, full two-boot Memcheck zero errors/live
blocks and separate ASan/UBSan/LSan. Hook controls36 each, four offline oracle
controls and five rejected CLI combinations pass. No native/test-PICS workaround
or original CSA result change; the historical CSA64 functional FAIL remains.

Next: **CSA67**, bounded resolver receive-error recovery with first-result capture
using the existing public API and a process-local fault. This send-failure result
does not prove interface/address replacement or recovery from a fatal RX error.
Do not disconnect the shared VM or blindly rerun already-attributed original
failures. Reproduce a native defect before changing code.

## CSA67: fatal receive offline latch repaired

[Receipt](csa67-results.json) and [analysis](csa67-validation.md) retain the
old-library functional failure after one ENETDOWN. New admitted owner requests
reopen the existing backend sockets; failed partial reopen preserves ID/results
and permits a later request. No new thread, timer or core dependency.

API33/35 checks, full signed OTA25/25 and CTests8/8 pass per memory variant;
full Memcheck zero errors/live blocks and separate ASan/UBSan/LSan. Partial-open
descriptor check excludes the explicitly inherited diagnostic log, not a hidden
resolver socket. Existing send controls36 each remain green. No original CSA
result/PICS change or historical CSA64 errno attribution is claimed.

Next: **CSA68**, review remaining automatic TC_SU_2_5 against prior CSA20/23/53
evidence and the unchanged installed script. Check existing attribution first;
rerun only when a verified prerequisite changes. Actual local address replacement
and Windows execution remain outside this acceptance.

## CSA68: automatic ApplyUpdateResponse failure already attributed

[Receipt](csa68-results.json) and [analysis](csa68-validation.md) reconfirm
CSA24a/24b: retained original450 FAIL versus explicitly local-corrected451 PASS.
The installed test/helper and archived logs are byte-identical to that evidence.
The original repeats the same three offline control failures; the existing patch
passes11/11. No full TH repetition, native change or new current-host OTA claim.
The generated queue now points to this attribution instead of generic fixture review.

The [CSA question draft](csa68-csa-question.md) is prepared, not sent. Full rerun
requires an accepted correction or a verified approved test version. Device-side
progress suppression or inflated capacity is not a remedy. Preserve both original
FAIL and historical local PASS, plus the separate manual YAML result.

Next: **CSA69**, review TC_DA_1_2 development-attestation/provisioning prerequisites
and prior evidence before any rerun. Separate production identity/trust prerequisites
from a native verification defect. Known OTA tester defects do not need another
multi-minute run while their prerequisites remain unchanged.

## CSA69: separate development VID from certification-time CD policy

[Receipt](csa69-results.json) and [analysis](csa69-validation.md) preserve
original FAIL171 at step6.2. Installed source matches CSA01; current public CD
still uses0xFFF1/0x8001/type0. No new full run or native change. Test CD type0
is allowed at certification testing with signer/signature validation; the
manufacturer VID assertion independently rejects the simulation identity.
Do not repeat unchanged inputs or mark downstream signature checks as passed.

Re-run only with authorized consistent identity/trust inputs and an isolated
fixture supporting them, or accepted guidance for a development profile. No
borrowed VID, SDK-CI flag, weakened signature or synthetic PASS. This is an
identified provisioning prerequisite, not a demonstrated test or native defect.

Next: **CSA70**, review TC_DA_1_7 original evidence and distinct-device credential
requirements. Determine whether two isolated instances with separate attestation
keys can satisfy the unchanged procedure; never infer uniqueness from shared DAC
or a single simulated node.

## CSA70: two real instances and a cloned-key negative control

[Receipt](csa70-results.json) and [acceptance](csa70-validation.md) supersede
original TC_DA_1_7 FAIL172 with original611/612 PASS18/18. The fixture supplies
two setup payloads/node IDs and distinct DAC credentials; it changes no native
code, original test, PICS or assertions. Control610 reaches both DUTs and fails
only the final key-equality check when both use DAC-A. Full two-node Memcheck and
separate ASan/UBSan/LSan executions are clean; observed key hashes match fixtures.

Retain pre-run environment errors and suite ERROR609 with its cancelled case;
correcting the project's PAA path is not a native repair. The collector's first
ordering assumption is retained separately, with a multiset correction that still
requires two entries and preserves cloned-key multiplicity. Temporary PAA removed,
all stage nodes stopped, TH idle. Laboratory trust is not production PAA/DCL
qualification, physical manufacturing uniqueness or certification. TC_DA_1_2
retains its independent VID prerequisite. Counts now123 PASS/27 FAIL/5 prerequisites.

Next: **CSA71**, consolidate the remaining generic TC_SU_4_1 triage from CSA27
and verify current original script/helper identity before any repetition. Prepare
a specific CSA question if unchanged; do not repeat the known failure or distort
the native list-operation status vector to obtain a green first status.

## CSA71: preserve complete list-write statuses; reuse CSA27 attribution

[Receipt](csa71-results.json) and [analysis](csa71-validation.md) reconfirm
unchanged TC_SU_4_1/helper and original456 record/log hashes. The test checks the
successful first clear in[0,0,135] and stops before partial-state readbacks.
Existing CSA27 two-fabric/restart and memory evidence remains historical; no
network or offline regression repeated. Current source retains ordered per-IB
results and one provider per fabric. No native workaround, original-test change
or classification delta; the generated triage now points to this concrete issue.

The [CSA question draft](csa71-csa-question.md) requests accepted full-vector/client
aggregation handling while preserving partial-state and fabric-isolation checks.
It is not sent or approved. Re-run only on an accepted test change, verified client
aggregation change, guidance, or a demonstrated relevant native regression.
Matching script hashes does not establish identity of a compiled SDK binding;
the SDK directory's parent Git HEAD must not be misreported as its revision.

Next: **CSA72**, consolidate existing CSA clarification drafts and evidence into
one local review package. Group specification/test questions, provisioning and
physical/manual prerequisites; name the requested decision and exact rerun gate
for every remaining FAIL. No automatic sending or unchanged long-test repeats.

## CSA72: complete unsent review packet and lab activity check

The [review packet](csa72-questions.md) is rendered from [JSON](csa72-questions.json)
and covers all27 failed and5 prerequisite positions once, preserving exact
case/endpoint/collection identities.22 CSA question groups separate specification,
test, timing and applicability decisions;4 owner/lab groups cover identity,
physical Wi-Fi, labels and the owner-deferred long diagnostics run. Linked
evidence retains historical verdicts, run IDs, hashes and unexecuted portions.

Every item names the requested decision/input and exact rerun gate. No submission,
upload, automated sending, new test, PICS/source change or long-run scheduling.
The renderer checks current coverage, evidence identity and Markdown freshness:
`python tools/matter/csa_review_packet.py`. Update the packet deliberately when
campaign state changes; stale identities/verdicts must not remain silently current.

[Receipt](csa72-results.json) and [validation](csa72-validation.md) record read-only
CPU/process samples. No old CSA job was found and TH was idle. Initial DUT/TH
guest samples were0.14%/0.33%; Windows VMware later totalled about1% of host CPU.
A separate active memory-optimization worker then built/tested a different
workspace; a later DUT sample reached8.73%, followed by3.27% with Memcheck using
about one core. These measurements are not simultaneous or interchangeable.
The progressing worker was left untouched; its results are not CSA72 acceptance.
No process was killed or VM/service setting changed. Short snapshots do not
establish historical peaks or attribute every CPU cycle to this worker.

Next: owner review/prioritization, then explicit recipient/material authorization
before any sending. Continue only work whose prerequisite actually changed;
do not restart the deferred multi-hour diagnostics test or already-attributed
original failures merely to keep the campaign running. Counts stay123/27/5.

## CSA73: frozen memory integration accepted

The [integration plan](csa73-integration-plan.md) imports only40 committed changes
through Memory39 `6c9835a`; ongoing Memory40/later work is excluded. Candidate
`ff3a732` preserves CSA70..72 and matches the selected native source. Main advances
only after the [regression gates](csa73-validation.md) pass; the source checkout
and existing paired desktop nodes are preserved.

Fresh acceptance:99/99 original automatic PASS positions, Windows112/112 CTest,
Linux109/109 per build, complete pair/wire/IPv6 scenarios under Memcheck and
separate sanitizers, signed simulated OTA and25 offline decoder checks. Raw
original outcomes and source/PICS/binary identity remain in [the receipt](csa73-results.json).
No additional native repair or new failure was found. Counts stay123/27/5;
historical manual outcomes, existing failures and their CSA72 prerequisites remain.

Next: separately review a frozen Memory40 delta with its Read lifetime/report
regression. Do not silently absorb a moving source branch or reinterpret this
automatic PASS-set regression as a fresh155-position full-matrix PASS. No push.

## Evidence and commits

Each finished batch must have a public `csaNN-results.json` and concise validation
report. Include exact case/endpoint/collection identities, source/PICS hashes,
original run IDs/outcomes, interpretation limits and one next task. Update the
campaign with `python tools/matter/csa_campaign.py --write` and verify it again.
Keep earlier failures and superseded attempts visible in their evidence chain.
A mistaken applicability classification may be corrected only with original
source, current TH API exclusion and the unchanged PICS fingerprint. Preserve
the checkpoint and record the correction as a new explicit delta. Manual blockers
require a specific prerequisite and must remain visible in the generated queue.

For runnable-host changes, run a full relevant Linux scenario under Memcheck,
then separately ASan/UBSan/LSan, plus focused tests for the affected mechanism.
For an external tester-only batch, reuse proven binaries only after checking
native source/binary identity; still collect appropriate end-to-end memory and
recovery evidence. Avoid broad repetitive tests that add no coverage. Report
what was compiled, run or not verified accurately.

Review every diff, inventory, report/count/link consistency and private-data
exclusions; commit the completed batch before starting the next. No push. A
long running test is RUNNING until a final result exists; retain process/run
identity so it can be resumed rather than submitted twice.

## Second pass: repair only attributed native defects

After executable first-pass coverage is exhausted, review every remaining FAIL.
Separate native implementation defects, missing test prerequisites, development
identity/provisioning limits, harness failures and specification/test questions.
The generated triage table intentionally leaves unreviewed failures UNTRIAGED.

Terminal PASE error delivery (CSA39) is repaired and original TC-SC-2.3 passes
in CSA51. Authenticated IM R=0 rejection (CSA41) is repaired and original
TC-SC-1.2 passes in CSA52. Remaining failures require assertion-level attribution. Preserve correct
security/reliability rules while fixing those mechanisms. Do not reduce a
standards-correct retransmission count or weaken certificate/access checks to
match a questionable procedure. Keep such CSA clarification items open.

For each native fix: reproduce the actual failure, make the smallest shared
change, rerun the original test unchanged, exercise related error/recovery and
memory paths, record superseding outcomes, update the progress table and commit.
Only then take the next independent defect. Finish with a stable rerun of the
applicable matrix, documenting remaining external blockers and certification
limits. Google/Apple UI acceptance and later embedded integration remain later
phases from [the roadmap](../roadmap.md).
