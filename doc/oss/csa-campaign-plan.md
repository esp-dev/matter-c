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
