# CSA24b: chronological progress and subscription cleanup in the SDK test

**Prepared and regression-tested; full TH rerun awaits the operator step.**
This is a local correction of an external SDK test, not a CSA-approved release.
The unmodified Python TC_SU_2_5 campaign result remains FAIL from run450. No
automatic PASS or change to cumulative official counts is claimed here.

The memory requirement is recorded separately in commit `9a793f1`: allocate
individual live contexts on demand, with limits used for admission rather than
eager allocation of every possible transaction. The target device has 128 kB RAM.
The interim eager table from CSA24a is not an accepted final embedded design.
No allocation refactor or other C stack change is made in this step.

## Correction

The original progress predicate carries state between calls. Re-evaluating it
against the whole historical list falsely accepts an initial null after later
positive progress. The patch consumes the existing report FIFO once, in receive
order, with one monotonic deadline for the whole operation. The predicate itself
is unchanged. Initial null/zero do not establish completion, positive progress
without a later null does not complete, and repeated reports cannot extend the
deadline indefinitely.

State subscriptions from scenarios 3 and 4 are cancelled before moving on. The
first subscription in each scenario replaces previous publisher subscriptions;
the second retains the first. Scenario 3 starts SoftwareVersion first, whereas
scenarios 4/5 start UpdateState first. This preserves simultaneous version/state
or state/progress monitoring and permits testing with the Core minimum of three
subscriptions instead of relying on excess capacity.

Every original assertion is preserved, including exact provider action/request
count, image disposal, Idle, null progress and unchanged software version. The
timing scenarios, provider IPC and stack semantics are unchanged. No broad
reporting-helper modification, fake response or PASS override is introduced.

The public [patch contract](../../tools/matter/patches/README.md) records source
hashes, third-party attribution, apply/restore instructions and regression usage.
The installed reporting helper remains unchanged. The complete SDK/TH source,
credentials, local administrative tooling and generated state stay outside Git.

## Executed verification

The optional [source regression](../../tools/matter/tests/test_csa24_progress.py)
executes the actual test block/helper AST with deterministic clock and queue
adapters. Eleven checks run on the Windows host and separately on Linux. The
original fails three controls: initial null replay, accepting 100 without a later
null, and scenario subscription replacement. The corrected source passes all 11.
The assertion/predicate preservation check passes for both; the patch does not
remove original assertions. Negative controls include no positive progress,
invalid percentages, a null-only stream and repeated reports through timeout.

The inventory check passes with 235 mapped files, 87 native definitions, 59 core
sources and 75 public headers. The C/H files retain the CSA24a source-manifest
hashes. Its native/Memcheck/sanitizer results are prior evidence, not new runs of
this corrected TH case. The unchanged C host has been built with transport 56
for the planned three-subscription test; building it is not commissioning proof.

```sh
python tools/matter/tests/test_csa24_progress.py \
  --test-source /path/to/TC_SU_2_5.py \
  --helper-source /path/to/event_attribute_reporting.py \
  --original-source /path/to/original/TC_SU_2_5.py
python tools/matter/check_test_map.py
```

## Pending full acceptance

The installed SDK file is root-owned and not writable by the test account. A
reviewable local operator script is prepared to check the pinned original/patch,
arm automatic restoration, and apply only this test-file correction. The regular
launcher then verifies the source regression, starts an isolated node/state with
budget three/transport 56 and labels the TH run **LOCAL-PATCH**. Only readiness
prompts are answered. The guard restores the original source after the run and
stops only that fixture node. If no run starts, restoration occurs after 3 minutes.

Until that operator step and full rerun finish, the canonical source is unchanged
and this patch has no full TH result. Any subsequent corrected-run PASS must be
recorded separately from unmodified CSA acceptance. CSA confirmation is still
needed before replacing the official campaign result. Other CSA cases have not
been rerun, and no Windows ecosystem, physical firmware, 128 kB fit or certification
is claimed. User-paired Windows nodes remain untouched.

Counts stay **97 PASS, 15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA**; see the
[prepared-change record](csa24b-results.json).

Next: **finish the explicitly labelled corrected TH run, verify restoration and
then proceed to TC-SU-2.6 NotifyUpdateApplied**, retaining the original failures
and patch evidence for CSA review.
