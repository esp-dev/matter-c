# CSA24b: chronological progress and subscription cleanup in the SDK test

**Full corrected TH run451: LOCAL-PATCH PASS, budget three/transport 56.**
This is a local correction of an external SDK test, not a CSA-approved release.
The unmodified Python TC_SU_2_5 campaign result remains FAIL from run450.
The local corrected result is separate; cumulative official counts do not change.

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
this corrected TH case. The unchanged C host uses transport 56 and the default
three subscriptions per fabric for the full acceptance below.

```sh
python tools/matter/tests/test_csa24_progress.py \
  --test-source /path/to/TC_SU_2_5.py \
  --helper-source /path/to/event_attribute_reporting.py \
  --original-source /path/to/original/TC_SU_2_5.py
python tools/matter/check_test_map.py
```

## Full local acceptance

Run451, titled `CSA24b-LOCAL-PATCH-progress-order-budget3`, passed all six TH
steps. It ran from **2026-10-17 14:29:03 UTC to 14:38:12 UTC**. The unchanged
requestor binary, provider, signed image and PICS are pinned in the
[result record](csa24b-results.json). The launcher repeated all 11 source
regression checks on TH before commissioning. The node used isolated state;
the subscription budget was three and transport capacity was 56 throughout.

The full automatic case verified:

- Both AwaitNextAction/provider-loss scenarios, with provider delays of 60 and
  180 seconds and unchanged-version observation windows of 120 and 180 seconds.
- Three complete, authenticated downloads of the 262342-byte image.
- Chronological progress reports in the final scenario: initial null reports,
  positive progress from 1 through 100, then a later null. There were 130 reports;
  the final sequence was `97, 98, 99, 99, 100, null`.
- The real provider IPC response: Discontinue (action 2), exactly one Apply request.
- Image disposal (file absent, size zero), final Idle, null progress and unchanged
  SoftwareVersion 1. Every original assertion remained enabled.

The operator applied the pinned patch to the root-owned SDK source after arming
automatic restoration. The first install reverted before launch because its
three-minute start window expired; no TH run started in that attempt. The retry
used an unprivileged waiting launcher so applying the patch automatically started
the prepared run, with a 30-minute fallback restoration window before start.
Only readiness prompts were answered during the test.

After the run, the root watcher restored the exact original source SHA-256
`91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`.
The reporting helper was unchanged. Ownership remained root and permissions 0644.
The guard stopped only the isolated fixture node, its stderr was empty, and TH
returned to idle. User-paired Windows nodes remain untouched.

CSA confirmation is still needed before replacing the official campaign result.
Other CSA cases have not been rerun, and no physical firmware, 128 kB fit or
certification is claimed. No C/H source was changed for this acceptance, and
Memcheck/sanitizers were not rerun for this test-only step.

Counts stay **97 PASS, 15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA**; see the
[result record](csa24b-results.json).

Next: **CSA25 — TC-SU-2.6 NotifyUpdateApplied**, retaining the original failures
and patch evidence for CSA review.
