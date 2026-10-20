# CSA68: automatic ApplyUpdateResponse test review

The remaining automatic **TC_SU_2_5** failure was already attributed in
CSA24a/24b. This step confirms that the installed test and helper still contain
the same behavior. No new native defect is demonstrated; no unchanged full
test is repeated. [Receipt](csa68-results.json) records fresh source checks,
offline controls and historical evidence identities.

## Evidence reused, rather than another full run

| Evidence | Outcome | Interpretation |
| --- | --- | --- |
| CSA23, YAML TC-SU-2.5, run446 | Manual PASS | Separate procedure, not automatic acceptance |
| CSA24, original Python run449 | FAIL | Fourth live subscription exceeded the declared budget of three |
| CSA24a, original Python run450 | FAIL | With capacity eight, reaches step5; history replay falsely signals download completion |
| CSA24b, locally corrected Python run451 | LOCAL-PATCH PASS | All six steps passed with budget three; not an approved CSA correction |

The current installed test SHA-256 is
`91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`;
the helper is
`038e99c144a66640375d483ae9e5a8fc5fbf6421d3b44129f6b1a5f7551be322`.
Both match CSA24a/24b exactly, before and after this read-only review. Archived
run450/451 result and log hashes were independently read again from the TH host
and match their committed receipts. Neither old result is a new execution.

## Exact failure and normative interpretation

The case keeps `progress_seen` in its download-progress predicate. The reporting
helper repeatedly evaluates that predicate against the entire report history.
For received values `null, 0, 1`, the first scan records positive progress.
The next scan replays the earlier null and falsely completes the wait. The same
problem affects `null, 1, 100` without a later null. The helper supports historical
matching; the case incorrectly uses it with a stateful chronological predicate.

In original run450, completion was announced at03:27:01.448 UTC after progress1,
without a later null. Provider IPC was read at03:27:01.552 UTC, before an
ApplyUpdateRequest: action0/count0 therefore failed the Discontinue/action2
assertion at line433. Test teardown then interrupted the ongoing download.
This is not evidence that the host completed the image and failed to request apply.

Matter Core R1.6.1, section11.20.7.5, defines UpdateStateProgress relative to
the current state, including null when progress is inapplicable. An earlier null
does not demonstrate a later transition. Suppressing legitimate initial nulls or
inventing progress would not repair the chronological test error. Section11.20.3.6
also retains the actual Await delay floor and Discontinue handling; neither is
changed here.

The separate resource failure is already addressed in the proposed test patch:
scenario subscriptions are cancelled/replaced between scenarios while preserving
both simultaneously needed subscriptions within a scenario. CapabilityMinimaStruct
(11.1.4.4) declares a supported subscription guarantee; KeepSubscriptions=false
(8.5.2.1) provides replacement semantics. Raising the host capacity alone let
run450 proceed, but did not fix the progress-order error. This review makes no
new claim about a currently running host's admission behavior or memory fit.

## Executed checks

On Windows, the existing `test_csa24_progress.py` was run against freshly read
installed sources. It executes the actual predicate/wait/helper AST with virtual
time, not a copied model of their logic. The original retains exactly three
failed controls: initial-null replay, 100-without-later-null, and scenario
subscription lifecycle. Its other eight controls pass.

The existing public patch was applied only to an ignored local copy with zero
context changes. The generated source matches the pinned CSA24b patched hash
`cb0e16c451093f51e153bd9d56c8d780bc8f1b7ceeaf06b94bad9136b929b588`.
All11 corrected controls pass, including original assertion/predicate preservation.
The two regression JSON hashes exactly match the earlier CSA24b evidence.
There was no installed-source patch, TH run, native C/H change, PICS change,
shared-network change or interaction with paired nodes.

Reproduction, with disposable source copies and the pinned helper:

```sh
python tools/matter/tests/test_csa24_progress.py \
  --test-source /path/to/TC_SU_2_5.original.py \
  --helper-source /path/to/event_attribute_reporting.py \
  --original-source /path/to/TC_SU_2_5.original.py
# Expected exit1: the same three control failures.

python tools/matter/tests/test_csa24_progress.py \
  --test-source /path/to/corrected/TC_SU_2_5.py \
  --helper-source /path/to/event_attribute_reporting.py \
  --original-source /path/to/TC_SU_2_5.original.py
# Expected exit0:11/11 controls.

python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
python tools/matter/check_test_map.py
git diff --check
```

See the existing [patch contract](../../tools/matter/patches/README.md) for pinned
source hashes and safe copy/apply/restore instructions. The full nine-minute
corrected run is historical CSA24b evidence, not acceptance of today's binary.
No new native build, Memcheck or sanitizer result is claimed in this analysis-only
step. No physical firmware or certification is verified.

## Disposition

Original automatic FAIL stays open. The [CSA question draft](csa68-csa-question.md)
is prepared, not sent; confirmation or an approved corrected test is still needed.
The generated queue now names the demonstrated test behavior instead of a
generic fixture investigation. Counts remain122 PASS/28 FAIL/5 prerequisites.
Re-run the full original procedure only when an accepted correction/test version
changes the ordering and lifecycle prerequisites; verify it offline first.

Next: **CSA69**, review TC_DA_1_2 attestation/provisioning prerequisites and prior
evidence, separating development identity/trust limitations from native defects.
