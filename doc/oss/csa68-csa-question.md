# Draft: TC_SU_2_5 progress ordering and subscription lifecycle

Status: prepared for review, not submitted. No CSA response or approval claimed.

## Environment and question

Matter Core R1.6.1; Test Harness v2.15.1+summer2026; SDK Python Tests,
TC_SU_2_5, endpoint0. Installed source fingerprints:

| File | SHA-256 |
| --- | --- |
| TC_SU_2_5.py | 91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb |
| event_attribute_reporting.py | 038e99c144a66640375d483ae9e5a8fc5fbf6421d3b44129f6b1a5f7551be322 |

Please confirm the intended chronological observation and subscription cleanup
for this test, and identify an approved correction or test release. We have two
reproduced concerns. Neither has been treated as an approved test defect or PASS.

## 1. Historical null can falsely end the download wait

In the test around lines404-424, `check_ota_download_matcher` retains
`progress_seen`. In helper lines470-489, `await_all_expected_report_matches`
rescans the complete history every100ms. Received sequence `null, 0, 1` sets
the flag on the first scan, then matches the earlier null on the second scan.
There is no null after positive progress. `null, 1, 100` also completes without
the later null expected by the predicate.

The offline reproduction executes the actual installed AST without SDK imports,
network traffic or source changes. In unmodified run450, the test read provider
IPC before an ApplyUpdateRequest had occurred, failing the Discontinue assertion
at line433 with action0/count0; teardown then interrupted an active download.

Section11.20.7.5 defines UpdateStateProgress relative to the current state;
initial null can be legitimate. Our interpretation is that a chronological
predicate must not treat a past null as a future completion transition. Should
the test consume the existing report FIFO once in receive order with a single
monotonic deadline, or use another approved observation mechanism?

## 2. Previous scenarios retain subscriptions

The original case can retain earlier scenario subscriptions when opening a fourth
one, although the publisher may declare the minimum of three. Unmodified run449
received RESOURCE_EXHAUSTED at line382 with a declared budget of three. With eight
available, run450 passes this boundary and exposes concern1.

Please confirm whether scenarios should cancel their previous subscriptions and
start the first subscription with KeepSubscriptions=false, retaining the second
subscription within each scenario. This preserves simultaneous version/state or
state/progress observation without requiring excess capacity. Relevant Core
sections are11.1.4.4 and8.5.2.1.

## Proposed correction and evidence

The [local patch](../../tools/matter/patches/TC_SU_2_5-progress-order.patch)
consumes the FIFO chronologically, bounds the complete wait with one deadline,
and cleans up scenario subscriptions. Every original assertion and the progress
predicate are preserved. It does not change provider IPC, DUT data, timers,
PICS, image disposal or version checks.

- Existing offline regression: original fails three of11 controls; proposed
  correction passes11/11. CSA68 repeated this against freshly read installed
  sources and reconfirmed identical results.
- Historical original run450: FAIL. Raw log SHA-256
  `9efb81375b423f734885b90b184f2a351c274c645b3eb917a627a37f5ebf9fd9`.
- Historical corrected run451: LOCAL-PATCH PASS, six steps, budget three,
  three complete262342-byte downloads, real Await60/180 scenarios, Discontinue
  action2/count1, image absent, Idle/null progress and unchanged version1.
  Raw log SHA-256
  `596bc15d2adb4e5021de9a7c5258efade9b9cc1f69a87ed93e20bad20a844607`.

See [CSA24b acceptance](csa24b-validation.md), [CSA68 review](csa68-validation.md)
and the [patch contract](../../tools/matter/patches/README.md). Raw SDK/test logs
are retained locally and are not included in this draft. No production identity,
credentials, keys, private network identifiers or paired-node state are attached.
Original FAIL remains in the campaign pending CSA guidance; the historical local
PASS does not certify the implementation or validate its current build.
