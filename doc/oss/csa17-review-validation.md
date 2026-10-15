# CSA17 follow-up: reporting repair and RemoveFabric acceptance

2026-10-14. This follow-up reviews the previous STOP evidence, reproduces the
defect independently and completes the scoped repair. Historical runs334/335
and the [original handoff](csa17-validation.md) are retained. No official test,
PICS, cryptographic policy or public C API was changed.

## Findings and repair

The host calls `matter_server_changed` when energy samples arrive. Meter
Identification did not opt into the existing subscription DataVersion policy,
so unrelated samples re-published unchanged identity. The independent controller
reproduced this before the fix: subscription established, then baseline identity
reports arrived during two seconds without SET. This explains run335's queued
pre-SET values; it is an implementation issue, not an established CSA discrepancy.

`matter_meter_identification.c` now marks its four identity attributes as
version-reported. Refresh already changes DataVersion for a changed or invalid
snapshot, so genuine changes and unavailable transitions remain reportable.
The IM state machine, permissions, heartbeat and initial report are unchanged.

The stronger pair oracle also exposed a test defect: asynchronous reports from
node A contaminated node B's readback in the shared chip-tool text stream.
The two controller scripts now use a dedicated read connection with its own
copied laboratory controller store and no subscriptions. They require no
identity reports during unrelated refreshes and still require all four SET and
CLEAR reports before reads. No report requirement was relaxed.

## Executed acceptance

| Check | Result |
| --- | --- |
| Official TC_MTRID_3_1, endpoint1, run336 | PASS: 14 passed / 4 N/A step records |
| Official TC_MTRID_2_1, endpoint1, run337 | PASS: 6 passed / 2 N/A step records |
| Focused Linux CTest | 8/8 normal, 8/8 ASan/UBSan/LSan |
| Additional dispatch/fabric/IM-subscription CTest | 3/3 normal |
| Full two-runtime Memcheck, normal commissioning order | PASS, 0 errors, 0 bytes/blocks at exit |
| Full two-runtime ASan/UBSan/LSan, reverse commissioning order | PASS |
| Standalone host SET/restart/CLEAR/reset/disabled trigger | PASS |
| Two fabrics: selective removal, surviving subscription and restart | PASS |
| Last-fabric response, clean exit, fresh commissioning using same store | PASS |

Memcheck reports 63,589 allocations and 63,589 frees, with no suppressions.
The final normal/sanitized build logs contain no `warning:` or `error:`.
The native scope covers diagnostics, root/root_alloc, store, runtime/runtime_alloc,
meter_services/meter_services_alloc; additional tests cover dispatcher response
drain through ACK/error/deadline, fabrics and subscription behavior.
The official N/A records remain visible; local four-attribute checks do not
convert skipped official steps into CSA coverage.

Latest catalog counts: **91 PASS / 14 FAIL / 21 BLOCKED / 32 MANUAL / 704 NA**.
Only MTRID3.1 changes classification; other entries are inherited, not rerun.
The [delta](csa17-review-results.json) identifies runs, PICS/script evidence,
binary/source hashes, local checks and limitations. The normal executable hash
is `feb43ea0355edcd7e19b165aceeafc673fc2dd4d5fe5613b1f074117e2f5b073`.
The 353 C/H files match the source manifest. Official script hashes still match
the prior report; the effective PICS hash is unchanged. TH ended idle.

## What removal means for Home

No RemoveFabric production-code change was necessary in this follow-up.
The independent controller verified both relevant lifecycle branches:

1. Two fabrics are commissioned on the same node. Removing the requesting
   fabric returns a successful NOCResponse. The other fabric keeps its active
   power subscription and can still read. After restarting the host, that
   remaining fabric reconnects over CASE and reports one commissioned fabric.
2. Removing the final fabric returns success before the host exits with code0.
   The reset also clears volatile test identity. Restarting with the same store
   allows fresh commissioning and returns the baseline identity with triggers
   disabled. The earlier SET/restart check preserves commissioning while
   discarding the RAM-only identity override.

The standalone executable deliberately exits after last-fabric reset. It does
not automatically restart itself or reopen commissioning while stopped.
Removing only one ecosystem's fabric does not imply deleting another ecosystem's
fabric. These are protocol/controller observations, not a fresh manual Google
Home or Apple Home UI acceptance. No Windows Matter node was running during the
initial process inspection; no user-paired store was modified or deleted.

## Reproduction and limits

Private orchestration/evidence is retained under `build/csa17-review/`:

```text
python build/csa17-review/lab.py package
python build/csa17-review/lab.py stage
python build/csa17-review/lab.py build
python build/csa17-review/lab.py official
# Remote, in the dedicated review directory:
python3 memory_review.py
python3 lifecycle.py
python build/csa17-review/collect.py
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_meter_triggers.py tools/matter/tests/chip_tool_three_phase.py
git diff --check
```

The lifecycle runner orchestrates the public trigger script with `--leave-set`,
`--previous`, `--mode restart`, `--remove-fabric`, and `--mode disabled`, followed
by a separate two-fabric scenario. Fresh output directories are required;
do not overwrite the retained runs. Lab addresses/keys/state are excluded from
the public package. Network scenarios run sequentially.

Retained unsuccessful attempts include the old binary's unchanged-report
reproduction, the old pair oracle mixing A/B reports, an initial local controller
port collision, and a rejected controller argument during oracle correction.
Those fixture attempts are not CSA results or memory acceptance. The final
controller-source hashes identify the accepted scripts; no C rebuild was needed
for the final Python argument correction.

Native Windows, physical firmware, manual Home UI and the remaining full CSA
catalog were not executed. All owned test processes were cleaned up; checked
test ports were free and no test node was left running. No commit or push.
