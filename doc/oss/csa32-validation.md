# CSA32: last-fabric removal and discovery

CSA31 was committed as **`527e26d`**. This pass executes original
**TC-OPCREDS-3.6 in FirstManualSuite**, with observed x86/controller/DNS-SD
evidence. **TH run466 ends FAIL:** three protocol verifications and evidence
upload pass; the fourth protocol verification fails against its literal CM=0
instruction. This is an operator-reviewed manual result, not a newly detected
automatic protocol assertion. No official source, PICS, runtime C/H, default
commissioning behavior or public API was changed to force a PASS.

## Observed lifecycle

The reusable `test_last_fabric_discovery_chip.py` scenario uses the full frozen
three-phase profile and an unmodified chip-tool, with disposable state only:

1. Commission over the node's actual setup QR, verify attestation and exactly
   one fabric, and observe its operational SRV record on the wire. An active EPM
   subscription remains present when removal starts.
2. Remove that final fabric through CASE. The controller receives NOCResponse
   status0/index1, and the host reports one reset and exits with code0.
3. Observe TTL0 withdrawal of the old operational identity, then actively query
   and confirm that it produces no positive reply. The stopped executable has
   no commissionable advertisements either.
4. Explicitly restart the executable with the **same state path**, without
   deleting or editing that state. It opens a basic commissioning window:
   **CM=1 with the _CM subtype**. The old operational identity is not restored.
5. Commission with a new independent controller. Exactly one fabric is present,
   with a different operational identity. Reads show one trusted root, one ACL
   entry and an empty GroupKeyMap. Stop cleanly and inspect stderr/memory logs.

The final scenario passes **27 checks under Memcheck** and **25 separately under
ASan/UBSan/LSan**. Memcheck totals **47,890 allocations and 47,890 frees** across
the two boots, with zero errors and zero live bytes. All four host stderr files
are empty. The final driver hash is retained with each result. Native binaries
are the accepted CSA30 builds; no implementation rebuild was needed.

The CLI intentionally exits after last-fabric reset; restart is an explicit
operator action in this fixture, not a newly implemented automatic restart.
This does not remove another ecosystem's fabric: the scenario first verifies
that the requesting fabric is the last one.

## Original procedure and specification discrepancy

Core R1.6.1 **11.18.6.12** requires removal of commissioned Matter data when the
last fabric is removed. It warns controllers not to rely on a response before
the relevant session is terminated. This implementation additionally supplies
the successful response observed above; the scenario does not equate a timeout
with successful removal.

Core **4.3.1.7** identifies CM=0 as not currently available for commissioning,
and CM=1 as commissioning using the device-provided setup passcode, including
factory-new/basic-window operation. Core **4.3.1.3** requires the _CM subtype
while commissioning is available and excludes it for CM=0. The observed CM=1
and _CM after explicit restart are consistent with an open basic window.

The original Step4 heading describes commissioning when CM=2 or BLE is present;
its verification text instead asks for CM=0 without _CM. This on-network/basic
profile restarts with CM=1. The operator therefore records **FAIL against the
literal verification**, rather than silently treating the contradictory heading
as a waiver. All four disabled-in-YAML steps are included as manual verification
steps by FirstManualSuite; none was skipped to obtain acceptance.

Run466 reports **4 passed and 1 failed step entries**: protocol steps1/2/3 pass,
step4 fails, and the final evidence-upload step passes. The operator reviews
retained real scenario observations, rather than making TH itself drive those
controller actions. Its original scenario inputs and the final independent
acceptance are retained separately. The official YAML/PICS hashes are unchanged.
TH is idle and all disposable node/controller processes have stopped.

**Question retained for CSA:** which Step4 expectation applies to an on-network
commissionee explicitly restarted with an open basic window after final-fabric
removal? Clarify CM=0 verification versus the conditional CM=2 heading and the
CM=1 basic-window path. The FAIL is retained pending clarification; no production
compatibility switch or commissioning-default change is introduced.

## Fixture correction and limits

The first independent attempt queried the operational record before its separate
publisher finished probing. Its failure is retained. A short PTR/SRV/ANY check
on the retained test node confirmed responses after publication. The fixture
now waits up to eight seconds for the **same positive SRV observation** before
removal; no responder timing or expected record was changed. Final runs use
fresh output directories. A later fixture-only improvement seals its own source
hash and marks cleanup failures as FAIL; the final accepted scenario uses that
version. The earlier input proof used by run466 remains separately preserved.

Raw logs, addresses, operational identities, controller keys and state remain
outside Git. Public records contain reduced observations and hashes. Windows
paired devices and stores were not touched. This is not physical Wi-Fi, Apple/
Google Home UI or certification acceptance. Non-default ACL/group-key data was
not seeded: the post-recommissioning reads verify expected defaults, not an
exhaustive audit of deletion of every optional dataset.

The row remains category MANUAL with **manual_result=FAIL**. Category totals
remain 97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA; the manual category now
contains 10 documented PASS, 1 documented FAIL and 29 without an outcome.
Other rows, including deferred CSA30, are inherited without rerun or waiver.

## Reproduction and next action

```sh
python tools/matter/tests/test_last_fabric_discovery_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --payload-exe /path/to/C-payload-utility --paa /path/to/development-paa \
  --credentials /path/to/development-credentials --interface 2 \
  --output /path/to/fresh-private-memcheck --valgrind
# Repeat separately with the sanitizer executable, without --valgrind.
python -m py_compile tools/matter/tests/test_last_fabric_discovery_chip.py
python tools/matter/check_test_map.py
git diff --check
```

Next: **CSA33, TC-DD-3.19**, the original commissioning/unpair/recommission
procedure, using the supported manufacturer restart path and a bounded operator
fixture. Keep this CM discrepancy and CSA30's transport investigation open;
do not rerun their long procedures merely to seek a different result.
See the [machine-readable record](csa32-results.json).
