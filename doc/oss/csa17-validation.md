# CSA17 validation - 2026-10-14: STOP for review

Meter Identification trigger support is implemented in the uncommitted host,
but **TC_MTRID_3_1 remains FAIL**. The task's two-unsuccessful-fixes stop gate
was reached by the pre-existing official runs 334 and 335. These were retrieved
and examined during this turn; they are not new executions of the current build.
No third functional correction, test modification or workaround was attempted.
Latest matrix remains **90 PASS / 15 FAIL / 21 BLOCKED / 32 MANUAL / 704 NA**.
See the [result delta and evidence hashes](csa17-results.json).

## Baseline and retained work

HEAD is `9d88156dc5080ffc9cc05f3b729f6e0d035cf6ac`. CSA15/CSA16 and partial
CSA17 edits were already present. They were preserved, including the pair
controller's network migration scenario. An ignored entry snapshot records
the starting diff. CSA01 run190 stopped at step8 with
TestEventTriggersEnabled=false; it remains historical evidence, not a new
baseline on today's executable. MP04 previously covered static MTRID 2.1,
including the documented ProtocolVersion step-report caveat.

Local Matter 1.6.1 Application Clusters 9.10 confirms nullable MeterType 0..2
and strings of at most 64 bytes. Core 11.12.7.1 requires key validation,
INVALID_COMMAND for unknown triggers and no effects surviving last-fabric
removal. The host's last-fabric reset stops and deletes the Node. The test
identity is a RAM flag and is not included in device storage. These lifecycle
properties were reviewed statically; current runtime restart/reset acceptance
is outstanding.

## Official evidence and stop decision

| Case / run | Result | Observed failure |
| --- | --- | --- |
| TC_MTRID_3_1 / 190 | Historical FAIL | Step8: disabled fixture |
| TC_MTRID_3_1 / 334 | Pre-existing FAIL | Step9: SET returns INVALID_COMMAND (133) |
| TC_MTRID_3_1 / 335 | Pre-existing FAIL | Step9 SUCCESS; step10 compares Generic(2) against Generic(2) |
| TC_MTRID_2_1 | Not rerun this turn | Prior official result inherited unchanged |

Run335's DUT log records `event=0b06000100000000`, confirming the helper's
endpoint field and the implemented masking/routing. Its Python log records
a MeterType callback containing 2 at **11:51:24.291 UTC**, before SET starts
at **11:51:24.978 UTC**. At **11:51:25.042 UTC**, all matchers succeed from
already queued values. The helper then compares `reports[attribute][0].value`
against the saved base value and fails immediately at step10. This is evidence
of a pre-SET baseline callback; it is not evidence that the changed identity
was successfully reported, or that SET itself failed.

The unchanged `AttributeSubscriptionHandler.start()` installs its callback
after `ReadAttribute` returns. Each subsequent callback appends to a history
list and a queue. TC_MTRID_3_1 does not reset that history before SET, and the
helper chooses index0. The source of the pre-SET unchanged report still needs
review of subscription/report delivery. An initial-report timing issue or
redundant host report is a hypothesis, not a proven normative discrepancy.
Do not manufacture a PASS by changing initial identity, dropping required
reports, or changing the official script/helper.

Live preflight verified TH project11 maps endpoint1 / discriminator3911.
The official script hashes still match:

- TC_MTRID_3_1: `8e7fc1bfa3e732a8e9de9d5b5af1a86e0555b1d53d808325c54f914662218ed3`
- TC_MTRID_2_1: `ef4240d597082646b171fa4804122a837b63037c841b1df5c8711dee25d4a4e0`
- TC_MTRIDTestBase: `1abd1e87d8c7dcf6c35b849b48585196603f35b50b5f2f6353f1b0bf498ae23c`

TH is v2.15.1+summer2026; SDK identity is
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`. Project flags remain restrictive;
PICS_SDK_CI_ONLY is not enabled. This turn did not modify project configuration,
PICS or official tests. Exact historical DUT binary associations are unavailable;
the delta leaves their hashes null rather than assigning today's binary.

## Implementation and oracle changes

The retained host implementation uses a per-Node boolean and the existing
snapshot/refresh/DataVersion notification path. SET changes attributes0..3;
CLEAR restores Generic/null/SIM-0001/1.0. `--test-event-key` remains opt-in and
keeps its existing validation. Three-phase meter services enable diagnostics
triggers without enabling the legacy energy simulator or disabling EEM
checkpoint persistence. No new cluster API, device type or PowerThreshold.

This turn removed an unused identity snapshot, corrected a specification
comment, and stopped printing the pair's key. The pair fixture requires meter
services when its test key is supplied. The local controller oracles now use
one wildcard subscription, require four decoded SET and CLEAR reports before
issuing reads, and compare DataVersions. This avoids the previous false-positive
checks and the four-subscriptions/three-slot mismatch. The single-node oracle
can retain controller storage across restart, leave SET active and remove the
last fabric while the fake identity is active. These stricter scenarios are
prepared and syntax-checked, **not runtime-accepted**.

## Commands and current-build verification

The fresh Linux build lives in a separate ignored laboratory directory. The
upload inventory contains build/source/test files, with no local/build state,
credentials, certificate files or private keys. It preserves the old evidence.

```sh
python build/csa17/lab.py package
python build/csa17/lab.py stage
python build/csa17/lab.py build
# On Linux, both Debug variants (MATTER_SANITIZE=OFF then ON):
cmake --build build/<variant> -j 3 --target matter-node runtime-pair-host \
  test_root test_root_alloc test_diagnostics test_meter_services \
  test_meter_services_alloc test_runtime test_runtime_alloc test_store
ctest --test-dir build/<variant> --output-on-failure \
  -R '^(test_root|test_root_alloc|test_diagnostics|test_meter_services|test_meter_services_alloc|test_runtime|test_runtime_alloc|test_store)$'
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_three_phase.py \
  tools/matter/tests/chip_tool_meter_triggers.py \
  tools/matter/tests/test_discovery_startup_linux.py
git diff --check
```

Both host/pair builds succeed; focused CTest is **8/8 PASS normally and
8/8 PASS under ASan/UBSan/LSan**. Neither build log contains `warning:` or
`error:`. Linux source verification matches all 353 C/H files. Current normal
DUT SHA256 is `457c39bb7bf461255b7f5430af2ff9d2348ca8d6faaf87d0d163b6ed3085d6b3`.
Other executable/source/log hashes are in the delta. Inventory is 229 mapped
files, 85 native definitions, 59 core sources, 75 public headers.

The full pair under Memcheck and separate runtime ASan/UBSan/LSan, the new
controller scenarios, and official MTRID 2.1/3.1 on this build were **not run**:
the mandatory STOP gate was identified during evidence review. Focused tests
do not substitute for those missing checks. Pre-existing pair evidence uses
the weaker oracle and is not credited as acceptance of the stricter scenario.
No native Windows or hardware work, commits or publication.

The lingering CSA17 DUT/capture processes were stopped using their recorded
PID and state-path ownership checks. TH remains idle; ports5541/5542/5551/5561
are free and no owned CSA17 DUT/capture remains.

**Next action:** hand the two failed attempts and the pre-SET callback timeline
to the main reviewer. Determine why that unchanged callback arrives before SET
and approve a scoped follow-up before implementing or running a third attempt.
