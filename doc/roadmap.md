# Development and acceptance roadmap

The target is Matter 1.6.1. Passing selected tests is not certification. The
current failures and measured coverage remain in [status](oss/status.md).

## Iteration strategy

Work in successive passes over this roadmap, narrowing the unresolved scope
each time. At the start of each pass review the declared profile, specification
requirements, CSA matrix, ecosystem acceptance, resource measurements and
integration prerequisites. Record what changed and what is still blocked.
Reviewing every area does not waive the ordered acceptance gates below.

Each pass selects a coherent group of failures or missing mandatory behavior,
checks the normative requirements and unmodified CSA assertions, implements the
fix, then runs the affected official cases and necessary independent regressions.
At the end of a pass refresh the full applicable CSA matrix against one identified
revision. Reuse unaffected evidence during development; avoid repeatedly running
local tests that cannot resolve the observed interoperability failure. Record
PASS, FAIL, SKIPPED/NOT_APPLICABLE, BLOCKED, MANUAL and NOT_RUN separately, with
reasons and the next concrete action. A skipped or unavailable case is not a pass.

Full CSA acceptance of the current declared profile takes priority over adding
tariffs or other optional capabilities. New capabilities enter a later pass with
their own PICS and acceptance coverage. The existing source registers stay available.

## 1. Complete the declared profile and CSA acceptance

Inventory and run **all applicable CSA tests** for the current declared device
types, features and PICS; use failures and mandatory coverage gaps to select
implementation work in the next pass. Maintain a test
matrix with executable/version, PICS, result and evidence for every case. Record
unsupported, blocked and manual cases explicitly; do not count a skip as PASS.
Resolve the historical failures and newly observed failures before leaving this
stage. Private extension semantics need separate controller tests; CSA composition
tests do not validate their meaning.

MP02 (three-phase measurements), MP03 (source registers) and MP04 (Identify,
Meter Identification and Time Synchronization) are implemented on x86.
MP04a identifies the startup discovery selection failure in the pinned controller's
`onnetwork-long` path. The pair oracle now uses its discriminator-checking QR-code
path, with browsing active before DUT startup and no announcement-settling delay.
See [evidence and remaining tool limitation](oss/mp04a-validation.md).

CSA01 establishes the first complete installed-catalog [matrix](oss/csa01-matrix.json)
for the frozen five-endpoint x86 profile. The [report](oss/csa01-validation.md)
records the actual official runs, PICS, baseline, failures and unexecuted coverage.
All four historical failures reproduced. A complete matrix does not mean a
completely passed profile: manual procedures and missing fixtures remain open.

CSA02 addresses commissioning, fail-safe and selective fabric/session teardown.
The [report](oss/csa02-validation.md) and [recheck evidence](oss/csa02-results.json)
retain the original failures, exploratory runs and final-source acceptance.
Host table holes and waiting for an unavailable PASE ACK are separate defects.
Exact duplicate-root and PASE RevokeCommissioning response expectations require
explicit CSA/test resolution, not implementation workarounds. Keep the MP04a
concurrent RemoveFabric scenario as a regression; a later pass alone does not
prove the cause of its historical intermittent timeout.

CSA03 completes the current profile's Descriptor composition: OTA Requestor on
Root and identity-only Electrical Utility Meter/Meter Reference Point on EP1.
The tariff condition remains absent. IDM 10.5, Descriptor, revision/superset and
all five endpoint-local PICS checks pass. IDM 10.1 still rejects the lab's test
vendor prefix; no certification bypass is enabled. See [evidence](oss/csa03-validation.md).

CSA04 addresses subscription delta reporting, all-cluster attribute subscriptions
and Administrator Commissioning notifications after committed fabric removal.
See [acceptance evidence](oss/csa04-validation.md) and [result delta](oss/csa04-results.json).
The official report-timing and multi-admin tests remain unmodified.

CSA05 shares the Read/Subscribe rule that a specific non-global attribute needs
a concrete cluster. TC_IDM_2_2, TC_IDM_4_2 and TC_IDM_4_3 pass unchanged; the
native wire matrix covers global ID boundaries and rejection before callbacks.
See [evidence](oss/csa05-validation.md) and [result delta](oss/csa05-results.json).

CSA06 reruns all applicable ACL cases and preserves two test/specification
discrepancies: ProxyView is D in Core 1.6.1; the invalid legacy append is rejected,
but the test inspects the earlier successful clear operation's status. No
production change or waiver is made. Negative write regressions verify valid
entries, storage/events and fabric isolation. TC_ACL_2_8 first times out during
discovery and then passes unchanged. See [evidence](oss/csa06-validation.md) and
[all attempts](oss/csa06-results.json); that timeout remains open.

CSA07 fixes a host race reproduced with rapid CASE revoke/reopen commands:
withdrawal must finish even if the requested window returns to its old values.
New windows also receive fresh DNS-SD instance names under Core 4.3.1. Native
and wire before/after checks confirm the fix; four final official rechecks pass.
Nine baseline official repetitions did not reproduce run 289, so its exact
attribution remains unproven and repeated commissioning stays under observation.
See [evidence](oss/csa07-validation.md) and [all attempts](oss/csa07-results.json).

CSA08 connects TimeSnapshot to the attached UTC clock and DeviceLoadStatus to
actual IM messages and established subscriptions, excluding retries and pending
reservations. Both selected General Diagnostics tests fail before and pass after
the repair. Latest matrix: 83 PASS, 22 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA.
See [evidence](oss/csa08-validation.md) and [all attempts](oss/csa08-results.json).

CSA09 fixes a dropped CASE failure StatusReport at the dispatcher boundary.
Unchanged TC_SC_3_4 reproduces the timeout before repair and passes all 13 recorded
steps afterwards; cryptographic validation remains intact. MRP error delivery,
retry and cleanup regressions pass, including a failing old-code control. Latest
matrix: 84 PASS, 21 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA. Full two-instance Memcheck
and separate sanitizer scenarios pass. See [evidence](oss/csa09-validation.md)
and [all attempts](oss/csa09-results.json).

CSA10 adds missing DNS-SD service/subtype enumeration in the host responder.
Unchanged TC_SC_4_1 passes enhanced commissioning and Extended Discovery, with
9 Basic Commissioning Window records N/A for the existing profile. Operational
TC_SC_4_3 also passes. Latest matrix: 85 PASS, 20 FAIL, 21 BLOCKED, 32 MANUAL,
704 NA. Independent wire checks fail before repair and pass afterwards; focused
native/sanitizer tests and both full memory scenarios pass. See
[evidence](oss/csa10-validation.md) and [all attempts](oss/csa10-results.json).

CSA11 fixes redundant Operational Credentials reports, empty attribute-only
updates and exact-tick heartbeat cancellation without increasing resource pools.
TC_RR_1_1 passes with five fabrics and 15 subscriptions, including the optional
unchanged-session-ID assertion; the TC_IDM_4_3 reporting recheck also passes.
Latest matrix: 86 PASS, 19 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA. See
[evidence](oss/csa11-validation.md) and [all attempts](oss/csa11-results.json).
Group-resource branches remain outside this profile's exercised RR coverage.

CSA12 closes the initial/enhanced window after twenty failed PASE attempts,
with one-shot notifications and per-window epochs. Unchanged TC_CADMIN_1_9 and
TC_CADMIN_1_11 pass; the matrix is 87 PASS, 18 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA.
Native regressions and both full memory scenarios pass. See
[evidence and limits](oss/csa12-validation.md) and [all attempts](oss/csa12-results.json).
Counting repeated failures after successful PASE still needs a separate Core
5.5.1 review. Retain the historical discovery attribution limit.

CSA13 admits the verified pending root at full fabric capacity and leaves the
TableFull result to AddNOC. Unchanged TC_CADMIN_1_19 and TC_OPCREDS_3_1 pass.
The matrix is 88 PASS, 17 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA. Focused native
regressions, the old-code control and both full memory scenarios are recorded in
[evidence](oss/csa13-validation.md) and [all attempts](oss/csa13-results.json).

CSA14 adds opt-in connected Wi-Fi simulation with restored-state precedence.
TC_CNET_4_1 passes. TC_CNET_4_4 remains FAIL: the installed script sends
ScanNetworks without the fail-safe required by Core 1.6.1 11.9.7.1. Keep that
result pending CSA/test resolution; supplementary armed scans are not a waiver.
The matrix is 89 PASS, 16 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA. See
[evidence and discrepancy](oss/csa14-validation.md) and [attempts](oss/csa14-results.json).

CSA15 fixes the TH's effective Wi-Fi parameter fixture; unchanged TC_CNET_4_9
passes on the CSA14 binary. TC_CNET_4_11 requires a controller/DUT transport
that actually switches AP networks and is blocked in the current Ethernet VM
fixture. Its previous official FAIL is retained. The local two-instance CASE
scenario covers simulated migration, authentication errors, rollback and commit.
The matrix is 90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA. See
[evidence and limits](oss/csa15-validation.md) and [attempts](oss/csa15-results.json).

CSA16 reproduces TC_CADMIN_1_10 FAIL in run 333 on the unchanged CSA14 binary.
Step 9 expects a response to RevokeCommissioning over PASE, while Core 1.6.1
11.19.8.3 says the caller SHALL NOT expect one. No code or test workaround is
made; the matrix stays unchanged. See [review evidence](oss/csa16-validation.md)
and [baseline delta](oss/csa16-results.json).

CSA17 adds the opt-in Meter Identification change/reset fixture on EP1, using
the existing snapshot/refresh path and preserving legacy energy triggers.
Official runs334/335 remain historical FAILs. The follow-up review reproduces
the redundant identity reports caused by unrelated source updates and applies
the existing DataVersion reporting policy. MTRID 3.1/2.1 now pass (336/337),
with full pair memory acceptance and independent selective/last-fabric removal,
restart and recommissioning. See [review evidence](oss/csa17-review-validation.md).
Manual Home removal/re-add acceptance on a running node remains pending.
Last-fabric removal currently stops the host; restart is required for re-add.
Keep CADMIN 1.10 as a
known CSA02/CSA16 discrepancy for the consolidated CSA report; do not rerun it
without new evidence or a relevant implementation/test/specification change.
Later-stage failed commissioning accounting remains a separate, unassessed task.
Return to CNET 4.4 after specification/test resolution and to CNET 4.11 when its
two-AP network fixture exists. Keep simulation results separate from radio and
IP-transition acceptance, without blocking unrelated CSA coverage.

Subsequent passes must resolve remaining read validation, diagnostics, discovery
and resource limits, and prepare the
missing three-phase triggers, OTA, Wi-Fi and manual/attestation fixtures. Retain
test/specification discrepancies for explicit CSA resolution, not silent waivers.
After submitting a discrepancy report and obtaining CSA's response, if a conflict
cannot be resolved, consider an explicit compile-time compatibility option.
Keep normative behavior as the default; document each deviation and the affected
TH/specification versions, and test both configurations independently. Results
from the compatibility mode must identify that mode and must not imply normative
conformance. No such option is implemented now, and no external report has been
sent as part of CSA14/CSA15.
Refresh the matrix after each coherent fix and rerun the full applicable suite
before closing this stage. Do not discard the initial failures or count test
credentials and skipped production checks as certification evidence.

MP05 (Commodity Metering), Commodity Tariff/Price and tariff/billing compositions
are deferred until this acceptance priority is met. The CSA03 identity-only
Utility Meter does not implement those capabilities.
Do not advertise a device type whose mandatory dependencies are missing.
Keep full-host checks with independent controllers, two instances in one process,
failure paths, Memcheck and separate ASan/UBSan/LSan throughout development.

CSA18 supplies targeted laboratory energy inputs for the existing three-phase
profile. The opt-in key now routes fake load/generator/STOP events to EP1 or
EP3/4/5 without changing unselected phases or another runtime. Aggregate
import/export registers integrate elapsed time and stay monotonic across STOP;
no per-phase energy is synthesized. Official EPM2.2 passes on all four measuring
endpoints and EEM2.2/2.3 pass on EP1. The matrix becomes 97 PASS, 14 FAIL,
15 BLOCKED, 32 MANUAL, 704 NA; unaffected rows are inherited. See
[evidence and limits](oss/csa18-validation.md) and [result delta](oss/csa18-results.json).
OTA is already declared; do not add tariffs
or otherwise expand the device profile to substitute for its missing acceptance.

CSA19 adds the official CHIP provider and signed host-simulation OTA fixture.
TC-SU-2.1 completes its three manual verification prompts and evidence upload
in TH run442. It stays separate from automatic CSA PASS coverage: one row moves
BLOCKED to MANUAL with manual result PASS; counts are 97 PASS, 14 FAIL,
14 BLOCKED, 33 MANUAL, 704 NA. Full download/authentication/restart/fresh CASE
also passes under Memcheck and separately ASan/UBSan/LSan. C sources remain at
the accepted CSA18 revision. No executable firmware or physical bootloader was
updated. See [evidence and limits](oss/csa19-validation.md) and
[fixture contract](ota-host.md).
CSA20 fixes the stored OTA query floor after asynchronous CASE setup: repeated
announcements can no longer cause a query less than 120 seconds after the
previous one. The new regression fails with the old implementation. Unchanged
TC-SU-2.2 completes its manual steps and evidence upload in run443, with optional
HTTPS N/A. All seven wire scenarios pass under Memcheck, and a separate complete
update/restart passes with ASan/UBSan/LSan; each build passes 11 focused native
tests. Counts become 97 PASS, 14 FAIL, 13 BLOCKED, 34 MANUAL, 704 NA;
manual PASS stays separate from automatic coverage. See
[evidence and limits](oss/csa20-validation.md) and [result delta](oss/csa20-results.json).
CSA21 fixes stale peer-session reuse after an OTA provider restart. An outbound
MRP timeout now retires that operational connection; subsequent work establishes
CASE, while cancellation/local failure/inbound behavior remains unchanged.
The previous binary fails the real interruption/retry scenario and the new native
regression. Unchanged TC-SU-2.3 completes manual verification and evidence upload
in run444: uninterrupted transfer, five real minutes after interruption, Idle
readback and a successful new transfer from offset zero. Consent, HTTPS and
resumption stay N/A. Counts become 97 PASS, 14 FAIL, 12 BLOCKED, 35 MANUAL, 704 NA;
manual PASS remains separate from automatic coverage. See
[evidence and limits](oss/csa21-validation.md) and [delta](oss/csa21-results.json).
CSA22 completes unchanged TC-SU-2.4 in manual TH run445. The peer-trace oracle
compares the actual UpdateToken and NewVersion to QueryImageResponse and the
authenticated image, using versions 2 and 3; a mismatched signed version is
rejected before Apply/Notify. Counts become 97 PASS, 14 FAIL, 11 BLOCKED,
36 MANUAL, 704 NA. This step also removes inline Read/Subscribe RX/TX buffers:
allocations follow actual RX/configured TX sizes, within the UDP wire budget.
See [results and limits](oss/csa22-validation.md).
CSA23 completes unchanged TC-SU-2.5 in manual TH run446: Proceed/0 and /180,
Await/60 with the 120-second floor, Await/180 followed by Proceed, and Discontinue.
An optional application callback now disposes of the discontinued host candidate;
the preceding binary retains it. All five real-time scenarios pass under Memcheck,
with separate sanitizer acceptance of retry/restart and disposal. The existing
Apply delay policy remains unchanged. Counts become 97 PASS, 14 FAIL,
10 BLOCKED, 37 MANUAL, 704 NA. See [evidence and limits](oss/csa23-validation.md).
CSA24 executes unmodified automatic TC_SU_2_5 (run449): both delay/provider-loss
scenarios pass, but Discontinue fails when its progress subscription exceeds
the host's three-per-fabric budget after earlier state handlers are retained.
Query backoff state and actual download progress are corrected and validated
under Memcheck and separate sanitizers. The official Python row is FAIL, not
automatic acceptance; the suspected resource assumption is not confirmed by CSA.
Counts become 97 PASS, 15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA. See
[evidence and limits](oss/csa24-validation.md) and [delta](oss/csa24-results.json).
CSA24a provisions the advertised per-instance subscription budget with a dynamic
transaction table and a transport-capacity guard. Normal/sanitizer tests and
full Memcheck/separate sanitizer scenarios pass with budget eight. Automatic
run450 accepts the fourth subscription but remains FAIL at a later assertion:
the original stateful matcher replays an old null after 1%, falsely declaring
download complete before Apply. A source-preserving minimal reproduction confirms
the behavior; it is not a CSA-approved test correction. Counts stay 97 PASS,
15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA. See [evidence](oss/csa24a-validation.md).
CSA24b now has a pinned local patch: chronological FIFO progress, a bounded
monotonic wait and scenario subscription cleanup. The original predicate and
assertions are retained. Source regressions pass 11/11 on Windows/Linux, with
negative original-source controls and another preflight run on TH. Full run451
passes all six steps with budget three/transport 56, including both delays and
Discontinue, chronological progress, image disposal and unchanged version. The
original SDK source is restored exactly and the isolated node is stopped.
This is LOCAL-PATCH PASS; no official result is relabelled pending CSA approval.
See [full-run evidence and limits](oss/csa24b-validation.md).
CSA25 completes manual TC-SU-2.6 in TH run452: evidence verification and upload
pass. Actual Notify commands after two independent signed simulation updates
carry the latest token and versions 2/3, matching fresh CASE readback. Full
Memcheck and separate sanitizers pass; no stack, PICS or official test change
was required. Only this row moves from BLOCKED to MANUAL/PASS; counts become
97 PASS, 15 FAIL, 8 BLOCKED, 38 MANUAL, 704 NA. Other rows are inherited.
See [evidence and limits](oss/csa25-validation.md).
CSA26 fixes event handoff states and known-length DownloadError progress.
Manual TC-SU-2.7 passes in run455; automatic TC_SU_2_7 fails at step1 in run454
because its subscription starts after the host's initial query. Official sources
and PICS remain unchanged. Seven independent scenarios pass 156 checks, including
live-MRP BDX Idle timing/recovery. Memcheck, separate sanitizers and 15 focused
tests per build pass. Only these two rows change: 97 PASS, 16 FAIL, 6 BLOCKED,
39 MANUAL, 704 NA. See [evidence and limits](oss/csa26-validation.md).
CSA27 runs the unchanged TC_SU_4_1: FAIL in run456 because step5 expects the
constraint error in the first status rather than after successful clear/append.
Core requires every generated status; no C or test workaround is introduced.
Independent chip-tool acceptance passes 29 Memcheck and 27 sanitizer checks,
including two fabrics, partial write/readback and persistence after restart.
The cumulative counts become 97 PASS, 17 FAIL, 5 BLOCKED, 39 MANUAL, 704 NA;
all other rows are inherited. See [evidence and limits](oss/csa27-validation.md).
CSA28 runs original automatic TC_SU_2_2: FAIL in run457 at the initial
DelayedOnQuery wait. Its UpdateAvailable announcement does not arrange a normal
query opportunity for the host's daily policy. The independent lab explicitly
configures a default provider before reason1 announcements, preserving protocol
timers and production behavior. Seven scenarios pass 134 local checks, including
full Memcheck and separate sanitizer update/restart acceptance. Only this row changes: 97 PASS, 18 FAIL,
4 BLOCKED, 39 MANUAL, 704 NA. Other rows are inherited. See
[scenarios, evidence and limits](oss/csa28-validation.md).
CSA29 completes original semi-automated TC-I-2.2 in run460: all 15 step entries
pass, including two agent-evaluated operator prompts and evidence upload. The
declared IdentifyType0 has no physical presentation; live callbacks provide
simulation evidence only. Independent chip-tool acceptance passes 34 checks
under Memcheck and separate sanitizers, including quiet countdown reporting and
fresh CASE after restart. No C/H or official sources/PICS changed. TH networking
and existing services are restored after the laboratory outage. Counts become
97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA; other rows inherited. See
[evidence and limits](oss/csa29-validation.md).
CSA30 fixes host OS uptime being passed as Node System Time and replaces the
constant simulated-interface description with an optional application network
snapshot callback. Independent chip-tool acceptance passes 59 checks across
Memcheck/separate sanitizers; focused native/package checks also pass. Original
semi-automated TC-DGGEN-2.1 ends ERROR in run463 after its full original 2h05 wait:
the next read hits a TH/chip-tool WebSocket keepalive timeout. It obtains no
second hours value; the 1h05 segment and later steps remain unexecuted. Source/
PICS are unchanged; final evidence and cleanup are complete. **No official PASS;
cumulative counts remain unchanged.** See [evidence and limits](oss/csa30-validation.md).
The idle laboratory has since been restarted cleanly, and the unchanged
WebSocket runner passes a 165-second idle check. Retry **run464 ends ERROR**
after its full 2h05 wait and a passed TotalOperationalHours **0-to-2** assertion.
Commissioning after the following factory reset encounters a controller
WebSocket keepalive timeout; the later 1h05 segment is unexecuted. Final
collection and cleanup complete; the exact stall mechanism remains unproven.
**CSA30 is unsuccessful; the owner deferred further investigation and long
retries in this pass. Next: CSA31, TC-DD-1.1/1.2 onboarding QR/manual pairing
payload tests.** Retain the controller stall as an open issue for later short
reproduction, and preserve both original ERROR results. No complete PASS or
certification is claimed.

CSA31 completes original TC-DD-1.1/1.2 in TH run465 with agent-supplied observed
QR/manual-code inputs: 9 and 3 passed steps, one inapplicable 21-digit branch.
Independent C bitmap scanning, chip-tool decoding and live mDNS pass 24 checks;
the existing C payload self-test passes Memcheck. Runtime C/H are unchanged.
Both rows remain MANUAL with manual_result=PASS; other results are inherited.
The manual card is CHIP-generated laboratory data, not a new GUI field; physical
labels and DCL validation remain outside this acceptance. See
[evidence and limits](oss/csa31-validation.md). Last-fabric removal and discovery
are recorded below. CSA30 remains unsuccessful/deferred.

CSA32 executes original manual TC-OPCREDS-3.6 in TH run466: protocol steps1/2/3
and evidence upload pass; Step4 fails its CM=0/no-_CM verification. After an
explicit same-store restart, the uncommissioned node opens CM=1 with _CM and
recommissions successfully. The heading instead refers to CM=2/BLE; retain this
as a test/specification clarification, without changing runtime defaults or
waiving the FAIL. Independent lifecycle acceptance passes 27 Memcheck and 25
separate sanitizer checks, with clean teardown and no C/H changes. The MANUAL
category now includes 10 PASS, 1 FAIL and 29 without an outcome; category totals
and other rows are unchanged. See [evidence and limits](oss/csa32-validation.md).
The follow-up same-controller lifecycle is recorded below. CSA30 stays deferred.

CSA33 completes original manual TC-DD-3.19 in TH run467: all seven entries pass.
The same live commissioner and unchanged credentials scan the same supplied QR,
commission, remove the final fabric and recommission after an explicit same-store
CLI restart. Both commissioning completions advertise CM=0; restart opens CM=1,
and the same operational identity is absent until recommissioning. Independent
acceptance passes 37 Memcheck and 35 separate sanitizer checks, with clean memory
and no runtime changes. MANUAL now contains 11 PASS, 1 FAIL and 28 without an
outcome; category counts remain unchanged. Two fixture failures and the explicit
restart/programmatic-QR limits are retained in [evidence](oss/csa33-validation.md).
The follow-up IP announcement verification is recorded below. CSA32's CM
discrepancy remains open; CSA30 remains unsuccessful/deferred.

CSA34 executes original manual TC-DD-2.1 in TH run468: 8 PASS, 17 NOT APPLICABLE,
1 FAIL at Step15a. Actual CM=0 advertisements omit mandatory PH under Core1.6.1
4.3.1.11. This is a confirmed implementation gap; incomplete PICS does not waive
the requirement. Complete basic/closed/enhanced discovery scenarios pass 37
Memcheck and 36 separate sanitizer functional checks with clean memory, but
overall conformance stays FAIL. No runtime or original-test/PICS changes.
The manual category now contains 11 PASS, 2 FAIL and 27 without an outcome;
category totals remain unchanged. See [evidence](oss/csa34-validation.md).
The PH/policy repair and affected discovery rechecks are recorded below.

CSA35 supplies application-owned PH metadata and per-Node Extended Discovery
policy: the reference host defaults to 900 seconds and supports off, bounded and
explicit unlimited advertising. PH reflects restart before commissioning and
Administrator afterward. Operational discovery/CASE survive suppression and new
windows still publish fresh instances. Original automatic TC_SC_4_1/4_3 and manual
TC-DD-2.1 pass with updated discovery PICS. Six full memory-instrumented policy
scenarios and two restored disabled boots pass, alongside focused native/package/
CLI validation. MANUAL now contains 12 PASS, 1 FAIL and 27 without an outcome;
category totals remain unchanged. See [evidence and limits](oss/csa35-validation.md).
CSA36 distinguishes optional Commissioner Discovery/UDC from the implemented
commissionable/operational discovery. The reference runtime has no `_matterd`
commissioner browsing or UDC handler; its incorrect `MCORE.DD.COMM_DISCOVERY`
declaration becomes false. The original TH eligibility endpoint removes only
TC-SC-4.7; no new test execution or PASS is claimed. The five endpoint CLI exports
preserve every other declaration and project field. Current matrix: 97 PASS,
18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA; MANUAL contains 12 PASS, 1 FAIL and 26
without an outcome. See [audit and limits](oss/csa36-validation.md).
CSA37 executes original manual TC-SC-2.1 in TH run472: FAIL on five literal
addressing/boolean/byte-size requirements that conflict with Core1.6.1; final
success verification and log upload pass. Independent full PASE/commissioning/
CASE/enhanced-window/second-fabric scenarios pass under Memcheck and separate
sanitizers, with no native or original test/PICS changes. The original FAIL stays
open for clarification. Counts are unchanged; MANUAL now contains 12 PASS, 2 FAIL
and 25 without an outcome. See [evidence and limits](oss/csa37-validation.md).
Continue first-pass coverage of 25 manual and 3 BLOCKED positions; revisit the 18
automatic and 2 manual FAIL results afterward, as requested.
CSA38 executes original manual TC-SC-2.2, run473: four encrypted communication
steps and upload pass; the required session termination/key clearing after bad
MIC fails. Core4.8.3 stops processing the damaged message without mandating
session destruction. Two full fault-injection scenarios pass under Memcheck and
separate sanitizers (50 checks, four bad-MIC deliveries), followed by same-session
recovery, full commissioning and CASE. Focused PASE/secure tests pass per build.
No native or original-test/PICS changes. MANUAL now has 12 PASS, 3 FAIL and 24
without an outcome; category totals stay unchanged. See
[evidence and limits](oss/csa38-validation.md).
CSA39 executes original manual TC-SC-2.3, run474: seven entries pass and two fail.
The runtime drops the PASE machine's prepared terminal error StatusReport after
invalid passcodeID/cA. This is a confirmed implementation defect, not a wording
discrepancy. Both full memory-instrumented scenarios retain overall FAIL while
late-message rejection, new commissioning/CASE and second-fabric recovery pass.
No native changes; two existing tests pass per build. See
[evidence and deferred repair](oss/csa39-validation.md). MANUAL now has 12 PASS,
4 FAIL and 23 without an outcome; category totals are unchanged.
CSA40 executes original manual TC-SC-1.1, run475: both steps/upload pass. Core
4.4.4/4.15 include IPv6/UDP headers in the1280-byte MTU, leaving1232 Matter bytes
without IPv6 extensions. Actual1279/1280 packets receive matching ACK/PBKDF;
1281/1328/1329 receive no reply. No native/PICS changes. Both full two-fabric
scenarios pass under Memcheck/separate sanitizers,64 independent checks total;
memory is clean and five focused UDP/MRP tests build/pass per variant. See
[evidence and limits](oss/csa40-validation.md). MANUAL now has13 PASS,4 FAIL
and22 without an outcome; category totals are unchanged.
CSA41 executes original manual TC-SC-1.2, run476: six entries pass and one fails.
Piggyback and duplicate standalone ACKs work. Five valid authenticated R=0 reads
get no data reply; R=1 controls pass before/after. Runtime admission rejects new
requests without R before IM handler creation, although lower layers support
R=0. This is a native defect, deferred with the earlier failure backlog. Both
full memory-instrumented scenarios retain FAIL; later commissioning/CASE and
five focused tests per variant pass. No native/PICS change. See
[evidence and deferred repair](oss/csa41-validation.md). MANUAL now has13 PASS,
5 FAIL and21 without an outcome; category totals are unchanged.
**Next: CSA42, TC-SC-1.3 MRP Retransmissions**, reviewing outbound loss, actual
retry intervals/counts and final eviction against Core. Continue the initial
coverage pass (21 manual plus 3 blocked); repair the 18 automatic and 5 manual
FAIL results afterward as requested. Keep clarification items open and CSA30
deferred.

## 2. Google Test Suite and manual ecosystem acceptance

After the CSA matrix is complete, run the applicable Google Test Suite and manual
checks: commissioning, discovery/reconnection, subscription recovery, controls,
data presentation, restart, fabric removal and multi-admin use. Distinguish
protocol support from what the ecosystem UI displays. Save evidence and resolve
failures before optimization; do not change the declared device type to disguise
missing ecosystem support.

## 3. Memory and code-size optimization

Incremental migrations already completed during acceptance: per-request
DataVersionFilters and Read/Subscribe RX/TX buffers. Remaining candidates include
Invoke/Write/outbound-IM buffers, expanded-result tables and connection/transport
tables. Migrate one subsystem at a time with its error-path, protocol and memory
tests; preserve the transport ceiling instead of increasing arbitrary capacities.

The target device has **128 kB RAM**. CSA24a's table allocated for the entire
configured transaction budget is an interim host implementation, not the final
memory model. A capacity is an admission ceiling, not a request to allocate that
many contexts. Allocate one transaction/subscription context only when work is
admitted, keep its address stable while referenced, and release it after its
last callback/I/O/ACK drain. Apply the same rule to other large tables and payload
buffers: allocate for actual live use, not the maximum configured capacity.
Moving a full static array into `calloc(limit, ...)` does not complete this work.
Any retained cache or upfront reservation needs a measured, documented reason.
Keep quotas, fabric isolation, OOM rollback and bounded lifetime behavior.

Measure an accepted baseline (flash/text/rodata, stack, steady-state and peak
heap). Replace oversized fixed-capacity arrays with per-instance dynamic
allocations sized to actual live demand, with explicit ownership, bounded
limits, overflow checks, OOM handling and complete cleanup. Do not introduce
unbounded allocation in latency-sensitive paths. Replace unexplained numeric
literals with named `#define` limits/IDs/units; retain intentional protocol
constants with documented meanings. Avoid changing wire behavior or public
contracts unnecessarily. Re-run affected CSA and ecosystem cases plus memory
and multi-instance checks, and compare measured savings to the baseline.
Account for idle, commissioning, CASE, concurrent subscriptions and OTA peaks,
including crypto, storage, application and task-stack headroom; host acceptance
alone does not demonstrate that the complete device fits 128 kB.

Unify duplicated monotonic-time primitives in this stage: checked/saturating
deadline arithmetic, unit conversion and earliest-deadline selection. Preserve
each operation's specified overflow/error policy and keep protocol decisions
(MRP backoff, subscription intervals, fail-safe expiry) in their state machines.
Aggregate module deadlines into a runtime next-wakeup API so an application can
wait for I/O or the earliest deadline instead of periodic polling. Retain
application-owned, single-thread scheduling and test clock boundaries, cancellation
and idle-network expiry. Fix any actual timing defects during CSA acceptance;
defer the cross-module refactor until the preceding acceptance gates are met.

## 4. Downstream provisioning and firmware integration

Only after those gates: persist manufacturing/field provisioning and integrate
the library with the target firmware in a separate downstream repository.
Hardware callbacks, credential ownership, storage, boot/update lifecycle and
resource budgets belong to that integration. This repository supplies the
portable library, public contracts and host tests, without product-specific code.
