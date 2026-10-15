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
**Next task: CSA19 — configure the OTA provider/image/restart fixture and run
the first applicable TC_SU_2_1 case.** OTA is already declared; do not add tariffs
or otherwise expand the device profile to substitute for its missing acceptance.

## 2. Google Test Suite and manual ecosystem acceptance

After the CSA matrix is complete, run the applicable Google Test Suite and manual
checks: commissioning, discovery/reconnection, subscription recovery, controls,
data presentation, restart, fabric removal and multi-admin use. Distinguish
protocol support from what the ecosystem UI displays. Save evidence and resolve
failures before optimization; do not change the declared device type to disguise
missing ecosystem support.

## 3. Memory and code-size optimization

Measure an accepted baseline (flash/text/rodata, stack, steady-state and peak
heap). Replace oversized fixed-capacity arrays with per-instance dynamic
allocations sized to actual configuration, with explicit ownership, bounded
limits, overflow checks, OOM handling and complete cleanup. Do not introduce
unbounded allocation in latency-sensitive paths. Replace unexplained numeric
literals with named `#define` limits/IDs/units; retain intentional protocol
constants with documented meanings. Avoid changing wire behavior or public
contracts unnecessarily. Re-run affected CSA and ecosystem cases plus memory
and multi-instance checks, and compare measured savings to the baseline.

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
