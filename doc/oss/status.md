# Development status

The CSA17 review is resolved by enabling the existing DataVersion reporting
policy for Meter Identification attributes. **TC_MTRID_3_1 PASS (run336)** and
**TC_MTRID_2_1 PASS (run337)** on unchanged official scripts. Latest matrix:
**91 PASS, 14 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows are inherited.
Full pair Memcheck and separate ASan/UBSan/LSan pass, as do single-host
restart/recommissioning and selective/last-fabric removal. Last-fabric removal
returns SUCCESS before the host exits; the other fabric survives selective
removal and restart. Manual Home UI acceptance was not repeated.
See [review and limits](csa17-review-validation.md) and
[current delta](csa17-review-results.json). **Next: manual Home removal/re-add
acceptance on a running node, keeping existing user fabrics separate from lab
state.** No node was left running after this laboratory campaign.

The following entry preserves the earlier handoff; the follow-up above supersedes
its STOP status and outstanding tests.

CSA17 is **STOP for review**, with **TC_MTRID_3_1 still FAIL**. Pre-existing
official run334 rejects SET; run335 accepts it but step10 compares the first
queued pre-SET MeterType=2 against the saved base value. The origin of that
unchanged report remains unresolved. The two-unsuccessful-fixes gate prevents
a third correction/attempt. The opt-in host fixture and stricter local oracles
are retained; current Linux normal/sanitized builds and eight focused tests
per variant pass. Current full pair memory/controller acceptance and MTRID2.1
rerun remain outstanding. Matrix stays **90 PASS, 15 FAIL, 21 BLOCKED,
32 MANUAL, 704 NA**. See [CSA17 evidence](csa17-validation.md) and
[delta](csa17-results.json). **Next: main-reviewer decision on the pre-SET
subscription callback before any further implementation/campaign.**

CSA16 reproduces **TC_CADMIN_1_10 FAIL (run 333)** on the unchanged CSA14
binary: step 9 awaits a RevokeCommissioning response over PASE. Core 1.6.1
11.19.8.3 says the PASE caller SHALL NOT expect a response because revocation
terminates the session. This confirms the CSA02 discrepancy; implementation
work stops for review with no workaround, C/test/PICS changes or new build.
Latest matrix stays **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**.
See [CSA16 evidence and decision](csa16-validation.md) and
[baseline delta](csa16-results.json). CSA17 above records the subsequent
Meter Identification fixture work and its unresolved subscription acceptance.
The known step 9 discrepancy awaits consolidated CSA/test resolution and does
not block independent work. Later-stage commissioning failure counting
remains unassessed; successful PASE alone is not successful commissioning.

CSA15 corrects the TH Wi-Fi parameter fixture: **TC_CNET_4_9 passes (run 332,
25 records)** on the unchanged CSA14 binary. Run 331 preserves the initial
empty-effective-SSID failure. **TC_CNET_4_11 was not rerun**: the TH VM has no
Wi-Fi interface/wpa_supplicant for the script's two-AP transition. Its historical
official FAIL remains; the new environment blocker is recorded separately.
Latest matrix: **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**, with other
rows inherited. The extended pair oracle covers simulated network migration,
authentication errors, rollback, commit and instance isolation.
Full Memcheck and separate ASan/UBSan/LSan runs pass; Memcheck reports zero
errors/leaks, 49,628 allocations/frees and no suppressions. C/binary identities
match CSA14; native builds/CTest were not repeated for this Python-only change.
See [CSA15 evidence and fixture limits](csa15-validation.md) and
[result delta](csa15-results.json). No C source, API, PICS or official assertion
changed. CSA16 above records the subsequent TC_CADMIN_1_10 normative review.
Retain CNET 4.4 pending CSA resolution and 4.11 pending its network fixture.

CSA14 adds explicit `--wifi-sim-connected` startup for the host, preserving
saved settings and the existing empty-network default. **TC_CNET_4_1 passes
(run 329)** after baseline run 327 fails on the missing connection.
**TC_CNET_4_4 remains FAIL (run 330)**: it now reaches ScanNetworks but omits
ArmFailSafe, receiving the FAILSAFE_REQUIRED required by Core 1.6.1 11.9.7.1.
No test assertion or server protection was relaxed; no CSA waiver was obtained.
Latest matrix: **89 PASS, 16 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited. Six focused tests pass normally and with ASan/UBSan/LSan.
Two-instance Memcheck and separate sanitizer scenarios pass, including connected
Wi-Fi, guarded/armed scans, Breadcrumb and rollback; zero Memcheck errors/leaks.
See [CSA14 evidence and discrepancy](csa14-validation.md) and
[all attempts](csa14-results.json).
CSA15 above records the subsequent removal/migration fixture work.

CSA13 removes the premature full-table error from RCAC admission. A verified
pending root uses the existing journal slot; **AddNOC returns TableFull** when
all five fabric slots are occupied. **TC_CADMIN_1_19 passes (run 325)** after
baseline run 324 reproduces IM ResourceExhausted at AddTrustedRootCertificate.
**TC_OPCREDS_3_1 also passes (run 326)** with its unchanged official assertions.
Latest matrix: **88 PASS, 17 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited. Six focused tests pass normally and with ASan/UBSan/LSan; the
old-code control fails. Full two-instance Memcheck and separate sanitizer runs
pass, with zero Memcheck errors/leaks. No pool, API or storage-schema expansion.
See [CSA13 evidence and limits](csa13-validation.md) and
[all attempts](csa13-results.json).
CSA14 above records the subsequent Wi-Fi fixture acceptance and open discrepancy.

CSA12 closes the initial/enhanced commissioning window after 20 failed PASE
attempts. Notifications are one-shot, counters belong to each runtime/window,
and existing CASE administration survives. **TC_CADMIN_1_9 passes (run 322)**
after baseline run 321 reproduces acceptance of the correct PIN after twenty
failures. **TC_CADMIN_1_11 also passes (run 323)**; four Basic Commissioning
feature records remain N/A. Latest matrix: **87 PASS, 18 FAIL, 21 BLOCKED,
32 MANUAL, 704 NA**; other rows are inherited. Five focused tests pass normally
and with ASan/UBSan/LSan, and the old-runtime control fails as expected. Full
two-instance Memcheck and separate sanitizer runs pass, with zero Memcheck
errors/leaks. See [CSA12 evidence and limits](csa12-validation.md) and
[all attempts](csa12-results.json). Counting failures after successful PASE is
outside this repair and remains for separate acceptance.
CSA13 above records the subsequent full-table commissioning acceptance.

CSA11 fixes excess unchanged Operational Credentials reports, empty attribute-only
updates before MaxInterval, and premature cancellation on late heartbeat wakeups.
**TC_RR_1_1 passes (run 319)** with five fabrics, three controllers/subscriptions
each and the optional unchanged-CASE-session-ID check. **TC_IDM_4_3 also passes
(run 320)**. Session/subscription limits and public function signatures are unchanged.
Latest matrix: **86 PASS, 19 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows
are inherited, not rerun. See [CSA11 evidence](csa11-validation.md) and
[all seven attempts](csa11-results.json), including intermediate failures and
the limits of RR group-resource coverage.
Seven focused tests pass normally and with ASan/UBSan/LSan. Full two-instance
Memcheck reports zero errors/leaks; the separate sanitizer scenario also passes.
CSA12 above records incorrect-passcode and window-lifecycle acceptance.

CSA10 adds missing host DNS-SD service/subtype enumeration, including the subtype
listing used by CHIP/TH. **TC_SC_4_1 passes (run 312)** for enhanced commissioning
and Extended Discovery; its 9 Basic Commissioning Window records remain N/A for
the existing profile. **TC_SC_4_3 also passes (run 313)**. Baseline run 311 and
the independent wire regression reproduce the missing listing before repair.
Latest matrix: **85 PASS, 20 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**, with other
rows inherited. Six focused tests pass normally and with ASan/UBSan/LSan;
35 wire checks and both full two-instance memory scenarios pass. Memcheck
reports zero errors/leaks. See [CSA10 evidence](csa10-validation.md) and
[all attempts](csa10-results.json).
CSA11 above records the subsequent resource/subscription acceptance.

CSA09 fixes delivery of required CASE failure StatusReports: the engine rejected
invalid input correctly, but the dispatcher closed before sending its output.
Reports now retain their MRP lifetime without creating a secure session or
continuing the handshake. The unchanged **TC_SC_3_4 passes all 13 recorded steps
(run 310)** after baseline run 309 reproduced the timeout. Latest matrix:
**84 PASS, 21 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; other rows are inherited.
Seven focused tests pass normally and with ASan/UBSan/LSan, including a new
regression that fails against the previous dispatcher. Full two-instance
Memcheck reports zero errors/leaks; the separate sanitizer scenario also passes.
See [CSA09 evidence](csa09-validation.md) and [all attempts](csa09-results.json).
CSA10 above records the subsequent Commissionable Node Discovery repair/recheck.

CSA08 fixes General Diagnostics at the runtime boundary: TimeSnapshot now uses
the attached Time Synchronization UTC, and DeviceLoadStatus reflects actual IM
traffic and established subscriptions. Both unchanged official cases fail on
the previous binary and pass after repair: **TC_DGGEN_2_4 and TC_DGGEN_2_5,
2/2 PASS**. Latest matrix: **83 PASS, 22 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**;
unselected rows are inherited. Six focused native tests pass normally and with
ASan/UBSan/LSan. Full two-instance Memcheck reports zero errors/leaks; the separate
sanitizer scenario also passes. See [CSA08 evidence](csa08-validation.md) and
[all attempts](csa08-results.json).
CSA09 above records the subsequent invalid CASE input repair and recheck.

CSA07 fixes a reproduced host discovery race: closing and reopening the same
commissioning window before asynchronous withdrawal completed could leave mDNS
stopped. The host now drains the transition and selects a fresh DNS-SD instance
per new window, as required by Core 1.6.1 section 4.3.1. Real CASE command/capture
reproduction fails before the fix and passes after it; the new native lifecycle
regression agrees. Final official results: **4/4 PASS** (three TC_ACL_2_8 runs
and TC_CADMIN_1_25). Nine old-binary official repetitions also passed, so the
specific cause of historical run 289 remains unproven. Latest matrix unchanged:
**81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Six focused tests pass
normally and with sanitizers; full two-instance Memcheck and separate
ASan/UBSan/LSan scenarios pass. See [CSA07 evidence](csa07-validation.md) and
[all attempts](csa07-results.json).
CSA08 above records the subsequent General Diagnostics repair and rechecks.

CSA06 reruns all four applicable Access Control cases. Latest results: **2 PASS,
2 FAIL**. TC_ACL_2_4 expects ProxyView despite its D conformance in Core 1.6.1;
TC_ACL_2_6 checks only the first status of a legacy clear/add/add write, whose
actual response is Success/Success/ConstraintError. Both remain FAIL pending
explicit CSA resolution. No production behavior was changed. Negative write
regressions verify rejection without invalid storage/events and fabric isolation.
TC_ACL_2_8 first timed out in discovery, then passed unchanged; its intermittent
failure remains open. The latest-status matrix stays **81 PASS, 24 FAIL,
21 BLOCKED, 32 MANUAL, 704 NA**, with unselected results inherited.
Six focused tests pass normally and separately with sanitizers; full two-instance
Memcheck and separate ASan/UBSan/LSan scenarios pass. See
[CSA06 evidence and limitations](csa06-validation.md) and
[all attempts](csa06-results.json).
CSA07 above records the subsequent discovery investigation and bounded fix.

CSA05 passes **3/3 official rechecks**: TC_IDM_2_2, TC_IDM_4_2 and TC_IDM_4_3,
with no skipped steps. Shared Read/Subscribe validation rejects a specific
non-global attribute without a concrete cluster before callbacks or subscription
reservation. Global wildcard paths remain valid. The native grammar tests also
correct a previously incorrect wildcard expectation. Combined matrix:
**81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; unselected rows are inherited.
Six focused tests pass normally and separately with ASan/UBSan/LSan. Full
two-instance scenarios pass under Memcheck (zero errors/leaks) and separately
with sanitizers. See
[CSA05 evidence](csa05-validation.md) and [all attempts](csa05-results.json).
CSA06 above records the subsequent Access Control validation.

CSA04 passes **5/5 official rechecks**, including the previously failing
TC_IDM_4_3 and TC_CADMIN_1_25. Root no longer repeats unchanged values on meter
notifications, attribute-only subscriptions accept up to 32 selectors with
bounded capture/chunking, and committed fabric removal updates the open window's
AdminFabricIndex while preserving VendorID and window state. Combined matrix:
**80 PASS, 25 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Unselected rows are inherited.
Six focused tests pass normally and separately with ASan/UBSan/LSan. Full
independent-instance scenarios pass under Memcheck (zero errors/leaks) and
separately with sanitizers. See [CSA04 report](csa04-validation.md) and
[all attempts](csa04-results.json).
These CSA04 totals precede the CSA05 rechecks above. Timer/deadline
consolidation stays in the post-acceptance optimization stage of the roadmap.

CSA03 corrects Descriptor composition: Root includes OTA Requestor; opt-in
meter services include the identity-only Electrical Utility Meter and its
Meter Reference Point base alongside Electrical Sensor. No tariff condition or
billing device type is advertised. Official rechecks: **12 PASS, 1 FAIL** (test
VID in TC_IDM_10_1); TC_IDM_10_5 now passes. Combined matrix: **78 PASS, 27 FAIL,
21 BLOCKED, 32 MANUAL, 704 NA**. Full two-instance Memcheck and separate
ASan/UBSan/LSan scenarios pass; unselected CSA results are inherited.
See [CSA03 evidence and limits](csa03-validation.md) and [result delta](csa03-results.json).
These CSA03 totals precede the CSA04 rechecks above.

CSA02 fixes host clock scanning after removal from a sparse fabric table and
fail-safe cleanup waiting for a peer ACK after the commissioner has evicted PASE.
The expiry response now drains its local UDP operation before session-context
retirement and rollback. See [lifecycle acceptance](csa02-validation.md) and
[recheck evidence](csa02-results.json). The original CSA01 matrix below remains
the historical baseline; unselected tests have not been rerun.
The seven final rechecks yield **4 PASS and 3 FAIL**, moving the combined matrix
to **77 PASS, 28 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**. The three remaining
selected failures are documented test/specification discrepancies, not waived
results. Full two-instance Linux scenarios pass under Memcheck (zero errors and
zero live allocations at exit) and separately ASan/UBSan/LSan. These are the
historical CSA02 totals, before the CSA03 rechecks above.

CSA01 establishes the complete installed-catalog matrix for the current x86
profile: `--three-phase --source-registers --meter-services`, endpoints 0/1/3/4/5.
Final matrix: **73 PASS, 32 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**; no PLANNED
entries. There were 112 official runs for 109 entries, including retained attempts.
The [acceptance report](csa01-validation.md) and [matrix](csa01-matrix.json) retain
official results, endpoint-local PICS, versions, evidence hashes, manual procedures
and missing fixtures. This is a first broad acceptance pass, not certification.
All four historical failures reproduced; additional failures affect composition,
fabric/session lifecycle, reporting, discovery, diagnostics and resource pressure.
Some failures instead concern lab prerequisites, development identity or possible
test/specification discrepancies; none is silently waived.

MP04a: startup discovery failure traced to the pinned chip-tool `onnetwork-long`
selection path, which accepts an unrelated unsolicited announcement. Captured
PTR/SRV/TXT records have the correct discriminator/instance/port relationships.
The pair oracle uses unmodified chip-tool's `pairing code` path, which checks the
returned discriminator. The startup regression begins browsing before both full
runtimes start, without an announcement-settling sleep. The legacy tool path
remains unreliable in this situation; the C responder/API is unchanged.
See [MP04a evidence](mp04a-validation.md).
Discovery/commissioning selected the correct ports in all four final QR-path
runs. Three complete pair scenarios passed; the Memcheck A-then-B run failed
later at RemoveFabric (request ACK received, Invoke response timed out). That
independent acceptance failure remains open alongside the CSA01 failures;
it is not relabelled as a full-pair PASS.
CSA02's two final full-pair rechecks did not reproduce that timeout. Its cause
remains unestablished, so the historical issue is not considered fixed.

MP04 implemented: opt-in `--three-phase --meter-services` adds Identify and
Meter Identification on EP1 and Time Synchronization on EP0. Each instance owns
its callbacks/clock; the host persists Last Known Good time in an atomic sidecar.
Focused official CSA tests passed; this is not complete utility-meter support.
See [MP04 report](mp04-validation.md), [contracts](../meter-services.md) and the
[ordered acceptance roadmap](../roadmap.md).

MP03 implemented: opt-in `--three-phase --source-registers` adds a configurable
manufacturer-specific source cluster. It preserves tariff/quadrant/demand
registers, directional values, metadata and volume channels with explicit
units/provenance/nullability. Complete host and two-instance controller runs
passed under Memcheck and separate ASan/UBSan/LSan. Official TC_DESC_2_1 passed
with the new cluster attached; private schema checks remain separate.
See [MP03 report](mp03-validation.md)
for actual coverage, RAM cost and limitations. No firmware integration.

MP02 implemented and accepted for the x86 complete-pair simulator: opt-in
three-phase profile, Descriptor/TagList, multi-measurement EPM and explicit
EEM register mode. The default profile and constructors remain available.
Focused official CSA acceptance: 10/10 PASS. Independent chip-tool Read/Subscribe,
restart and two complete instances passed, including separate full Linux
Memcheck and ASan/UBSan/LSan runs. See [MP02 report](mp02-validation.md) for
commands, native tests, source-availability limitations and storage migration.

Protocol work targets Matter 1.6.1; this is an experimental partial implementation.
Complete callback-driven runtime, PASE/CASE/IM, commissioning, ACL, diagnostics,
power/energy measurement and simulated OTA are present. Linux/Windows host
adapters and an installable CMake package are included. Hardware integration and
a production OTA bootloader are outside the current validated scope.

The four historical official CSA failures remain unresolved and are reproduced
in CSA01. They are no longer the complete failure list:

- TC_CGEN_2_2: trusted-root count during the fail-safe scenario.
- TC_OPCREDS_3_4: RevokeCommissioning response timeout over PASE.
- TC_ACL_2_4: deprecated ProxyView behavior/profile expectations.
- TC_ACL_2_6: legacy ConstraintError expectation.

Later focused OPCREDS3.8/ACL2.8 runs passed, including separate Memcheck and
ASan/UBSan/LSan scenarios. These historical results do not constitute a complete
CSA matrix, certification or a fresh acceptance run of this public snapshot.
See validation.md for the publication snapshot and mp02-validation.md for the
subsequent three-phase acceptance; neither is a full-stack certification.

**Historical CSA01 follow-up: CSA02 - commissioning, fail-safe and selective fabric/session teardown.**
Full applicable CSA acceptance takes priority over new tariffs. Work proceeds in
successive passes over the [roadmap](../roadmap.md), with explicit coverage gaps,
evidence and follow-up actions. Address the connected CGEN/OPCREDS/CADMIN lifecycle
failures as one coherent implementation pass, including the independent
concurrent-subscription RemoveFabric regression from MP04a. Retain the remaining
CSA01 failures and blocked/manual coverage for subsequent passes.
