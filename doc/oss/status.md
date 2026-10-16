# Development status

The optional metered socket now exposes EPM/EEM/Power Topology on the On/Off
endpoint, using an independent synthetic 600 W / 0 W source and persistent
cumulative import. A whole-profile Read reproduced the former 320-result
ceiling; Read/Subscribe results now grow dynamically to an application limit
of 512. Seven focused CTests pass on Windows, Linux and separate Linux
sanitizers. Full CHIP commissioning/Read/Subscribe/On/Off/restart/RemoveFabric
passes under Memcheck and separately ASan/UBSan/LSan, including corrupt-state
startup rejection. Manual Apple Home on iOS 27.0.1 recovered online and showed
600 after On; the user reports its unit as `T`, unresolved UI labeling.
Energy totals in that UI are not confirmed. These are interoperability results,
not new CSA acceptance; counts and next CSA24 task below are unchanged.
See [metered socket evidence and limits](plug-energy-validation.md).

**CSA23: TC-SU-2.5 manual PASS, run446**, five verification steps and evidence
upload. The previous binary returns Idle after Discontinue but retains the
verified download; an optional application discard callback now removes the
host candidate. Failed removal revokes candidacy and logs failure. The existing
Apply action/timer policy is unchanged. Peer traces and monotonic logs confirm
Proceed/180 at 180.001 s, Await/60 at 120.208 s
and Await/180 at 180.267 s, with exact token/version and request-count checks.
Five full scenarios pass under Memcheck: nine host boots, 260,130 matched
allocations/frees, zero errors/leaks. Separate Await/retry/update/restart and
Discontinue ASan/UBSan/LSan scenarios pass; each build passes eight focused
CTests. Counts: **97 PASS, 14 FAIL, 10 BLOCKED, 37 MANUAL, 704 NA**; this is manual
acceptance, not automatic CSA coverage or certification. Other rows are inherited.
Consumers must rebuild for the appended optional OTA port callback. See
[CSA23 evidence and limits](csa23-validation.md) and [delta](csa23-results.json).
**Next: CSA24 — automatic TC_SU_2_5, provider IPC, subscriptions and interruption.**

**CSA22: TC-SU-2.4 manual PASS, run445**, with its required verification step
and evidence upload. Peer JSON traces prove ApplyUpdateRequest uses the latest
QueryImageResponse token and the authenticated image version, for separate
version 1-to-2 and 1-to-3 simulations. A valid signature with a different version
is rejected before Apply/Notify and keeps the installed version unchanged.
The OTA engine already enforced this binding; the change strengthens its oracle
and native copied-context regression. Counts are now **97 PASS, 14 FAIL,
11 BLOCKED, 36 MANUAL, 704 NA**; manual PASS is separate from automatic coverage.

Read/Subscribe now allocate input at actual received length and output according
to configuration. RX supports 1202 application bytes; TX supports 1198, reserving
four additional wire bytes for a piggyback ACK. These follow the 1280-byte IPv6
UDP ceiling, not a larger transport. Native cases cover 83 filters, 1025/1198/1202
byte requests, oversize rejection and allocation failure. Linux passes 11 focused
tests in normal and sanitizer builds; Windows passes five. Full IM and OTA
scenarios pass under Memcheck and separately ASan/UBSan/LSan. See
[CSA22 evidence, commands and limits](csa22-validation.md).
**Next: CSA23 — TC-SU-2.5, ApplyUpdateResponse actions and real delay/retry timing.**

DataVersionFilters recovery fixes a reproduced Apple Home resubscription failure:
the old 16-entry table rejected a 547-byte SubscribeRequest with ResourceExhausted.
Read/Subscribe now allocate exactly the validated filter count, bounded by the
existing request byte budget, with no allocation for empty lists. Native tests
cover 70 filters, malformed tails, conflicting versions and allocation failures;
the added Subscribe allocation variant checks cleanup. Four focused tests pass
on Windows, Linux and separate Linux ASan/UBSan/LSan builds. Independent CHIP
scenarios pass under Memcheck and separately under sanitizers: 17 cluster filters,
fresh CASE, filtered priming, live On/Off reports and RemoveFabric. Memcheck has
31,177 matched allocations/frees, zero errors and zero live bytes. The preserved
Windows pairing recovered; the user confirmed Apple Home online and On/Off.
This is local interoperability evidence; the CSA matrix is unchanged.
See [details and limits](im-version-filters-validation.md). Next remains CSA22.

CSA21 fixes OTA recovery after a provider process restart: exhausted outbound
MRP retries retire only that peer's operational session, so a later operation
establishes CASE. The preceding binary reproduces unknown-session drops and
fails the full retry scenario; the new native regression fails with the old code.
**TC-SU-2.3 passes as a manual TH procedure in run444**: complete transfer and
interruption/retry, evidence upload, consent/HTTPS/resumption N/A. The fixed
interruption scenario waits 301.021 real seconds, independently reads Idle /
version 1, and completes a new transfer from offset zero without restarting or
recommissioning the requestor before retry. Uninterrupted and interrupted OTA
pass under Memcheck: four requestor boots, 111,042 allocations/frees, zero
errors/leaks. Each build passes 13 focused CTests with no compiler warnings.
A separate ASan/UBSan/LSan interruption/retry run waits 301.053 seconds and
completes both requestor boots with clean exits and empty stderr.
Latest matrix: **97 PASS, 14 FAIL, 12 BLOCKED, 35 MANUAL, 704 NA**;
this manual PASS does not increase automatic coverage. Other official rows are
inherited. See [CSA21 evidence](csa21-validation.md), [delta](csa21-results.json)
and [fixture contract](../ota-host.md). Host simulation is not firmware installation
or certification; Windows, hardware and Home UI acceptance remain unperformed here.
**Next: CSA22 — TC-SU-2.4, ApplyUpdateRequest fields and token/version binding.**

CSA20 fixes an early OTA retry after repeated AnnounceOTAProvider: the
conservative 120-second floor now survives asynchronous CASE setup and starts
from Invoke completion. The old binary reproduces 119.862/119.858-second
intervals; the new native regression fails with the old code and passes with
the fix. **TC-SU-2.2 passes as a manual TH procedure in run443**: six evaluated
steps, optional HTTPS N/A and evidence upload. Actual provider responses cover
UpdateAvailable, Busy/60, NotAvailable, Busy/180, both same/older versions and
an invalid BDX URI. Busy limits pass at 120.239 s between queries and 180.247 s
from the response respectively. All seven scenarios pass under Memcheck:
10 C requestor boots, 315,962 allocations/frees, zero errors/leaks. Separate
ASan/UBSan/LSan update/restart and 11 focused CTests per build pass.
Latest matrix: **97 PASS, 14 FAIL, 13 BLOCKED, 34 MANUAL, 704 NA**;
the changed row stays MANUAL with recorded PASS, not automatic CSA coverage.
See [CSA20 evidence](csa20-validation.md), [result delta](csa20-results.json)
and [fixture contract](../ota-host.md). Other official rows are inherited.
**Next: CSA21 — TC-SU-2.3, applicable OTA image-transfer procedures and failure paths.**

CSA19 prepares the official CHIP OTA provider, a signed simulation image and
restart orchestration. **TC-SU-2.1 passes as a manual TH procedure in run442**:
three evidence-based prompt decisions and the attached log, not automatic CSA
assertions. Run441 is retained as cancelled at the CLI upload step. The single
row moves BLOCKED to MANUAL with a recorded manual PASS; latest matrix:
**97 PASS, 14 FAIL, 14 BLOCKED, 33 MANUAL, 704 NA**. Other rows are inherited.
The MANUAL count includes this completed procedure and otherwise unexecuted work.
Full BDX/authentication/simulated restart/fresh CASE scenarios pass normally,
under Memcheck (55,065 allocations/frees, zero errors/leaks) and separately under
ASan/UBSan/LSan. C/H sources and binaries are unchanged from CSA18. This is not
executable firmware installation or certification. See [CSA19 evidence](csa19-validation.md),
[result delta](csa19-results.json) and [fixture contract](../ota-host.md).
Manual Home removal/re-add remains pending; user fabrics are not lab fixtures.

The entries below retain preceding campaigns; the newest entry supersedes
their next-task pointers without changing inherited results or limitations.

CSA18 completes the targeted energy fixture for the existing three-phase host.
Unchanged official **TC_EPM_2_2 passes on EP1/3/4/5 (runs435–438)** and
**TC_EEM_2_2/2_3 pass on EP1 (runs439/440)** after baseline run434 reproduces
the missing trigger route. Latest matrix: **97 PASS, 14 FAIL, 15 BLOCKED,
32 MANUAL, 704 NA**; only those six previously blocked rows change classification.
Optional ActiveCurrent/aggregate Voltage steps stay N/A. Normal and separate
ASan/UBSan/LSan focused tests pass 9/9; full pair memory/controller results and
source/binary identities are in [CSA18 evidence](csa18-validation.md) and its
[result delta](csa18-results.json). Default non-fixture behavior, public core
API and PICS are unchanged. This is Linux x86 acceptance, not certification.
Manual Home removal/re-add remains pending;
no user-paired state is used for laboratory campaigns.

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
