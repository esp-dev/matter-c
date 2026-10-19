# Test inventory

test-map.json enumerates 242 test, fixture, fuzz and controller files. Run
`python tools/matter/check_test_map.py` to verify coverage, current dependency
source membership and the closed public-header set.

`test_pase_exchange_chip.py` records unmodified chip-tool's actual PASE UDP
datagrams across two full commissions, with the first fabric's CASE active when
opening the second window. Typed TLV, message/exchange headers, success status,
encrypted-data ordering and sampled session-ID/random separation are checked
against Core1.6.1; four altered in-memory captures test oracle rejection. The
original TC-SC-2.1 wording is evaluated separately, without rewriting its
addressing, hasPBKDF or byte-size discrepancies. Raw packets, setup codes and
controller state stay private. Run Memcheck and sanitizers separately; independent
Core evidence is not an automatic or manual CSA PASS.

CSA38 adds `--tamper-pase`: send a one-bit MIC corruption before the first valid
encrypted request and response, hold originals/retransmissions for at least 0.6
seconds per direction, then release them. Observe no encrypted peer progression
during the hold and successful commissioning in the same PASE session afterward.
This demonstrates message rejection/recovery required by Core4.8.3. Original
TC-SC-2.2 Step5's stronger session-termination/key-clear expectation is evaluated
separately; no key-memory dump or wire proof of key erasure is claimed.

CSA39 adds mutually exclusive `--pase-errors`: isolated negative controllers alter
only passcodeID0 to1 or one cA bit, with valid TLV/headers. Observe required error
statuses for up to 12 seconds, terminate pending controller commands if necessary,
then send late valid-shaped Pake1/correct cA with fresh counters. Confirm no
reactivation, followed by two full commissions/CASE without DUT restart. Missing
StatusReports are explicit conformance assertions and keep the overall result
FAIL even when all functional recovery checks pass. The opt-in partial negative
transcript reader does not waive the status assertion; default positive PASE
validation still requires the complete six-message success exchange.

CSA40 adds mutually exclusive `--mrp-size`: skip-only Matter MX padding around
a valid small PBKDF request exercises complete IPv6 sizes1279/1280/1281/1328/1329
(UDP payloads1231/1232/1233/1280/1281). Require matching ACK/PBKDF replies at the
boundary and two seconds of silence above it, then two full commissions/CASE
without DUT restart. No IPv6 extension options, DONTFRAG, unique identities and
counters; fixed40+8 headers are accounted explicitly. Original manual TH results
are recorded separately. See [CSA40 evidence](csa40-validation.md).

CSA41 adds mutually exclusive `--mrp-flows`, requiring Python cryptography and
the existing `fixtures/pase-vector.py` test arithmetic. An independent peer
completes reliable PASE, checks data/piggyback and duplicate/standalone ACKs,
then sends five authenticated VendorID ReadRequests with R=0 between successful
R=1 controls. Missing data replies remain explicit conformance/overall FAIL.
The peer closes its PASE session before the usual two chip-tool commissions/
CASE reads, without DUT restart. Keys are never exported; raw state stays
private. See [CSA41 diagnosis and limits](csa41-validation.md).

CSA42 adds mutually exclusive `--mrp-retries`: advertise idle=active500ms, send
one valid PBKDF request and discard all DUT replies for12 seconds. Check five
identical data transmissions/four retries, real Core backoff gaps, terminal tail
silence and no revival on a late ACK, followed by two full commissions/CASE.
Equal intervals isolate timing but do not prove state selection. Keep original
TC-SC-1.3 Step4's total-versus-retry wording result separate from independent
Core acceptance. See [CSA42 evidence and limits](csa42-validation.md).

CSA43 adds `--mrp-duplicates`: ACK the original reliable PBKDF response, then
repeat the same request/counter three times. Require matching standalone ACKs
and no repeated data output, followed by two fresh full commissions/CASE without
DUT restart. See [CSA43 evidence](csa43-validation.md).

`test_commissionable_announcement_chip.py` supplies CSA34 wire/controller evidence
for unsolicited announcements, actual unfiltered chip-tool browsing and complete
basic/closed/enhanced Commissionable Node Discovery records, addresses, subtypes
and instance rotation. Run under Memcheck and separately with a sanitizer node.
Functional checks do not waive the independent required-PH predicate: actual
CM=0 without truthful PH makes the whole validation FAIL. CSA35 adds explicit
unlimited/off/timed policy scenarios, withdrawal with live CASE/operational
discovery, and subsequent enhanced-window reopening. Keep raw packets/state
private. See `csa34-validation.md` for the retained original failure and
`csa35-validation.md` for the fix and updated-PICS acceptance.

`test_last_fabric_discovery_chip.py` checks the actual last-fabric response,
operational SRV/goodbye/no-late-reply observations, active-subscription teardown,
same-store explicit restart and commissioning with a fresh controller. It records
Step4's literal CM=0 comparison separately from the supported CM=1 basic window.
Run under Memcheck and separately with a sanitizer node; this independent fixture
does not change the original manual FAIL recorded in `csa32-validation.md`.
With `--same-controller --qr-image /private/card.png`, it also checks the CSA33
same-live-controller lifecycle, scans the supplied bitmap with Pillow/zxing-cpp,
verifies CM=0 after both commissioning completions and rediscovers the same
fabric/node identity after recommissioning. Old controller subscriptions are
explicitly released after removal. See `csa33-validation.md` for manual TH results;
no native runtime change or fresh physical/Home UI acceptance is implied.

`test_onboarding_payload_chip.py` supplies CSA31 operator evidence from a scanned
C-generated QR bitmap, chip-tool parsing/checksum controls and live mDNS. It
requires Pillow, zxing-cpp2.3.0, an existing C payload utility and shared qrcodegen
library. Its manual setup card is generated by CHIP; it does not add a desktop
manual-code field or accept physical labels. Keep all output private. Original
TH results and known coverage gaps are separate in `csa31-validation.md`.

`test_general_diagnostics_chip.py` checks process-relative node time, restart
and factory-reset counters, live NIC MAC/addresses, empty fault lists and the
disabled test-trigger default. It compares NetworkInterfaces against Linux OS
data. Run the full three-boot scenario separately under Memcheck and sanitizers.
This short acceptance does not replace the original TC-DGGEN-2.1 hour-long waits.

`test_identify_chip.py` checks Identify command60, real countdown, command0,
write15, expiry, quiet countdown reporting and fresh CASE after restart against
live application callbacks. IdentifyType0 has no physical presentation. Run
separately under Memcheck and sanitizers; official mixed manual/automatic TH
acceptance is reported independently in `csa29-validation.md`.

`test_ota_attributes_chip.py` is an optional two-fabric OTA attribute scenario
using unmodified chip-tool. It checks every WriteResponse status, partial list
updates, fabric isolation, mandatory state attributes and persistence after
restart. Run separately with Memcheck and sanitizers. This local acceptance does
not replace the original TC_SU_4_1 result; see `csa27-validation.md`.

`test_csa24_progress.py` is an optional offline regression for an externally
supplied SDK test/helper source. It executes the actual progress-wait AST using
deterministic report queues and clocks, checks negative/positive chronological
sequences and bounded timeout, and verifies preservation of original assertions
and scenario subscription ownership. It is not a default CTest or official CSA
result; see the local patch contract in `tools/matter/patches/README.md`.

CMake defines 87 native test variants, with explicit platform/privilege filters.
Default CTest totals: 88 on Windows, 85 on Linux, including inventory, crash
recovery and a relocated installed-package consumer with two runtimes.

`test_gui_pairing` checks native C QR packing and onboarding boundaries.
The optional `test_gui_host_chip.py` drives two concurrent pipe-controlled
minimal workers through signed Read/Subscribe, malformed input, restart/fresh
CASE, distinct identities and last-fabric removal. Run under Memcheck and
separately sanitizers; this does not test Win32 painting or ecosystem UI.
`test_node_discovery` drives the real host advertisement composition through
deferred removal and rapid window reopening with a deterministic backend.
`test_dispatch` also drives malformed CASE input through ingress and the real
engine into reliable failure-report delivery, retry and ACK/exhaustion/stop drain.
It additionally provisions the transaction table from Root CapabilityMinima,
checks budgets 3/4/8 when transport permits, rejects unsupported/range-exceeding
budgets, checks full-budget rejection, fabric isolation and scoped replacement,
and injects failure of the second constructor allocation (the table). The OTA
CHIP provider runner accepts an explicit budget and reads its advertised value
before exercising download, retry, restart and Notify.
`test_discovery` covers service/subtype enumeration and shared-record suppression;
`test_mdns_linux.py` verifies enumeration and known-answer thresholds on multicast
alongside its existing TC/NSEC/address/duplicate-response checks.
`test_opcreds` exercises five-fabric NOCs/Fabrics subscription chunking and
DataVersion suppression; `test_root` and `test_im_subscribe` cover unrelated
notifications, retained heartbeat deadlines, late owner-loop wakeups and bounded
exchange/status timeouts. CSA11 retains failing controls with the old behavior.
`test_pase` also checks one-shot failure notifications and success/cancel
exclusions. `test_runtime` and its allocation variant inject failed PASE requests
and duplicates through public ingress, checking the twentieth-attempt closure
and isolation of another runtime. CSA12 records a failing old-runtime control.
`test_fabric` also fills the fabric table and admits a distinct pending RCAC,
checks signature/storage errors and TableFull, then verifies rollback/root-only
journal recovery without changing installed records or keys. CSA13 records its
failing old-host control and the unchanged official CADMIN 1.19/OPCREDS 3.1 results.
The optional `--wifi-sim-connected` mode of `test_discovery_startup_linux.py`
passes through to `runtime-pair-host` and its CHIP controller. It checks each
instance's connection, rejects unarmed scans, then exercises armed general and
directed scans, missing SSIDs, Breadcrumb and rollback during the full pair
lifecycle. This supplementary scenario is not TC_CNET_4_4 acceptance.
CSA15 extends the same optional scenario with exact network-list checks,
wrong-password rejection/error clearing, second-AP connection, rollback,
CommissioningComplete retention and isolation of the other runtime. It does
not switch OS interfaces and is not TC_CNET_4_11 acceptance. The unchanged
official TC_CNET_4_9 result and its runner parameter fixture are documented
in [CSA15](csa15-validation.md).

[CSA16](csa16-validation.md) reproduces unchanged TC_CADMIN_1_10 step 9 on
the CSA14 binary. Its PASE RevokeCommissioning response expectation conflicts
with Core 1.6.1 11.19.8.3. The official FAIL is retained pending CSA/test
resolution; no implementation regression or native/memory rerun was added.

[CSA17](csa17-validation.md) adds the opt-in MTRID change/reset test event
triggers to the meter-services host and `runtime-pair-host --test-event-key`.
The pair scenario `--meter-triggers` verifies changed/reported/cleared
identity on one runtime, unchanged identity on the other, and wrong-key or
unknown-event rejection. `chip_tool_meter_triggers.py` covers run/disabled/
restart modes on a disposable node. These are laboratory regressions, not
official TC_MTRID_3_1 acceptance, which is recorded separately.
The [follow-up](csa17-review-validation.md) executes the stricter oracle: four
SET/CLEAR reports, no unchanged identity reports on unrelated samples, instance
isolation, restart and last-fabric reset. Readback uses a separate controller
connection so asynchronous A reports cannot contaminate B's identity check.
Full pair Memcheck and separate ASan/UBSan/LSan pass; official MTRID 3.1/2.1
pass in runs336/337. Historical failures remain in the earlier report.

CSA18 extends `test_energy_sim` with profile-specific normal source rates and
counter continuity across generator/STOP transitions. The existing pair
`--meter-triggers` oracle also exercises load/STOP on all four EPM endpoints of
both nodes, varying phase voltage, invalid targets/codes, peer/phase isolation,
aggregate export growth and no rollback after STOP. Official EPM/EEM results
and skipped optional steps are recorded separately in
[CSA18](csa18-validation.md); these local checks do not replace them.

CSA19 adds `test_ota_chip_provider.py`: an unmodified CHIP OTA provider,
attested commissioning, QueryImage/Busy timing, BDX, signed simulated install,
restart and fresh CASE readback. `--mode update --valgrind` covers both boots;
a separate sanitized executable covers ASan/UBSan/LSan. It is optional and is
not part of native CTest. Official TC-SU-2.1 is a manual TH procedure; its
prompt decisions and attached evidence are recorded separately in
[CSA19](csa19-validation.md) and the [fixture contract](../ota-host.md).

CSA20 extends the same runner with actual QueryImageResponse trace validation,
Busy 60/180-second and NotAvailable timing, both same/older version offers and
invalid BDX URI rejection. The optional provider JSON trace is independently
parsed by Python; neither provider CLI flags nor a successful announcement alone
establish the response under test. No new CTest definition or source is added.
The existing `test_ota_query` and allocation variant add an asynchronous-setup /
repeated-announcement regression that fails with the previous stored query floor.
See [CSA20](csa20-validation.md) for the manual TH result and coverage limits.

CSA21 extends that runner with `interrupt-retry`: a real provider process kill
after a verified partial prefix, five real minutes, independent Idle/version
readback, partial-file cleanup, provider restart with retained KVS, ReceiveInit
at offset zero and the full authenticated simulation/restart/Notify path.
Normal `update` remains a separate uninterrupted-transfer control. These are
optional external CHIP scenarios, not new native CTest definitions. The installed
TC-SU-2.3 remains a manual TH procedure; its conditional consent/HTTPS/resumption
steps require features outside this profile. Results and limits are recorded in
[CSA21](csa21-validation.md).
The existing `test_dispatch` also checks outbound MRP timeout retirement and its
peer isolation, with negative controls for ACK, cancellation, local send failure,
inbound traffic and PASE. The timeout control fails against the preceding code.

External CHIP/TH, Matter.js network scenarios, fuzz campaigns and privileged
IPv6 injection are optional, not implied by default CTest results. Their scripts
and prerequisites are retained in tools/matter/tests and fixtures. See each
entrypoint and the map for exact routes; generators are not build prerequisites.
No CSA test distribution is bundled, and no local result waives open CSA failures.

DataVersionFilters regression adds `test_im_subscribe_alloc` alongside the
existing Read allocation variant. Both native suites now cover 83 entries and
malformed final entries beyond the former entry/token budgets; Subscribe checks
that version suppression only applies to priming and that its filter table is
released before idle, on allocation/reservation errors and deletion.
`test_im_version_filters_chip.py` runs a disposable full-profile host against
unmodified chip-tool, with 17 distinct cluster filters, exact inventory, fresh
CASE after controller restart, subsequent switch reports and RemoveFabric.
Its `--memcheck` mode and a separate sanitizer host run are external scenarios.

CSA22 extends those native tests with exact-sized RX/TX ownership, requests of
1025/1198/1202 bytes, oversize rejection and constructor/receive allocation
failure. The runtime dispatcher uses the transport-derived output budget.
`test_ota_apply` mutates both the caller token and version after begin and checks
the immutable command copy. The existing CHIP provider runner adds peer-trace
Apply/Notify token/version correlation, independent versions 2 and 3, and an
offered/signed-version mismatch rejection scenario. These remain external
scenarios, not new CTest definitions. See [CSA22](csa22-validation.md).

CSA23 adds five `apply-*` modes to that external runner: real Proceed/0,
Proceed/180, Await/60 (120-second floor), Await/180 followed by Proceed, and
Discontinue. Decoded peer responses, exact request counts, token/version binding,
monotonic timing, retained version during delay and physical candidate disposal
are checked. `test_bdx` and its allocation variant cover scoped file discard,
stale/restarted ownership, removal failure and candidacy revocation. The eight
focused BDX/Apply/update/runtime CTests and their allocation variants remain
existing definitions. See [CSA23](csa23-validation.md) for actual runs and limits.

The existing `test_ota_query` and allocation variant distinguish a Busy response
from transport/IM/malformed-response/timeout failures. They retain retry timing
checks while requiring Idle for non-Busy backoff. `test_bdx` and its allocation
variant also check unknown progress before a validated header, monotonic bounded
progress across byte-wise writes, completion and reset after commit/cancel.
These extend existing definitions rather than adding CTest entries.

`test_plug_energy_chip.py` exercises the disposable full-profile metered socket:
verified attestation, exact whole-tree inventory, mixed EPM/EEM attribute/event
subscription, 600 W / 0 W transitions, paused import while off, zero export,
persistent import after restart/fresh CASE, and last-fabric removal. Run with
`--memcheck`, then separately against a sanitizer executable. Native Read and
Subscribe suites cover 512/513 expanded-result limits, initial/growth allocation
failure, Read plan allocation failure and cleanup. `test_energy_sim` covers
fractional carry across short On/Off bursts. See
[actual results](plug-energy-validation.md); these are not official CSA cases.

The same runner's optional `--power-only` mode adds endpoint 6 to that host.
Its inventory requires Electrical Sensor with exactly Descriptor/EPM/Power
Topology, excluding On/Off and EEM. CASE reads and Subscribe priming verify
123000 mW; reads after socket On, Off and restart verify source independence.
The default runner mode and CSA profile are unchanged. See
[power-only acceptance](power-only-validation.md).

`test_plug_energy_chip.py --sensor-only` instead verifies the minimal
`--power-sensor-only` node. Its full-tree inventory requires only endpoints
0 and 1 and excludes On/Off/EEM throughout. It checks 123 W Read/Subscribe,
restart/fresh CASE, last-fabric removal and rejection of five conflicting CLI
profiles. Both modes remain external scenarios, not additional native CTests.
See [minimal sensor evidence](sensor-only-validation.md).

Adding `--sensor-energy` to that runner enables EEM in the minimal host and
verifies FeatureMap 7, distinct import/export values, mixed power/energy/event
Subscribe, import growth at constant positive power, unchanged historic export
and retention of both registers after restart. The pure-EPM mode keeps its
no-EEM inventory assertion. See [energy evidence](sensor-energy-validation.md).

CSA44 records original TC-DESC-2.1 FAIL, TH run480: flat PartsList wording and
incomplete whole-device cluster acceptance. Independent five-endpoint Descriptor/
served-catalog acceptance passes 117 checks per memory variant without native changes.
See [CSA44 evidence](csa44-validation.md). Continue with BDX receiver coverage.

CSA45 records TH run481: BDX1.2/2.2 and IDM1.1 manual PASS; BDX2.3 restart FAIL.
Real binary transfer/image/counter checks and four DUT-originated invokes are
separate from the failed recovery. See [CSA45 evidence](csa45-validation.md).

CSA46 records TH run482: DGGEN2.2/DGWIFI2.2/GRPKEY5.4 manual PASS with explicit
optional-event NAs; CNET4.13 FAIL retains BLE/arithmetic limits. Functional BootReason,
network reorder/rollback/commit and policy rejection pass. See [CSA46 evidence](csa46-validation.md).

CSA47 corrects two stale onboarding applicability positions to NA using original
PICS predicates and current TH exclusion, without changing PICS. Four explicit
manual prerequisites remain visible; no new test run or PASS is claimed. See
[CSA47 review](csa47-validation.md).
