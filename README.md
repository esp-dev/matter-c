# Matter C

Standalone C99 Matter library and host development environment, licensed under
[Apache-2.0](LICENSE). Third-party terms are retained in [NOTICE](NOTICE) and
[provenance](doc/oss/provenance.md). This is experimental software, not a CSA
certified implementation. See [status and known failures](doc/oss/status.md).
The [CSA execution plan](doc/oss/csa-campaign-plan.md) and
[generated queue](doc/oss/csa-campaign-status.md) track remaining coverage,
failure attribution and later native repairs. Run `python tools/matter/csa_campaign.py`
to check that public evidence and the queue agree.

The application owns scheduling, networking, storage and hardware callbacks.
Multiple runtimes can run in one process/thread. The core does not require
ESP-IDF or FreeRTOS. See the [runtime contract](doc/runtime.md).

## Build

Requirements: CMake 3.20+, Git, GCC with C99, Python 3.9+ for tests/bootstrap.
Current package targets Linux or MinGW Windows. PowerShell is needed only for
the preserved Windows runners. Configuration/build never downloads dependencies.
On Windows put the MinGW-w64 compiler/DLL directory on PATH or pass `-Compiler`.
The package defaults to 128 buffered events. Set `-DMATTER_EVENTS_CAPACITY=16`
through `1024` at configure time to change the shared library/consumer budget;
the selected capacity propagates through the exported CMake target.

```sh
python tools/matter/bootstrap_mbedtls.py
# Offline alternative: add --source /path/to/existing/mbedtls-git-checkout
cmake -S . -B build/cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build/cmake -j 3
ctest --test-dir build/cmake --output-on-failure
```

```powershell
cmake -S . -B build/cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Debug
cmake --build build/cmake -j 3
ctest --test-dir build/cmake --output-on-failure
```

The bootstrap clones official [Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls)
3.6.0 (`mbedtls-3.6.0`, commit `2ca6c285a0dd3f33982dd57299012dacab1ff206`)
into ignored `third_party/mbedtls`, without Espressif patches.
It validates existing checkouts without resetting them. Build scripts accept
`--mbedtls` / `-MbedtlsDir` overrides. No source path outside this repo is needed.
Upstream license remains in that checkout. The current pin and evidence are in
[cmake/dependencies.json](cmake/dependencies.json), shared by bootstrap, CMake
and the legacy build/test runners.
For an existing old checkout, preserve it separately before bootstrapping, or use
`--destination third_party/mbedtls-upstream` and the CMake directory override.
The selected C sources and checked-in headers require no framework submodule.

Use `-DMATTER_MBEDTLS_DIR=/path/to/checkout` with CMake. On Windows, use native
CPython and set `-DPython3_EXECUTABLE=/path/to/python.exe` if CMake selects a
different installation. Socket/file-lock tests need normal local OS access.

## Install and consume

```sh
cmake --install build/cmake --prefix /path/to/matter-prefix
cmake -S examples/consumer -B build/consumer -DCMAKE_PREFIX_PATH=/path/to/matter-prefix
cmake --build build/consumer
ctest --test-dir build/consumer --output-on-failure
```

The consumer needs only `find_package(MatterC CONFIG REQUIRED)` and
`target_link_libraries(my_app PRIVATE MatterC::Matter)`. The exported target
propagates the selected ABI capacity and transitive platform/crypto libraries.
The development package has version 0.0.0, with no stability or publication claim.
Use `MatterC::Runtime` and `<runtime/matter_runtime.h>` for complete composition.
It links `MatterC::Matter` transitively. Supply crypto/credentials, atomic blob,
Wi-Fi, UTC/timestamp and regulatory callbacks, then attach application endpoints
to the borrowed Root. The application owns UDP, discovery and the event loop.
The small example exercises lifecycle/TLV/crypto; the installation test also
builds `tools/matter/tests/test_runtime.c` outside the repository against the
relocated package and starts two full runtimes using only public headers.

For a library-only build use `-DMATTER_BUILD_HOST=OFF -DBUILD_TESTING=OFF`.
For a small core-only configuration also set `-DMATTER_BUILD_RUNTIME=OFF` and
`-DMATTER_TRANSPORT_CAPACITY=8`. The complete runtime needs at least 52 slots;
the default is 56. Subscription capacity is configurable per instance through
`identity.capabilities.subscriptions`, also exposed by the host as
`--subscriptions-per-fabric N`. The dispatcher allocates its transaction table
for that budget and advertises the same value. For eight per fabric, build with
`-DMATTER_TRANSPORT_CAPACITY=128` and pass `--subscriptions-per-fabric 8`; the
existing default remains three. Impossible configurations fail before startup.
See [resource ownership and bounds](doc/runtime.md#subscription-resource-budget).
`-DMATTER_SANITIZE=ON` enables
ASan/UBSan and Linux leak detection in CTest. Do not run that build under Valgrind.

[Test map](doc/oss/test-map.md) records every retained test and optional route.
The default CTest suite excludes external controller, privileged IPv6 and fuzz
campaigns. The original `build_host.ps1`, `build_host_linux.py`, `run_tests.ps1`
and other runners remain usable; their production lists share `cmake/sources.json`.
They retain their previous command line and output locations.

## Host and tests

The English-language Windows [native C desktop](doc/desktop.md) builds as `matter-desktop.exe`:
one executable manages independent power-sensor windows, commissioning QR/status
and a release-triggered −10…+10 kW slider. Per-user state retains each node's
identity/pairing. Runtime dependencies are Windows/UCRT only; development
credentials remain external. See [acceptance](doc/oss/desktop-validation.md).
REST HTTP(S) integrations are planned, not implemented.

The [CSA18 campaign](doc/oss/csa18-validation.md) enables targeted energy test
inputs on the three-phase host. Official EPM2.2 passes on aggregate/L1/L2/L3,
and EEM2.2/2.3 pass on aggregate import/export. The laboratory key also retains
the MTRID fixture; phase energy is never fabricated. Current matrix and limits
are recorded in the [result delta](doc/oss/csa18-results.json).

The [CSA17 follow-up](doc/oss/csa17-review-validation.md) fixes redundant Meter
Identification subscription reports: unrelated energy samples no longer report
unchanged identity. Official MTRID 3.1/2.1 pass (runs336/337); full pair Memcheck
and separate sanitizer acceptance pass. Independent chip-tool also confirms
selective/last-fabric removal, restart and recommissioning with the same store.
The host exits after its last fabric is removed; restart it to commission again.
This is protocol acceptance, not a current manual Google/Apple Home UI test.
See the [result delta](doc/oss/csa17-review-results.json) and
[CLI/fixture contract](doc/meter-services.md#test-event-triggers-csa17).

The [CSA15 report](doc/oss/csa15-validation.md) records TC_CNET_4_9 PASS with an
explicit Wi-Fi parameter fixture and the unchanged CSA14 binary. TC_CNET_4_11
still needs a controller/DUT environment that can switch between real or
validated virtual AP networks; the local two-instance migration regression is
separate from official acceptance. See [result delta](doc/oss/csa15-results.json).

The [CSA14 report](doc/oss/csa14-validation.md) records the optional connected
Wi-Fi simulation: TC_CNET_4_1 passes; TC_CNET_4_4 remains FAIL because its
unarmed ScanNetworks receives the status required by Core 1.6.1. Supplementary
armed scans pass without relaxing that guard. See [result delta](doc/oss/csa14-results.json).

The [CSA13 report](doc/oss/csa13-validation.md) records full-fabric-table acceptance:
unchanged TC_CADMIN_1_19 and TC_OPCREDS_3_1 pass after removing premature RCAC
rejection, allowing AddNOC to return TableFull. See [result delta](doc/oss/csa13-results.json).

The [CSA12 report](doc/oss/csa12-validation.md) records the failed-PASE attempt
limit: unchanged TC_CADMIN_1_9 and TC_CADMIN_1_11 pass after closing the window
at twenty failures. See [result delta and coverage limits](doc/oss/csa12-results.json).

The [CSA11 report](doc/oss/csa11-validation.md) records concurrent resource
acceptance: TC_RR_1_1 passes with 15 subscriptions across five fabrics, including
the optional unchanged-session-ID check. TC_IDM_4_3 also passes after repairs to
redundant reporting and heartbeat scheduling. See [result delta](doc/oss/csa11-results.json).

The [CSA10 report](doc/oss/csa10-validation.md) records DNS-SD service/subtype
enumeration. Unchanged TC_SC_4_1 and the TC_SC_4_3 operational discovery recheck
pass, with the Basic Commissioning Window coverage limit recorded explicitly.
See [result delta](doc/oss/csa10-results.json).

The [development roadmap](doc/roadmap.md) orders CSA acceptance, Google Test Suite
and manual checks, measured optimization, then downstream firmware integration.
The [CSA01 acceptance report](doc/oss/csa01-validation.md) links the complete
installed-catalog matrix, frozen x86 profile, official results and coverage gaps.
The [CSA02 lifecycle report](doc/oss/csa02-validation.md) and
[recheck results](doc/oss/csa02-results.json) preserve subsequent fixes and attempts.
The opt-in [meter services](doc/meter-services.md) add Identify, Meter Identification
and a per-instance Time Synchronization server (`--three-phase --meter-services`).
The [CSA03 report](doc/oss/csa03-validation.md) records their corrected device-type
composition, official Descriptor/PICS rechecks and remaining test-identity limit.
The [CSA04 report](doc/oss/csa04-validation.md) covers subscription delta reporting,
all-cluster selector capacity and window state after fabric removal.
The [CSA05 report](doc/oss/csa05-validation.md) covers invalid Read/Subscribe
paths, global-attribute wildcard rules and the unchanged official IDM rechecks.
The [CSA06 report](doc/oss/csa06-validation.md) records Access Control validation,
two test/specification discrepancies and an unresolved intermittent discovery
timeout during multi-fabric commissioning.
The [CSA07 report](doc/oss/csa07-validation.md) documents the reproduced rapid
window-reopen discovery race, its fix, instance-name rotation and official
commissioning rechecks, with the historical timeout's attribution limit.

The optional [three-phase profile](doc/three-phase.md) adds tagged aggregate/L1/L2/L3
endpoints and EEM source-register semantics: run the host with `--three-phase`
and a separate state file. The default host profile is preserved.
Add `--source-registers` for the [manufacturer-specific source view](doc/meter-source.md):
tariff/quadrant/demand registers, directional values, metadata and volume channels.

`--test-switch` adds a simulated metered socket on endpoint 2: On/Off plus
Electrical Sensor, Power Topology, EPM and EEM. It reports 600 W while on and
0 W while off, with its own cumulative import register and zero export.
With `--state`, a separate `.plug-energy` TLV sidecar retains that register
and its fractional remainder. It starts off after restart. This UI experiment
is an incomplete plug device profile, not certified hardware; see
[validation and UI limitations](doc/oss/plug-energy-validation.md).

For a separate power-only UI experiment, add `--test-power-only`. Endpoint 6
is an Electrical Sensor with Descriptor, EPM and Power Topology, reporting
a fixed synthetic 123 W independently of the socket. It has neither On/Off
nor EEM. Existing endpoint numbers and the profile without this flag remain
unchanged. See [acceptance and UI limits](doc/oss/power-only-validation.md).

Use `--power-sensor-only` for a minimal node: required Root services on endpoint
0 and one Electrical Sensor on endpoint 1, with Descriptor/EPM/Power Topology
and synthetic 123 W. There is no On/Off or EEM anywhere. This mode excludes
the other measurement/switch/test-trigger profiles and uses a separate mDNS
host label so it can coexist with other simulated nodes on the same interface.
See [minimal sensor acceptance](doc/oss/sensor-only-validation.md).

`--power-sensor-only --sensor-energy` also exposes EEM on endpoint 1:
separate cumulative import/export registers and the cumulative measurement
event. Initial simulated registers are 12.345 kWh imported and 2.345 kWh
exported. The constant +123 W increases import; export is historical and
unchanged. With `--state`, accepted register checkpoints survive restart through
the existing store. Display and unit selection remain the controller's choice.
See [energy-register acceptance](doc/oss/sensor-energy-validation.md).

The optional [OTA host laboratory](doc/ota-host.md) uses an unmodified CHIP
provider to exercise QueryImage, Busy timing, BDX, a signed simulation image,
restart and NotifyUpdateApplied. Its memory-tool modes cover both boots.
The fixture does not install executable firmware or certify a bootloader.
The [CSA20 report](doc/oss/csa20-validation.md) records QueryImageResponse
manual acceptance and the timing fix that keeps repeated announcements from
bypassing the OTA query floor during asynchronous CASE setup.
The [CSA21 report](doc/oss/csa21-validation.md) records manual TC-SU-2.3
acceptance: interruption, five real minutes, Idle readback and retry from zero.
An outbound MRP timeout now retires the stale peer session, allowing CASE after
the provider restarts.

The [CSA22 report](doc/oss/csa22-validation.md) records manual TC-SU-2.4
acceptance: peer-trace UpdateToken/NewVersion binding for image versions 2 and 3,
and rejection of a signed image with the wrong version. Read/Subscribe RX/TX
buffers now use per-handler allocations and transport-derived UDP budgets.

The [CSA23 report](doc/oss/csa23-validation.md) records manual TC-SU-2.5
acceptance of Proceed, AwaitNextAction and Discontinue, using real 120/180-second
intervals and decoded peer responses. Discontinue now disposes of the downloaded
host candidate through an optional application callback; accepted simulation
images remain available for inspection. Memcheck and separate sanitizer runs
cover retry/restart and disposal. Rebuild consumers for the appended runtime OTA
port field. This is simulated host OTA, not firmware installation or certification.

The [CSA24 report](doc/oss/csa24-validation.md) records automatic Python
TC_SU_2_5 run449: both delay/provider-loss scenarios pass; Discontinue fails
before its OTA assertions on a fourth live subscription. The host supports the
Core minimum of three per fabric; the test retains earlier state handlers.
This remains an official FAIL pending resource-capacity clarification. Query
error states and actual download progress are corrected, with native tests,
Memcheck and separate sanitizer acceptance. Rebuild OTA port consumers for the
new optional progress callback. The separate manual CSA23 result is retained.

The [CSA24a follow-up](doc/oss/csa24a-validation.md) adds a per-instance budget
and dynamically sized transaction table, validated with eight subscriptions per
fabric. Automatic run450 accepts the fourth subscription but remains FAIL on
premature progress-history matching in the unmodified test. A minimal replay of
the original helper/predicate reproduces that behavior; no CSA-approved test fix
or automatic PASS is claimed. Defaults and existing paired Windows nodes remain.

The [CSA24b correction](doc/oss/csa24b-validation.md) is an explicit local SDK
test patch with 11 passing source regressions and preserved original assertions.
It consumes progress reports chronologically and cleans up scenario subscriptions.
Full corrected run451 passes with budget three/transport 56, including both delay
scenarios and Discontinue/image disposal. The original SDK source is restored
exactly and the isolated node is stopped. This is LOCAL-PATCH PASS; no new
unmodified official CSA PASS is claimed. Notify acceptance is recorded below.

The [CSA25 acceptance](doc/oss/csa25-validation.md) records manual TC-SU-2.6 PASS
in TH run452. Two independent updates to versions 2/3 verify actual Notify token
and version against Query/Apply and fresh CASE Basic Information/BootReason.
Full Memcheck and separate sanitizers are clean; no C/H, PICS or SDK test changes
were required. Only this manual row changes, giving 97 PASS, 15 FAIL, 8 BLOCKED,
38 MANUAL and 704 NA. Other rows are inherited; this is not automatic CSA
assertions or certification. OTA event acceptance is recorded below.

The [CSA30 General Diagnostics work](doc/oss/csa30-validation.md) corrects host
OS uptime leaking into Node time and connects actual selected-NIC diagnostics
through an optional application callback. Independent chip-tool acceptance
passes 59 checks with clean Memcheck and separate sanitizers; focused Linux,
Windows and installed-package checks pass. Original semi-automated TC-DGGEN-2.1
ended as **ERROR in TH run463**: after its original 2h05 wait, the next read
encountered a TH/chip-tool WebSocket keepalive timeout. No second hours value
was obtained; later steps were not executed. **No official PASS; cumulative
CSA counts are unchanged.** See the [result record](doc/oss/csa30-results.json)
and [callback contract](doc/runtime.md).
The unchanged case's retry **run464 also ends ERROR**, after passing the full
2h05 wait and verifying TotalOperationalHours **0 to 2**. A controller WebSocket
keepalive timeout interrupts commissioning after the following factory reset;
the later 1h05 segment is unexecuted. Final evidence and cleanup are complete.
CSA30 is unsuccessful; further investigation is deferred by the owner, with
no further long retry in this pass. The next campaign is CSA31 onboarding
QR/manual pairing payload tests.

[CSA31 onboarding acceptance](doc/oss/csa31-validation.md) completes original
TC-DD-1.1/1.2 in TH run465: 9 and 3 passed steps, respectively, with the 21-digit
manual branch not applicable. Operator inputs come from a scanned C QR bitmap,
live mDNS and a CHIP-generated development manual card. Independent acceptance
passes 24 checks, and the existing C payload self-test passes Memcheck. No runtime
changes, physical-label/GUI acceptance, DCL verification or certification are
claimed. Last-fabric removal/discovery follows below; CSA30 remains deferred.

[CSA32 last-fabric acceptance](doc/oss/csa32-validation.md) verifies successful
removal, mDNS withdrawal and same-store restart/recommissioning. Independent
acceptance passes 27 Memcheck and 25 separate sanitizer checks, with clean memory
diagnostics. Original manual TC-OPCREDS-3.6 run466 is **FAIL at Step4**: its
verification expects CM=0/no-_CM, while an explicitly restarted uncommissioned
node opens a CM=1 basic window with _CM. The contradictory CM=2 heading is retained
for CSA clarification; no runtime/test workaround was introduced. The follow-up
commissioning/unpair/recommission result is below; paired Windows devices are untouched.

[CSA33 lifecycle acceptance](doc/oss/csa33-validation.md) completes original manual
TC-DD-3.19 in TH run467: preconditions, five protocol steps and evidence upload
pass. Both pairings use the same live controller, unchanged credentials and the
same scanned C-generated QR. Removal withdraws the operational identity; explicit
same-store restart opens CM=1, and recommissioning restores CASE/operational
discovery and CM=0. Independent acceptance passes 37 Memcheck and 35 separate
sanitizer checks, with zero memory errors/leaks. No runtime changes were needed.
The manual category now has 11 PASS, 1 FAIL and 28 without an outcome. CSA32's
separate discrepancy and deferred CSA30 remain open. Announcement verification
follows below. See the [result record](doc/oss/csa33-results.json).

[CSA34 announcement verification](doc/oss/csa34-validation.md) records original
manual TC-DD-2.1 FAIL in TH run468: 8 PASS, 17 NOT APPLICABLE and 1 FAIL. Actual
CM=0 Extended Discovery omits mandatory PH (Core1.6.1 4.3.1.11). Basic/closed/
enhanced discovery, records/subtypes/IPv6 addresses, instance rotation and
unmodified chip-tool browsing work; 37 Memcheck and 36 separate sanitizer
functional checks pass with clean memory, while overall conformance remains
FAIL. Original test/PICS and runtime C/H are unchanged. Next: CSA35, PH and
customer Extended Discovery policy, truthful PICS and affected discovery rechecks.
The manual category now has 11 PASS, 2 FAIL and 27 without an outcome. See the
[result record](doc/oss/csa34-results.json).

[CSA35 PH and discovery policy](doc/oss/csa35-validation.md) fixes that failure.
Automatic TC_SC_4_1/4_3 pass in runs469/470; manual TC-DD-2.1 passes in run471,
including its newly declared PH/Extended Discovery branches. Three policy modes
pass full Memcheck and separate sanitizer scenarios; restored disabled boots
accept fresh CASE. Four accepted Memcheck processes have zero errors/live bytes.
The manual category now has 12 PASS, 1 FAIL and 27 without an outcome; category
totals remain unchanged. Its Commissioner Discovery declaration is audited below.

[CSA36 Commissioner Discovery / UDC audit](doc/oss/csa36-validation.md) corrects
the unsupported optional `MCORE.DD.COMM_DISCOVERY` declaration to false.
The original TH applicability endpoint excludes only TC-SC-4.7; ordinary
commissionable/operational discovery remains supported. No protocol test PASS
is claimed. Five endpoint CLI exports preserve all other PICS/project values.
Current totals: **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**; MANUAL contains
12 PASS, 1 FAIL and 26 without an outcome. No native code or paired-node changes.
The original PASE procedure is reviewed below.

[CSA37 PASE exchange review](doc/oss/csa37-validation.md) records original manual
TC-SC-2.1 **FAIL**, run472: five steps conflict with Core1.6.1 addressing/boolean/
byte-size rules; final success verification and upload pass. Two full scenarios
pass 40 independent checks across Memcheck and separate sanitizers, including four
complete PASE exchanges and two fabrics per scenario. Memcheck has 43510 matched
allocations/frees and zero errors/live bytes. No native/test-source/PICS change.
Category totals are unchanged; MANUAL now contains 12 PASS, 2 FAIL and 25 without
an outcome, plus 3 BLOCKED positions outside MANUAL. The original FAIL is retained.
The bidirectional/error procedure is reviewed below.

[CSA38 PASE decryption-error review](doc/oss/csa38-validation.md) records original
manual TC-SC-2.2 **FAIL**, run473: four communication steps/upload pass; its
session-termination/key-clear expectation after bad MIC is not met. Core4.8.3
message rejection and subsequent same-session recovery pass 50 independent checks
across Memcheck/separate sanitizers. Memcheck has 43536 matched allocations/frees,
zero errors/live bytes; two focused tests pass per build. No native/PICS change.
Totals are unchanged; MANUAL now has 12 PASS, 3 FAIL and 24 without an outcome.
The invalid-input procedure is reviewed below.

[CSA39 PASE error handling](doc/oss/csa39-validation.md) records original manual
TC-SC-2.3 **FAIL**, run474: both required error StatusReports are absent. The PASE
machine prepares them, but the dispatcher closes before sending; repair is
deferred. Late-message rejection and full new commissioning/CASE work without
restart, with 52 functional checks passing; four required-status assertions fail
across Memcheck/separate sanitizers, so overall FAIL is retained. Memcheck has
48294 matched allocations/frees and zero errors/live bytes. No native/PICS change.
MANUAL now has 12 PASS, 4 FAIL and 23 without an outcome; totals are unchanged.
The MRP size-boundary procedure follows below; failures remain deferred.

[CSA40 MRP size boundary](doc/oss/csa40-validation.md) records original manual
TC-SC-1.1 **PASS**, TH run475. Complete IPv6 packets1279/1280 bytes receive ACKs
and valid PBKDF replies;1281/1328/1329 receive none. Core4.4.4/4.15 includes the
IPv6/UDP headers in the1280-byte MTU, giving a1232-byte Matter ceiling without
IPv6 extensions. No native/PICS changes were needed. Full scenarios pass64
independent checks across Memcheck/separate sanitizers; memory is clean and five
focused tests build/pass per variant. MANUAL now has13 PASS,4 FAIL and22 without
an outcome; category totals are unchanged. The MRP flow review follows below.

[CSA41 MRP flows](doc/oss/csa41-validation.md) records original manual TC-SC-1.2
**FAIL**, TH run476. Piggyback and duplicate standalone ACKs pass. Five valid
encrypted R=0 reads receive no data reply, with R=1 controls working before/
after in the same session. Runtime admission applies a blanket R requirement;
repair is deferred. Both full scenarios retain FAIL despite clean Memcheck/
separate sanitizers and successful later commissioning/CASE. Five focused tests
build/pass per variant; no native/PICS change. MANUAL now has13 PASS,5 FAIL and21
without an outcome; category totals stay unchanged. The retry review follows below.

[CSA42 MRP retries](doc/oss/csa42-validation.md) records original TC-SC-1.3
**literal manual FAIL**, TH run477, for Step4's total MAX-1 wording. Core acceptance
passes: five total immutable transmissions/four retries, correct timed backoff,
terminal silence and no restart on late ACK. Both full scenarios pass64 checks
under Memcheck/separate sanitizers; memory is clean and two focused CTests pass
per variant. No native/PICS change; no native count defect is established. MANUAL
now has13 PASS,6 FAIL and20 without an outcome; category totals stay unchanged.
The counter/duplicate acceptance follows below; earlier failures stay deferred.

[CSA43 counters and duplicates](doc/oss/csa43-validation.md): original manual
TC-SC-1.4 PASS, TH run478. Exact repeat requests receive matching standalone ACKs
without repeating the original PBKDF data response. Both full scenarios pass64
checks with clean native memory instrumentation and successful subsequent CASE.
Three focused tests pass per variant. MANUAL now has14 PASS,6 FAIL,19 unexecuted.
Continue with CSA44 Descriptor and the generated campaign queue; no native fix
or certification claim is made by this acceptance.

The [CSA29 Identify acceptance](doc/oss/csa29-validation.md) records original
semi-automated TC-I-2.2 PASS in TH run460, all 15 step entries. Two operator
verifications use live x86 callbacks with IdentifyType0 (None); no physical
indicator is claimed. Independent chip-tool acceptance passes 34 checks with
clean Memcheck and separate ASan/UBSan/LSan, including countdown reporting and
fresh CASE after restart. The TH laboratory is responsive after Docker recovery.
No C/H or official test changes were needed. Current counts: **97 PASS, 18 FAIL,
3 BLOCKED, 40 MANUAL, 704 NA**. This is not fully automatic acceptance or
certification. See the [result record](doc/oss/csa29-results.json).

The [CSA28 QueryImageResponse acceptance](doc/oss/csa28-validation.md) records
original automatic TC_SU_2_2 FAIL in run457: its initial UpdateAvailable
announcement does not arrange a normal query opportunity for this daily policy.
The independent lab adds an explicit default-provider fixture while retaining
the same production schedule and 120/180-second limits. Seven scenarios pass
134 local checks with clean Memcheck/separate sanitizers. Original test/PICS/C/H
sources remain unchanged. CSA28 counts: **97 PASS, 18 FAIL, 4 BLOCKED,
39 MANUAL, 704 NA**; local acceptance is separate from official results and certification.

The [CSA27 attribute acceptance](doc/oss/csa27-validation.md) records original
TC_SU_4_1 FAIL at step5: the test examines the first Success instead of the later
ConstraintError in a list write. Two-fabric chip-tool acceptance passes 29
Memcheck and 27 sanitizer checks, including partial writes, fabric isolation and
restart persistence. No C/H, PICS or official test changes were required.
CSA27 counts: **97 PASS, 17 FAIL, 5 BLOCKED, 39 MANUAL, 704 NA**. This is not
certification; retain the response-status observation for CSA review.

The [CSA26 event acceptance](doc/oss/csa26-validation.md) fixes spurious Idle
handoffs and null progress on known-length download errors. Manual TC-SU-2.7
passes in run455; unchanged automatic TC_SU_2_7 fails in run454 because it misses
an initial query transition during setup. Seven independent scenarios pass 156
checks, including actual BDX idle timing/recovery, with clean Memcheck/separate
sanitizers and 15 focused tests per build. Counts become 97 PASS, 16 FAIL,
6 BLOCKED, 39 MANUAL and 704 NA; other rows are inherited. No certification or
automatic PASS is claimed. Attribute acceptance is recorded in CSA27 above.

The CMake executable is `build/cmake/matter-node` (with `.exe` on Windows).
Legacy builders keep `build/matter-host/linux-gcc/matter-node` or
`build/matter-host/gcc/matter-node.exe`. An unknown option prints usage and exits 2.
The application owns its event loop; network interface, credential directory and
persistent state are explicit parameters. Keep generated credentials/state in
ignored `build/`, and never use public fixture keys as device credentials.

For the credential-backed runtime host, Extended Discovery (CM=0) defaults to
900 seconds per closed-mode entry/boot. Add `--extended-discovery-seconds 0` to
disable it, a numeric seconds value to bound it, or `unlimited` to opt into
indefinite advertising. This setting withdraws only commissionable DNS-SD;
operational discovery, CASE and authenticated new commissioning windows stay
available. It is a process option, not a stored GUI preference. Host PH is 1
before commissioning and 4 for a commissioned administrator. See
[policy, API and acceptance limits](doc/oss/csa35-validation.md).

The host defaults to VendorName `Matter C` and ProductName `Matter C host simulation`.
Override them at compilation, for example:

```sh
cmake -S . -B build/cmake -DMATTER_HOST_VENDOR_NAME="Example" -DMATTER_HOST_PRODUCT_NAME="Example energy meter"
```

The legacy builders accept `--vendor-name` / `--product-name` (Python) and
`-VendorName` / `-ProductName` (PowerShell). Both strings must contain 1..32 UTF-8
bytes; NUL, line breaks and semicolons are unsupported. Direct C compilation can
define `MATTER_HOST_VENDOR_NAME` and `MATTER_HOST_PRODUCT_NAME` as string literals.
VID/PID and credential matching are unchanged. For custom branding, give the same
expected strings to `chip_tool_acceptance.py --vendor-name ... --product-name ...`.
Library consumers continue to supply their identity through `Matter_Root_Config_T`.

Local lab paths may be kept in ignored `local/lab.json`; this file is a private
notebook, not automatically loaded by the host. Builds still take explicit paths.
Portable certificate tests use synthetic signed chains and public upstream
fixtures with retained notices. See [fixture provenance](tools/matter/fixtures/fixture-provenance.md).

The optional Matter.js test controller uses the committed package lock:

```sh
npm ci --prefix tools/matter/controller --ignore-scripts
mkdir -p build
node tools/matter/tests/host_controller.mjs tools/matter/controller/node_modules credentials build/credentials
build/cmake/matter-node --interface 2 --seconds 60 --port 5541 --credentials build/credentials --state build/state.bin --pin 20202021 --discriminator 3846 --case-resumption-profile chip --certificate-validity strict
```

Choose your isolated test interface. `--case-resumption-profile chip` is the
explicit interoperability profile; certificate validity remains strict above.
For an already connected simulated Wi-Fi device, add `--wifi-sim-connected`
and use a fresh state path. It seeds the existing `testharness` AP as configured
and connected; `testharness-2` remains available to scans. The default still has
an empty Networks list. A restored file always takes precedence, including an
empty list: this option never replaces saved settings. It requires `--credentials`.
The radio is simulated; IPv6 transport uses the selected real host interface.
It neither configures nor connects the OS Wi-Fi adapter. ScanNetworks requires
an armed fail-safe as specified by Core 1.6.1 section 11.9.7.1.
To execute the Matter.js network scenario, pass `--modules tools/matter/controller/node_modules`
to `tools/matter/tests/test_host_network.py` together with `--exe`, `--interface`
and `--ipv6`. Windows DLL search can be set with `--runtime`; Node with `--node`.
Other network runners retain these explicit overrides.

`build_host_linux.py --sanitize` builds ASan/UBSan (LSan enabled at runtime).
Run Memcheck separately on the ordinary build with `--leak-check=full
--show-leak-kinds=all --track-origins=yes --error-exitcode=99`.
The Linux `--test` runner also requires `MATTER_IPV6_INJECTOR` pointing to the
fixed-case helper with CAP_NET_RAW; it never grants that capability itself.
SDK/CSA test scripts in `tools/matter/tests` require an externally provisioned
CHIP/TH environment; neither SDK nor TH is redistributed here.

Fixture generators are optional, not build prerequisites. OpenSSL/GCC default
to PATH and support `OPENSSL`/`GCC`. `extract_operational.py` takes explicit
`--rs-matter` and `--matter-js` checkouts; use revisions in tools/matter/fixtures/operational-sources.md.
Committed fixtures remain available without any upstream checkout or CSA PDF.

See [current status and validation](doc/oss/status.md) for the next task.
