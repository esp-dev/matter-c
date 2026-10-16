# Matter C

Standalone C99 Matter library and host development environment, licensed under
[Apache-2.0](LICENSE). Third-party terms are retained in [NOTICE](NOTICE) and
[provenance](doc/oss/provenance.md). This is experimental software, not a CSA
certified implementation. See [status and known failures](doc/oss/status.md).

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
the default is 56. `-DMATTER_SANITIZE=ON` enables
ASan/UBSan and Linux leak detection in CTest. Do not run that build under Valgrind.

[Test map](doc/oss/test-map.md) records every retained test and optional route.
The default CTest suite excludes external controller, privileged IPv6 and fuzz
campaigns. The original `build_host.ps1`, `build_host_linux.py`, `run_tests.ps1`
and other runners remain usable; their production lists share `cmake/sources.json`.
They retain their previous command line and output locations.

## Host and tests

The Windows [native C desktop](doc/desktop.md) builds as `matter-desktop.exe`:
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

The CMake executable is `build/cmake/matter-node` (with `.exe` on Windows).
Legacy builders keep `build/matter-host/linux-gcc/matter-node` or
`build/matter-host/gcc/matter-node.exe`. An unknown option prints usage and exits 2.
The application owns its event loop; network interface, credential directory and
persistent state are explicit parameters. Keep generated credentials/state in
ignored `build/`, and never use public fixture keys as device credentials.

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
