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

The [development roadmap](doc/roadmap.md) orders CSA acceptance, Google Test Suite
and manual checks, measured optimization, then downstream firmware integration.
The opt-in [meter services](doc/meter-services.md) add Identify, Meter Identification
and a per-instance Time Synchronization server (`--three-phase --meter-services`).

The optional [three-phase profile](doc/three-phase.md) adds tagged aggregate/L1/L2/L3
endpoints and EEM source-register semantics: run the host with `--three-phase`
and a separate state file. The default host profile is preserved.
Add `--source-registers` for the [manufacturer-specific source view](doc/meter-source.md):
tariff/quadrant/demand registers, directional values, metadata and volume channels.

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
