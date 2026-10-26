# Build, install and configure

Run commands from the repository root unless another directory is stated.

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
[cmake/dependencies.json](../cmake/dependencies.json), shared by bootstrap, CMake
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
See [resource ownership and bounds](runtime.md#subscription-resource-budget).
`-DMATTER_SANITIZE=ON` enables
ASan/UBSan and Linux leak detection in CTest. Do not run that build under Valgrind.

[Test map](oss/test-map.md) records every retained test and optional route.
The default CTest suite excludes external controller, privileged IPv6 and fuzz
campaigns. The original `build_host.ps1`, `build_host_linux.py`, `run_tests.ps1`
and other runners remain usable; their production lists share `cmake/sources.json`.
They retain their previous command line and output locations.
