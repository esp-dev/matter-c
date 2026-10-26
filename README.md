# Matter C

A standalone **C99 Matter stack** for embedded devices and native Linux/Windows
applications. The application owns the event loop, networking, storage and radio;
the portable core does not require ESP-IDF or FreeRTOS.

The project targets **Matter 1.6.1** and is licensed under [Apache-2.0](LICENSE).
It is experimental and **not CSA certified**. Supported functionality and local
interoperability results do not establish complete device conformance; see
[current status and known failures](doc/oss/status.md).

## Features

| Area | Implemented functionality |
| --- | --- |
| Commissioning and security | PASE/SPAKE2+, operational CASE with resumption, operational certificates, multi-fabric administration, ACLs, group keys and fail-safe recovery. Explicit trusted-UTC or Last Known Good certificate-time policy. |
| Interaction Model | Read, Write, Invoke, Subscribe, events, wildcard paths, version filters and multipart reports with stable snapshots. |
| Networking | IPv6 UDP, MRP acknowledgements/retransmission, commissionable and operational DNS-SD/mDNS discovery. Optional BLE/BTP commissioning through the ESP NimBLE port. |
| Device models | Root services and diagnostics; shared RGB lighting with OnOff, Level Control, HS/XY/CT Color Control, Groups, Scenes and optional Groupcast Listener/PerGroup. Electrical power/energy, meter identity and time synchronization models are also available. |
| Updates | OTA Requestor and BDX transfer, plus an optional ESP installer for signed inactive-partition writes, confirmation/rollback and NotifyUpdateApplied. |
| Platforms and tools | Portable CMake libraries, Linux/Windows CLI hosts, a native Windows desktop simulator, ESP-IDF components and controller/fault-injection test tools. |

Features are composed through application-selected models and ports. The
[RGB profile contract](doc/oss/bulb-integration.md),
[runtime contract](doc/runtime.md) and [test map](doc/oss/test-map.md) describe
limits, optional roles and their actual coverage.

## Ownership and memory

- **Application-owned lifecycle.** Create, process, stop/drain and delete each
  instance explicitly. Multiple instances can share one application thread; the
  core creates no background task or socket.
- **Demand-owned memory.** Transactions, packet storage, report blocks, snapshots
  and handshake/encoding workspaces allocate as needed within configured bounds.
  Allocation failure is handled before publication where the operation requires
  atomic changes; retained snapshots and ciphertext keep their delivery lifetime.
- **Explicit resource budgets.** Limits are checked and advertised consistently.
  Asynchronous send completion, IM confirmation and MRP ACK/drain have distinct
  ownership gates; stopping does not invalidate data still borrowed by a port.
- **Platform control stays with the product.** Wi-Fi initialization/reconnect,
  external provisioning, persistent storage, time provenance and hardware output
  belong to the application. Matter can be retired while other application
  services and Wi-Fi continue running, as demonstrated by the ESP examples.

There is no universal RAM figure for the stack. Application models, resource
limits, SDK configuration and overlapping operations determine peak use. The
[same-IDF C6 comparison](doc/oss/memory43-validation.md) measures complete firmware
headroom, largest free blocks and stack observations against ESP-Matter, with
workload and coverage limits. It includes Wi-Fi/SDK/task allocations; it is not
an isolated-core memory claim or a guarantee for another product.

## Build

The native package requires CMake 3.20+, Git, a C99 GCC/Clang toolchain and
Python 3.9+. Windows uses MinGW-w64 and native Python. Dependencies are fetched
explicitly by the bootstrap, never implicitly by CMake.

```sh
git clone https://github.com/esp-dev/matter-c.git
cd matter-c
python tools/matter/bootstrap_mbedtls.py
cmake -S . -B build/cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build/cmake -j 3
ctest --test-dir build/cmake --output-on-failure
```

On Windows, put MinGW-w64 on PATH and configure with a matching generator:

```powershell
python tools/matter/bootstrap_mbedtls.py
cmake -S . -B build/cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Debug
cmake --build build/cmake -j 3
ctest --test-dir build/cmake --output-on-failure
```

The native package pins official Mbed TLS 3.6.0 in
[cmake/dependencies.json](cmake/dependencies.json). ESP builds use their SDK's
crypto backend. See [build and configuration](doc/build.md) for offline dependency
paths, capacity options, library-only builds and separate sanitizer builds.

## Install and consume

```sh
cmake --install build/cmake --prefix /path/to/matter-prefix
cmake -S examples/consumer -B build/consumer -DCMAKE_PREFIX_PATH=/path/to/matter-prefix
cmake --build build/consumer
ctest --test-dir build/consumer --output-on-failure
```

```cmake
find_package(MatterC CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE MatterC::Matter)
```

`MatterC::Matter` exposes the portable modules. `MatterC::Runtime` adds complete
commissioning/fabric/ACL/diagnostics composition through
`<runtime/matter_runtime.h>`. Supply crypto/credentials, atomic storage, Wi-Fi,
time and regulatory callbacks, attach application endpoints, then drive the
runtime from the application's scheduler. The exported target carries its
capacity definitions and required dependencies. The development package version
is 0.0.0; API/ABI stability is not promised.

## ESP32 and example applications

| Entry point | Purpose |
| --- | --- |
| [ESP-IDF core component](components/matter_c/CMakeLists.txt) and [platform ports](components/matter_c_esp32) | Embed the C runtime with application-owned SDK services. |
| [ESP32-C6 runtime example](examples/esp32-runtime/README.md) | UDP/IPv6, discovery, Wi-Fi, atomic NVS and lifecycle integration on ESP-IDF 6.1. |
| [BLE/BTP port](doc/oss/ble-transport.md) | Optional NimBLE commissioning with retained TX ownership; disabled by default. |
| [Native ESP OTA installer](components/matter_c_esp32/OTA.md) | Signed firmware installation, real reboot/rollback and provider notification. |
| [RGB bulb application](https://github.com/esp-dev/matter-c-bulb) | Separate ESP32-C6/WS2812 product firmware using this repository as a submodule, with BLE commissioning, Wi-Fi, signed OTA and authenticated REST provisioning. |
| [ESP memory fixtures](examples/esp32-memory/README.md) and [reference comparison](examples/esp-matter-memory/README.md) | Reproducible profiling and matched ESP-Matter workloads. |

The shared lighting helper currently composes one light endpoint. Example/test
images use development identities; provision real credentials and review the
application's partition, clock and storage policy before deployment. The product
repository records its own physical and app interoperability acceptance.

## Host and tests

CMake builds `matter-node` on Linux/Windows and `matter-desktop.exe` on Windows.
The hosts provide optional measurement/switch simulations and explicit
interface, credential and state selection. See [host usage](doc/host.md),
[native desktop](doc/desktop.md), [three-phase measurements](doc/three-phase.md),
[meter services](doc/meter-services.md) and [source registers](doc/meter-source.md).
The simulated Wi-Fi model does not configure the computer's Wi-Fi adapter.

Validation has several distinct layers:

- Native CTest, including allocation-failure and installed-package checks.
- Full two-instance/controller scenarios under Memcheck and, separately,
  ASan/UBSan/LSan. [Wire regressions](doc/runtime-wire-tests.md) add controlled
  ACK/RX/TX faults and OOM cases without a physical board.
- Physical ESP32-C6 tests and scoped cross-stack memory comparisons.
- Original CSA procedures, local compatibility/patch results and manual
  ecosystem checks, each recorded separately in its own report.

External controller and CSA/TH environments are not bundled. Optional
[CSA compatibility switches](doc/oss/csa75-compatibility.md) are OFF by default;
compatibility outcomes do not replace strict results. Keep private keys, live
state and laboratory configuration in ignored `local/` or `build/`; public test
keys are unsuitable for real devices.

## Documentation and validation history

| Document | Contents |
| --- | --- |
| [Runtime contract](doc/runtime.md) | Ports, lifecycle, ownership, atomicity and resource bounds. |
| [Build guide](doc/build.md) | Dependencies, installation, exported targets and capacity options. |
| [Host guide](doc/host.md) | CLI flags, simulated models, credentials, discovery and optional controllers. |
| [Development status](doc/oss/status.md) | Dated changes, known failures and validation limits. |
| [Validation index](doc/oss/validation-index.md) | CSA and memory reports, retained as historical evidence. |
| [Test map](doc/oss/test-map.md) | Retained tests, fixtures and optional execution routes. |
| [CSA campaign](doc/oss/csa-campaign-plan.md) and [progress](doc/oss/csa-campaign-status.md) | Applicable procedures, results, blockers and next work. |
| [Roadmap](doc/roadmap.md) | Development and acceptance priorities. |

Detailed run counts and per-iteration memory measurements live in those reports.
A historical PASS is scoped to its recorded revision/profile and does not imply
certification or a new run on the current branch.

## License and provenance

First-party code is licensed under [Apache-2.0](LICENSE). Third-party material
retains its original terms; see [NOTICE](NOTICE),
[source provenance](doc/oss/provenance.md) and
[fixture provenance](tools/matter/fixtures/fixture-provenance.md).
