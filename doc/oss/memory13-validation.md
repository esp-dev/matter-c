# Memory13 — initial ESP-IDF integration and physical memory laboratory

The C library now has an optional ESP-IDF component and a C6 laboratory
application. The application owns PSA startup, entropy, time, task scheduling,
radio and cleanup. Host public APIs, wire/storage formats and existing resource
limits remain unchanged. The default lab has 128 events and 56 transport slots.
This stage implements a measured component/crypto/IM foundation, not a complete
commissioned target runtime.

## ESP-Matter reference build

Prepared a separate official ESP-IDF **v6.0.2** checkout on the Linux VM, commit
`7101770dc6db2667b3c477cc31365dd1acd6db4e`, with its own tools/Python environment.
The existing SDKs and tools belonging to the other user were not modified.
ESP-Matter `release/v1.6.1` at
`4c9dd7aa80b3ddfa64c814bdfabe76c60944cc75`, ConnectedHomeIP
`b1902b39ac6734913ce5f4d2abf153693a50264b`, bootstraps with `--no-host-tool` and
successfully builds the standard `examples/light` for `esp32c6`.

The BIN is **1864928 B**, SHA256
`e6806d66760bdcc64270011dde62beeae9df71f91a404b9de4e0c9fb338fefbf`.
ELF/map, bootloader, partition/OTA data and flash arguments were saved locally.
This reference was compiled, not flashed or commissioned. The light model,
BLE/OTA/services and configuration differ from the C laboratory, so image/static
RAM differences are not a stack-efficiency comparison. The selected branch
[recommends IDF 6.0.2](https://github.com/espressif/esp-matter/tree/release/v1.6.1).

## C integration and ownership

`components/matter_c` reads the same `cmake/sources.json` core/runtime lists as
the host build. It does not create tasks or replace application ports. The
example uses the separate native Windows IDF **v6.1** at
`fff9895c82d744c7237be8847347bdd1b07c6643`, GCC15.2.0 and Mbed TLS 4.1.0.

The existing backend retains its 3.6 host path. The 4.x adaptation shares the
same validation, arithmetic/SPAKE, output clearing and cleanup code, using PSA
for HKDF, CSR key wrapping/signing and operational key-ID hashing where the old
API is unavailable. Each instance still owns its AES-256 CTR-DRBG. PSA startup
and lifetime remain application-owned. CSR signing uses the application's PSA
RNG after checking the instance RNG health/reseed gate. Temporary PSA keys and
operations are released on all exits.

Two target-specific issues were exposed by the unchanged reference tests:

- Hardware ECC did not reproduce an existing P-256 generator vector in the
  tested C6 configuration. The SDK alternative multiplication path also does
  not preserve the backend's software blinding/entropy callback behavior.
  The component currently requires software ECC and rejects an incompatible
  hardware-ECC configuration. This is not a general chip-defect diagnosis.
- The SHA-1 driver faulted on an unaligned public-key span in flash. Operational
  key-ID hashing now reuses the already allocated, aligned DER workspace before
  DER construction. No additional allocation or large task-stack buffer is used;
  exact DER/signature and future-extension tests remain active.

Compiler `.su` review then found that the by-value PSA HKDF initializer introduced
a **592 B** frame despite the heap-owned operation. Copying the official immutable
initializer directly into that operation reduces this frame to **48 B**. The
template is read-only; it is not shared mutable workspace. The same independent
crypto vectors and allocation-failure checks are rerun after this correction.

The compatibility boundary uses private builtin arithmetic and X.509 OID headers
from the pinned SDK. Upgrade compatibility needs another source/target review.

## Physical test and scope of measurements

The attached board is **ESP32-C6FH4 rev. 0.0, 4 MB flash**, with Secure Boot and flash
encryption disabled. A complete original flash backup was kept locally before
programming; it and the AP credential header are ignored and never exported.
No eFuse or router configuration was changed. Development BINs are flashed and
verified through the native Windows esptool/UART tools.

There are separate builds:

- **Self-tests:** eight existing test translation units on the MCU: crypto,
  SPAKE2+, credentials, operational certificates, attestation, Read, Subscribe
  and private event metadata. Two host clock functions get a small ESP timer
  adapter; the test vectors/negative cases are unchanged. Inherited `x86` timing
  labels describe the original fixture text, not this execution platform.
- **Profiling:** those suites/fixtures are excluded with
  `CONFIG_MATTER_C_LAB_SELF_TESTS=n`, preserving the same library limits/backend.
  It runs backend/HKDF/CSR allocation faults, a 128-record event log, real local
  two-party PASE with final confirmation/key transfer and PASE construction/RX
  faults, then WPA2 association/DHCP and event log/OOM/drain with Wi-Fi active.

The volatile event-number port is explicitly a lab fixture. Two PASE engines
exchange copied plaintext messages locally; the final gate models delivery after
receiver acceptance. It is not a UDP/MRP or controller-interoperability test.
Trusted CASE constructors used by IM tests are not a physical CASE handshake.

The application temporarily runs synchronous crypto tests/PASE at idle priority
so RTOS idle/watchdog work can progress, then restores its priority for Wi-Fi.
The maximum 100000-iteration PBKDF2 vector takes about 57 seconds in this setup;
1000 iterations take about 0.58 seconds. These are wall times under this lab
scheduling policy, not production deadline guarantees or a changed limit.

## Results and interpretation

Exact final samples, task names, compiler frames, image hashes and verified source
hashes are in [memory13-results.json](memory13-results.json). Both firmware modes
finished with `LAB_PASS`, seven injected library allocation failures, zero
library live allocations/bytes and a successful SDK heap integrity check.

Final profiling build, bytes:

| Phase/measurement | System allocated internal heap | Tracked library blocks |
| --- | ---: | ---: |
| Boot | 24312 | 0 |
| Crypto backend ready | 24848 | 340 |
| Empty event log, backend retained | 25656 | 1148 |
| Full 128-record log, backend retained | 57400 | 32892 |
| Largest sampled local PASE phase, two peers | 29676 | 4440 |
| Wi-Fi associated with DHCP | 77576 | 340 |
| Wi-Fi plus full event log | 110128 | 32892 |
| Log drained while Wi-Fi remains active | 77576 | 340 |
| Complete library/radio teardown | 30704 | 0 |

The event log itself grows from 808 B empty to 32552 B full; its 128 record blocks
are 248 B each for this five-byte payload. The library's largest individual
request is 1576 B. PASE rows are samples between synchronous operations, not the
maximum of their internal crypto temporaries. The cumulative SDK free-heap
minimum is 282256 B; the largest free block with the full log and Wi-Fi is 262144 B.
The owner uses an observed 1184 B from its 12288 B stack reservation. The separate
self-test build observes 2584 B owner stack use and 67704 B tracked library peak;
its fixtures make those results unsuitable as steady-node requirements.
The profiling BIN is 975344 B and the self-test BIN 1267680 B, including the
different linked tests, SDK and radio services. Firmware hashes are in the JSON.

The library profiler observes only its own libc calls, serialized by the owner.
Its bytes are rounded allocator block capacities; SDK/Mbed TLS internals and
application fixtures are excluded from this counter. System samples include
those resources in the **internal 8-bit heap**. Heap low-water marks aggregate
per-region minima and can occur at different instants. They are not a normative,
exhaustive or necessarily coincident peak of the entire node.

RTOS stacks are already heap allocations. Do not add reserved stack sizes again
to the system heap measurement. Only the owner's 12 KiB reservation is given;
per-task free-stack minima are copied safely while scheduling is suspended and
printed afterward, during active Wi-Fi and after teardown. The hardware
high-water observation includes the exercised call chains, whereas `.su` files
describe individual compiled functions, including some not linked/executed here.
See [Espressif's heap/stack measurement guidance](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-guides/performance/ram-usage.html).

Wi-Fi event-log drain restores the corresponding baseline; after complete
library teardown its tracked live count is zero. Platform resources such as
the tcpip task and PSA services remain application-owned. A post-radio heap
difference alone is not classified as a library leak or a fragmentation proof.

## Regression evidence

- Windows full CTest **98/98**, with the toolchain DLL directory on child PATH;
  final rebuilt crypto/certificate/SPAKE focused tests **5/5**.
- Linux full CTest **95/95** in normal and separately ASan/UBSan/LSan builds.
- Two-instance metered/source/three-phase acceptance **6/6** under Memcheck and
  **6/6** separately with sanitizers. Both node exits0, empty stderr; Memcheck
  has zero live bytes/blocks, zero errors and zero suppressions.
- Physical C6 self-tests and separate profile cover the target 4.x branch.
  Seven injected library failures include backend construction, HKDF operation,
  CSR workspace, PASE construction, retryable PASE RX and two event append cases.
  Internal PSA/SDK allocator faults are not exhaustively injected.
- Inventory passes 256 mapped files, 97 native definitions, 59 core sources and 75
  public headers. Exported host core source/header hashes are checked against the
  checkout. SDK sources, licenses, host CMake defaults and CSA evidence are preserved.

Initial SDK Kconfig deprecation notices remain visible. A missing MinGW DLL PATH
was corrected in the child environment before the successful host build.
No warning-free system/toolchain claim is made.

Representative commands (paths/credentials belong in ignored local configuration):

```text
git clone --branch v6.0.2 --depth 1 --recurse-submodules --shallow-submodules <official-idf> <new-vm-sdk>
idf_tools.py install --targets esp32c6
idf_tools.py install-python-env --features core
./install.sh --no-host-tool
idf.py -C examples/light -B <reference-build> -D IDF_TARGET=esp32c6 build
idf.py -C examples/esp32-memory -B <target-build> -D SDKCONFIG=<config> -D IDF_TARGET=esp32c6 build
esptool --port <C6-port> flash-id
esptool --port <C6-port> get-security-info
esptool --port <C6-port> read-flash 0 0x400000 <private-backup>
esptool --chip esp32c6 --port <C6-port> write-flash @flash_args
ctest --test-dir <host-build> --output-on-failure
python tools/matter/check_test_map.py
```

## Changed files and next task

- `components/matter_c/`: optional IDF source-manifest integration, unchanged
  budget defaults and opt-in owner-serialized allocation accounting/fault injection.
- `examples/esp32-memory/`: application-owned hardware/PSA/Wi-Fi composition,
  two variants, reused reference tests, heap/task telemetry and lifecycle/OOM probes.
- `main/apps/matter/crypto/`: shared private version boundary plus minimal4.x
  API adaptations, aligned key-ID input and removal of the HKDF stack temporary.
- `cmake/sources.json`: register the new private header for the existing source
  inventory. `README.md`, status and this report: entry points and evidence limits.

Next: compose the actual target runtime with application-owned UDP/IPv6/discovery
and atomic persistent storage, then commission and measure CASE/resumption,
fail-safe publication and live subscriptions. The current lab AP proves Wi-Fi
association/DHCP, not IPv6/controller reachability. Long-running fragmentation,
full target concurrency, radio throughput/loss, a matching ESP-Matter workload,
official CSA acceptance and a specification-wide RAM bound remain unverified.
