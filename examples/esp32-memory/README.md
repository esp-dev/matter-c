# ESP-IDF memory laboratory

Initial ESP32-C6 integration of the C library with ESP-IDF 6.1 / Mbed TLS 4.1.
The application owns the task, clocks, entropy source, PSA initialization, radio
and cleanup. No scheduler/task is created by the library. This is an embedded
component/crypto/IM laboratory, not a commissioned network Matter device.

The `components/matter_c` component consumes the same source manifest as the
host build, including runtime sources. It preserves the default 128-event and
56-transport-slot limits. Public C APIs, wire and storage formats are unchanged.
The example links the paths it exercises; building the static component is not
evidence that every runtime path has run on ESP32.

## Build

Activate native ESP-IDF 6.1, then run from the repository root (PowerShell):

```powershell
$repo = (Resolve-Path .).Path
idf.py -C "$repo/examples/esp32-memory" -B "$repo/build/idf61-memory" `
  -D SDKCONFIG="$repo/build/idf61-memory/sdkconfig" -D IDF_TARGET=esp32c6 build
```

The example needs 4 MB flash, the standard larger single-app partition, a 12 KiB
main task stack and the default lab allocation profiling. It does not configure
Secure Boot or flash encryption. Confirm the attached board/port and preserve
any existing firmware/state before a laboratory flash. Flash/monitor through
the selected IDF tools using the generated flash arguments and matching ELF.

`CONFIG_MATTER_C_LAB_SELF_TESTS=y` is the default. For a separate profiling
configuration set it to `n`: the same library and limit settings remain, while
the long host test suites and their fixtures are excluded. Keep distinct build
directories/config files and record which variant produced each measurement.

## Optional private Wi-Fi configuration

Keep a `matter_lab_wifi.h` in an ignored `local/` directory:

```c
#define MATTER_LAB_WIFI_SSID "your-lab-ssid"
#define MATTER_LAB_WIFI_PASSWORD "your-lab-password"
```

Pass its directory with `-D MATTER_C_LAB_CONFIG_DIR=<absolute-private-directory>`.
Do not pass the password as a command-line define or commit the header, firmware
or complete device backups. Without a header the application prints `WIFI_SKIP`.
It uses Wi-Fi credentials in RAM and does not reconfigure the AP. The current
scenario requires WPA2 and a successful DHCP lease, then stops/deinitializes the
radio and releases its event handlers, netif and NVS instance. A stopped radio
does not imply that lwIP's process-wide platform resources have been removed.

## What runs

- Eight existing host test translation units reused on the C6: crypto, SPAKE2+,
  credentials, operational certificates, attestation, Read, Subscribe and private
  event metadata. Only the two host timing APIs get an ESP timer adapter. Their
  inherited timing labels still say `x86`; the hardware under test is C6.
- Library allocation faults at backend construction, HKDF, CSR workspace,
  PASE construction/RX and event append, checking cleanup/retry where applicable.
  SDK/PSA internal allocator failures are not exhaustively injected.
- Real two-party PASE engines with crypto, matching keys, immutable sender copies,
  the final delivery gate and one-shot key transfer. Messages are exchanged
  locally: this is not a UDP/MRP, BLE or independent-controller acceptance test.
- Demand-allocated event log through empty/full/OOM/delete, repeated with Wi-Fi
  connected, followed by library zero-live checks and SDK heap integrity checks.

`MEMORY` JSON lines report current internal 8-bit heap allocations/free bytes,
largest free block, SDK low-water marks, the application's reserved stack and
observed minimum free stack, plus library allocation counters. The library
counter counts allocator block sizes, not requested payload bytes or all crypto
allocations. Application fixtures, SDK and Mbed TLS internals are excluded from
that counter but remain visible in the system heap samples.

The heap low-water field is cumulative and aggregates individual heap minima;
it is not a proof of a coincident, exhaustive whole-node maximum. Task stacks
are already allocated from the system heap: do not add reserved stacks to that
heap figure again. `TASK_MEMORY` reports per-task minimum free stack in bytes;
names are copied while the scheduler is suspended and printed afterward, both
while Wi-Fi is active and after teardown. Only the main task's configured
reservation is provided here. Formatting and
test fixtures affect the measurements. Compiler `.su` files are also generated.

Maximum PBKDF2 vectors intentionally run for a long time. The application lowers
its laboratory owner to idle priority during synchronous crypto tests/PASE so
the RTOS can service idle's watchdog; it restores its original priority before
radio work. This does not turn the crypto API into an asynchronous API or prove
that production scheduling deadlines are met.

## Mbed TLS 4 boundary

The app initializes PSA before using the backend and supplies true hardware
entropy while RF is off. That temporary entropy source is disabled before
starting Wi-Fi. Each backend keeps its own AES-256 CTR-DRBG. The 4.x CSR writer
uses PSA's signing RNG after an instance RNG health/reseed check. PSA initialization
and lifetime remain application-owned.

Software ECC is currently required (`CONFIG_MBEDTLS_HARDWARE_ECC=n`) to retain
the backend's point blinding and entropy-failure callback behavior. Hardware
ECC failed an existing generator vector on the tested C6 configuration; this
is not a general hardware-defect diagnosis. The component rejects an unsupported
hardware-ECC configuration rather than silently changing those semantics.

Builtin arithmetic and X.509 OID lookup use private SDK headers, pinned/tested
against IDF 6.1. Operational key-ID hashing reuses the existing aligned DER heap
workspace because the SDK SHA-1 driver could fault on an unaligned flash span.
These compatibility dependencies require review on an SDK upgrade.

Next integration: application-owned UDP/IPv6 and discovery, atomic persistent
storage, real commissioning/CASE/resumption and matching workloads for the
ESP-Matter reference. A Wi-Fi association alone does not establish IPv6 or Matter
controller reachability. No CSA certification result is inferred from this lab.
