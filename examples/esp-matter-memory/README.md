# ESP32-C6 external-stack memory reference

This laboratory compares the C runtime RGB fixture with an external ESP-Matter
light on a second C6. It does not embed ConnectedHomeIP in the C library. Keep
controller state, Wi-Fi headers, device flash backups and UART logs in ignored
`local/` or `build/`. No SDK checkout is modified by the preparation tool.

The measured reference uses ESP-Matter release/v1.6.1 commit
`4c9dd7aa80b3ddfa64c814bdfabe76c60944cc75`, its ConnectedHomeIP submodule
`b1902b39ac6734913ce5f4d2abf153693a50264b`, and ESP-IDF v6.0.2
`7101770dc6db2667b3c477cc31365dd1acd6db4e`. The C runtime uses IDF v6.1.
See the [Memory21 report](../../doc/oss/memory21-validation.md) for results,
failed exploratory runs and configuration differences.

Prepare a **new** copy after exporting the external IDF/ESP-Matter environments:

```sh
python tools/matter/prepare_esp_memory_reference.py \
  --esp-matter /path/to/pinned/esp-matter \
  --output /path/to/new-reference-light \
  --sdkconfig /path/to/existing-reference-sdkconfig \
  --hue-saturation
cd /path/to/new-reference-light
idf.py -B /path/to/reference-build -D IDF_TARGET=esp32c6 build
```

The tool adds observation hooks, enables the existing Hue/Saturation feature
when requested, and disables the three Wi-Fi IRAM placement options to match
the C lab. XY, color temperature, Scenes, other stock features and resource
limits remain enabled. Its board adapter uses WS2812 GPIO8 and button GPIO9.
Flash **that build's actual flasher_args.json**, after backing up the target;
the C runtime and reference have different partition offsets.

The C profile enables `MATTER_C_RUNTIME_RGB`, `MATTER_C_RUNTIME_SOAK`, and
`MATTER_C_RUNTIME_COMPARE_SAMPLER`. Keep `MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS`
off for headline comparisons: that separate attribution table changes layout.
Both observers compile the same `matter_lab_heap_sample.h`, sample internal
8-bit heap nominally every100ms from the SDK timer task, and include their own
timer/global cost. Samples can still miss shorter peaks. The SDK's aggregate
regional free watermark is a separate metric, not an exact simultaneous peak.
Dynamic task stack reservations are included in this heap pool; static RAM and
IRAM are reported separately from the linker map.

For the external light, run the private UART collector (requires pyserial):

```sh
python examples/esp-matter-memory/uart_capture.py --port COM_REFERENCE \
  --output build/private-reference --reset \
  --wifi-header local/private/matter_lab_wifi.h
```

The optional header contains the same JSON-string `MATTER_LAB_WIFI_SSID` and
`MATTER_LAB_WIFI_PASSWORD` macros as the C lab. Provisioning happens locally;
values are redacted before logs are saved. Omit the header for an already
provisioned board. File controls accept memory checkpoints and collector stop
only. `memstat <lowercase-label>` reports heap and all task stack watermarks.

Use the C runtime's existing UART collector for its board. With the pinned
Matter.js0.17.9 dependencies and an IPv6-connected interface, run sequentially:

```sh
node examples/esp-matter-memory/compare.mjs <node_modules> <scoped-ipv6> \
  <private-state> <controller-id> <private-uart-directory> reference commission <interface>
node examples/esp-matter-memory/compare.mjs <node_modules> <scoped-ipv6> \
  <private-state> <existing-controller-id> <private-uart-directory> c reuse <interface>
```

`commission` starts with an uncommissioned board; `reuse` requires one existing
fabric paired with the selected controller. Four temporary fabrics are added.
The private topology journal retains their identities if a test fails; do not
rerun blindly over a partially commissioned fixture. Preserve the original
fabric and controller state or explicitly restore a private lab backup.

The common workload establishes five fabrics, three live CASE sessions/fabric,
15 subscriptions to one Hue path, seven explicit Read paths, NodeLabel writes,
OnOff/Level/HS invokes, six update rounds, and readback. Every subscription must
observe Hue85 and170. RGB readback permits at most2s for the reference's
asynchronous SDK transition handler; it never shortens protocol timers. The
fixture closes subscriptions/sessions, waits12s for retirement, then creates
fresh CASE sessions and requires successful temporary-fabric removal responses.
NodeLabel is restored, the LED ends off, and the primary fabric is retained.

The final optional argument selects cleanup: `drained` (default), `live`, or
`local-close`. `live` removes each temporary fabric through one of its three
still-open CASE sessions, reads through every surviving session, and requires
fresh Hue updates on all surviving subscriptions after every removal.
`local-close` closes only local subscription listeners, waits2s, and removes
through the existing sessions while server exchanges may still owe ACKs.
Both variants require four successful RemoveFabric responses and record their
latencies. These are transport regressions; they do not shorten Matter timers.

Full wildcard inventories are recorded separately (the models differ). A
seven-path subscription workload exhausted the stock reference's shared path
pool; that failure is retained rather than increasing its limits. Our custom
OOM, RX-loss, reconnect and held-TX drain controls remain a separate C-only
regression, not a matched fault-injection test of ESP-Matter or official CSA.

## Lifecycle and application-budget comparison

Optimization ends at Memory40. Subsequent comparison images leave its library
source and limits unchanged. The normal-image comparison measures available
internal 8-bit heap, SDK minimum free, sampled minimum free, largest free block
and loaded/idle checkpoints. Keep SDK regional minima separate from simultaneous
100 ms samples. Heap-backed task stacks are already included in free heap.

Use the same explicit diagnostic peer profile on both devices when selected:
`MATTER_TEST_PEER_ROLE=corrected`. The optional override is the existing pinned
Memory26/27 test-peer helper; it changes no installed package or DUT timer.
Record the profile and package hash, including failed original-peer runs.

For the one-way lifecycle experiment, first export clean C sources or prepare
a new pinned HS reference as above. Generate another isolated project:

```sh
python tools/matter/prepare_memory_comparison.py \
  --kind c --source /path/to/exported-c \
  --output /path/to/new-c-observer --reserve-bytes 65536
python tools/matter/prepare_memory_comparison.py \
  --kind reference --source /path/to/prepared-reference \
  --output /path/to/new-reference-observer --reserve-bytes 65536
```

The C output retains the exported repository structure; build its
`examples/esp32-runtime`. Build the reference output directly. Keep the existing
SDK versions/configurations. Set `IDF_PY_BUILD_JOBS=1` and
`CMAKE_BUILD_PARALLEL_LEVEL=1`. CHIP's nested build invokes bare `ninja`; use a
project-local PATH wrapper which executes the real Ninja with `-j1` as well.
Do not change the shared SDK's build files or the system Ninja.

Both probes keep Wi-Fi connected for 65 seconds before creating Matter, then
reserve and pattern-fill the optional application payload through the common
wire workload. The C collector's `q` command performs its existing ACK/drain and
deletion sequence, followed by another 65-second Wi-Fi-up observation before
radio teardown. The reference uses the previously saved SDK Wi-Fi configuration
to connect before creating its node. After its common workload, request a UART
checkpoint labelled `shutdown` (`memstat shutdown`). The probe destroys the
model, shuts down Server and PlatformManager, observes Wi-Fi for 65 seconds,
checks/releases the reserved payload, and remains stopped. Keep that collector
running until `LIFECYCLE_SHUTDOWN_COMPLETE`, then stop the collector only.
The reference observer removes its SDK IP/Wi-Fi event forwarding and verifies
that the CHIP task has exited before deleting platform queues/locks.
`StopEventLoopTask()` alone is asynchronous; the initial observer without this
barrier asserted in FreeRTOS and is retained as a failed experiment.

`LIFECYCLE_MEMORY` includes 0/1/5/15/30/65-second free-heap and largest-block
checkpoints, local SDK regional minima, Wi-Fi/IPv6 state and reserved payload
size. Check external IPv6 connectivity after deletion too. These instrumented
images are separate from the normal-image headline measurements. A retained
64 KiB allocation demonstrates that budget under this workload; it is not an
MQTT, HTTP or TLS-handshake measurement.

The reference probe is an experiment with the pinned low-level APIs, not a new
supported ESP-Matter stop/restart interface. Its static singleton/pool storage
remains linked. Do not equate a connected netif or returning `Shutdown()` with
complete RAM reclamation, unchanged application services, or proven restart.
Compare a separate Wi-Fi-only reference configuration when BLE is unnecessary;
retain the stock BLE-after-commissioning result and all Matter resource limits.

## Same-IDF user case with real OTA

[Memory42](../../doc/oss/memory42-validation.md) adds the native ESP installer.
[Memory43](../../doc/oss/memory43-validation.md) measures both physical C6 boards
with IDF6.0.2, mDNS1.14.0, BLE off, CHIP shell off and real signed OTA1→2.
The matched controller is pinned Matter.js0.17.9; chip-tool is also suitable
when its host can reach the DUT's scoped IPv6 address. Manual Apple/Google Home
and production attestation are separate tests.

The preparation tool modifies the C lab's defaults and partition file in an
**exported source copy**. It rejects a Git checkout. Build outside shared SDK
trees and use new output directories:

```sh
# Export this repository to <exported-c> first; do not use the working checkout.
python tools/matter/prepare_esp_memory_reference.py \
  --esp-matter <pinned-esp-matter> --output <new-hs-reference> \
  --sdkconfig doc/oss/memory43/profiles/reference-sdkconfig --hue-saturation
python tools/matter/prepare_memory_comparison.py --kind reference \
  --source <new-hs-reference> --output <new-lifecycle-reference> --reserve-bytes 0
python tools/matter/prepare_esp_usercase.py --source <exported-c> \
  --reference <new-lifecycle-reference> --output <new-usercase-profiles>
```

Activate pinned IDF6.0.2 and ESP-Matter1.6.1. Use the same mDNS1.14.0 component
for both projects; retain the reference's resolved dependency lock/components.
Build the reference output directly and C at `<exported-c>/examples/esp32-runtime`.
C requires `MATTER_LAB_MDNS_DIR` and `MATTER_C_LAB_CONFIG_DIR`. The latter can
point to a public stub `matter_lab_wifi.h` with empty SSID/password strings:
this profile obtains actual Wi-Fi bytes from NVS instead. Keep old fault-image
and normal-image build directories/configs separate. Exact measured configs
and hashes are under `doc/oss/memory43/`.

```sh
idf.py -C <exported-c>/examples/esp32-runtime -B <new-c-build> \
  -D SDKCONFIG=<new-c-sdkconfig> -D IDF_TARGET=esp32c6 \
  -D MATTER_LAB_MDNS_DIR=<mdns-1.14-component> \
  -D MATTER_C_LAB_CONFIG_DIR=<stub-directory> build
idf.py -C <new-usercase-profiles>/reference -B <new-reference-build> \
  -D IDF_TARGET=esp32c6 build
```

For version2 set `CONFIG_APP_PROJECT_VER="2"` in both configs and
`CONFIG_DEVICE_SOFTWARE_VERSION_NUMBER=2`,
`CONFIG_DEVICE_SOFTWARE_VERSION_STRING="2"` in the reference, then reconfigure
and rebuild. Preserve each version's ELF/map/config and flash manifest before
reusing any build directory. Compilation used at most4 jobs, including CHIP's
nested Ninja via a project-local PATH wrapper; shared SDKs were not modified.

Before destructive lab setup, save and verify the entire original4MiB flash
and the original controller state. The new shared partition layout changes
offsets: table0xc000, NVS0x10000/256KiB, otadata0x50000, ota_0 at0x60000 and
ota_1 at0x230000, each0x1d0000 bytes. Do not migrate by overwriting only an app.
Provision default NVS namespace `lab_wifi`, blob keys `ssid` and `password`,
locally. Sign both initial and update app images with the same local RSA3072
key using `espsecure sign-data --version 2`, then wrap the signed update payload
in a standard Matter OTA image (VID0xfff1/PID0x8000, numeric version2, SHA-256).
Hardware Secure Boot and eFuses are not enabled. No signing keys, NVS seeds,
network credentials, controller keys or raw logs belong in public exports.

Use one new private output folder per run, with its version2 Matter image named
`source.ota`. Flash signed version1 and provision Wi-Fi, then start capture before
the controller. Substitute COM24 and `reference` for the other board:

```sh
python examples/esp-matter-memory/usercase_uart.py \
  --port COM23 --output <private-c-run> --reset
node examples/esp-matter-memory/usercase.mjs <node_modules> <scoped-ipv6> \
  <private-c-run> c Wi-Fi full
```

The collector uses UART1M and follows reboots. A local `control-request.json`
with `{"command":"stop"}` releases it. Digits0..9 select measurement phases;
`m` records a checkpoint, `u` queries OTA, `q` deletes Matter while preserving
Wi-Fi. On C only, `x` arms a single interrupted SDK trial boot. The controller
waits for firmware READY, records successful version readback and requires one
Apply and matching Notify after actual restart. Its Busy retries are bounded
client behavior, not server capacity changes or shorter Matter timers.

The optional C `commission-ota` mode with environment
`MATTER_USERCASE_OTA_EXPECT=reject|interrupt|rollback` exercises a wrong signer,
interrupted BDX or SDK rollback respectively. Use a fresh disposable version1
setup each time. For `reject`, supply a valid Matter envelope around an image
signed with a different private key. The interrupt case also needs separate
inactive-flash readback to prove a partial transfer. `ota-only`, `commission-only`
and provider-only `serve` modes support private diagnosis; they are not headline
matched runs.

After a full run, require external IPv6 ping3/3 while Matter is stopped and save
`wifi-after-stop-ping.json` as `{"pass":true,"probes":3}` **only after that test**.
Then export verified numeric data and plots (matplotlib required):

```sh
python tools/matter/plot_esp_usercase.py --c <private-c-run> \
  --reference <private-reference-run> --output <new-public-results>
```

The exporter rejects failed/incomplete runs, missing phase data, OOM or missing
post-shutdown ping evidence. It emits numeric JSON/CSV and lavender/blue PNG/SVG,
without copying raw UART or controller stores. Inspect both plots visually.
Finally restore both original full-flash images, probe their original controllers
with fresh CASE/control/readback, stop collectors and release only the temporary
AP profile. Leave the user's IPv6 setting intact.
