# Memory15 — sustained C6 concurrency validation

Status: physical C6 run PASS, 3606.237 seconds of the requested one-hour
fault/recovery workload, followed by acknowledged fabric cleanup and successful
deferred-TX stop/drain. Preliminary failures remain separate evidence. This is
an independent laboratory result, not an official CSA result.
Machine-readable evidence is in [memory15-results.json](memory15-results.json).

## Scope and implementation

Hardware: ESP32-C6FH4 rev0.0, 4 MiB flash without PSRAM, COM23, and TL-MR3020 V1
running its existing OpenWrt19.07.10 image. Native IDF6.1 and the pinned
Matter.js0.17.9 controller communicate through same-link IPv6.

The existing C6 root-node laboratory retains the same five-fabric, three
CASE-sessions/subscriptions-per-fabric, 56-transport-slot and 128-event limits.
The test creates separate authenticated sessions, protects each with a full
Subscribe snapshot, performs concurrent full Reads and observes DeviceLoadStatus
on the wire. Constructor/API budgets are not reduced to fit the board.

Optional `CONFIG_MATTER_C_RUNTIME_SOAK` is off by default. It adds a small
application-owned observer, nominal 100 ms heap sampling, five-second telemetry and
local owner-thread fault controls. Library/port allocations retain existing
profiling; SDK/PSA allocations and application fixtures remain visible only in
system heap. Large buffers stay on the heap; raw lwIP RX does not allocate.

The first full-load attempt exposed an adapter scheduling defect: terminal TX
completion returned before queued RX delivery. Continuous TX could therefore
starve ACK ingress. The adapter now services both in one owner turn while
retaining reentrancy and borrowed-lifetime guards.
A physical loopback fixture queues RX and an accepted TX together and requires
both callbacks after one process call. It passes on the repaired target.

One RX slot also loses concurrent request/ACK bursts even after fixing that
starvation. The owner now doubles stable receive headroom on observed overflow,
up to eight slots, and trims extra free slots after ten idle seconds. Allocation
is outside the TCP/IP lock and never in raw RX. Growth OOM retains the current
FIFO; deactivation drains callback references and frees all queued/free slots.
The original packet ceiling and all Matter admission limits are unchanged.

The first live reconnect calibration also exposes a distinct scope-key defect:
the same netif is removed/re-added with a new numeric lwIP index, while secure
channels retain and compare their original interface key. The adapter now keeps
a stable key for its borrowed netif lifetime and translates only at the OS TX
boundary. No core path checks are relaxed. `UDP_SCOPE_PASS` saves a path, restarts
the radio, requires an actual OS-index change, then verifies RX and accepted-TX
completion through that original path.

The oracle/collector source, usage, local fault semantics and cleanup are in
the [runtime laboratory README](../../examples/esp32-runtime/README.md).
Raw UART/controller captures, topology, credentials and binary artifacts remain
private in ignored directories. Failed runs are kept for attribution.

## Configuration boundary found by saturation

With the SDK's three Wi-Fi IRAM placement optimizations enabled, five parallel
full Reads beside 15 full subscriptions exhaust SDK allocation headroom. The
instrumented boundary run records 25 failed SDK allocation attempts, largest
request 1477 B, and MRP/Read timeout. It is a failure, even though injected core
failures remain at the 13 boot fixtures and final stop drains cleanly.

The separate optional `sdkconfig.wifi-flash` switches off only
`ESP_WIFI_IRAM_OPT`, `ESP_WIFI_RX_IRAM_OPT` and `ESP_WIFI_EXTRA_IRAM_OPT` (including
generated compatibility aliases). Driver RX/TX pools remain 10/32/32; Matter
limits are unchanged. Linker DIRAM use falls 140803 -> 107471 B, recovering
33332 B. With final identical sources, flash code grows 1172498 -> 1204602 B.
This follows the SDK's documented
[code-placement tradeoff](https://github.com/espressif/esp-idf/blob/v6.1/components/esp_wifi/Kconfig);
it must be judged with actual traffic, not linker savings alone. The default
laboratory configuration is unchanged. Both it and a fresh configuration using
the documented soak/flash overlays compile successfully.

A first flash-code attempt completes 120 full Reads and two injected allocation
failures with 15 subscriptions and no SDK allocation failure. It then stops on
a timeout during deliberate three-second packet loss; that strict oracle did
not attempt post-loss re-establishment. The subsequent oracle counts interrupted
fault-window operations and explicitly requires fresh healthy Reads and all 15
subscriptions, recording every session/subscription rebuild. Healthy-traffic
failures remain fatal. The earlier default-config bounded calibration was
interrupted by a Windows collector sharing violation, corrected with an
append-only reply journal; it is an infrastructure failure, not a passed soak.

A later 27-minute attempt reaches 587 full Reads, 12 OOM recovery cycles, six
loss cycles and three completed reconnect recoveries. The fourth reconnect's
five Reads complete, but immediate replacement CASE admission returns `BUSY`.
This is retained as a failed attempt. The oracle now staggers best-effort session
closes across fabrics and, only during recovery, permits counted two-second
CASE BUSY backoff with a 90-second deadline. Old protected slots are not bypassed
or reclaimed early. Initial admission and the fourth-session BUSY probe stay
strict. `recovery_busy_wait_ms` counts explicit backoff sleep, excluding handshake
time. The successful hour uses this recovery policy. No BUSY retry is needed in
that run after staggering closes; the 90-second retry branch is not physically
exercised there. The protected fourth-session BUSY probe still passes.

## Completed physical workload

The final firmware is unchanged between the 27-minute attempt and the successful
hour. The latter starts with five persisted fabrics; the earlier attempt creates
the four additional fabrics from the original state. Both use the optional
Wi-Fi flash-code profile. The final oracle completes the following:

| Observation | Result |
| --- | ---: |
| Fault/recovery load window | 3606.237 s |
| Controller run including setup/cleanup | 3729.903 s |
| Concurrent protected CASE sessions / full subscriptions | 15 / 15 across 5 fabrics |
| Complete full Reads / attribute reports | 1392 / 185136 |
| Full 133-attribute Subscribe snapshots, including rebuilds | 360 |
| Tracked OOM cycles, positions 1–9 repeated three times | 27 |
| OOM-window rejected Reads / ended subscriptions / workload rebuilds | 8 / 12 / 12 |
| Three-second ingress-loss cycles / rejected Reads / workload rebuilds | 14 / 5 / 2 |
| Observed ended subscriptions from loss | 1; failed load queries need not expose every lost subscription |
| Actual radio reconnects and full workload recovery | 9 |
| Reconnect-window Reads | All 45 complete |
| Healthy-traffic operation errors / unexpected subscription closures | 0 / 0 |
| Recovery CASE BUSY retries | 0 |
| SDK failed-allocation attempts | 0 |
| Final deferred-TX stop wait | 3.585 s |

Loss and OOM can end sessions/subscriptions: this is recovery coverage, not
uninterrupted availability. The final Read deliberately interrupted by stop is
rejected, separately from healthy-traffic counters. Each full Read requires 133
distinct attribute paths; each initial/rebuilt Subscribe snapshot requires 133
attributes. DeviceLoadStatus verifies 15 total and three accessing-fabric
subscriptions. Handshakes are established sequentially and held concurrently;
maximum simultaneous PASE/CASE admission is not measured. Fabric removal and
recommissioning are not repeatedly churned while other fabrics stay saturated.

Successful full-Read latency is median 6082 ms, p95 8412 ms, maximum 17029 ms,
including deliberate fault/reconnect recovery. These are workload latencies, not
a matched throughput comparison against another stack.

| Memory observation | Bytes |
| --- | ---: |
| Maximum sampled internal heap allocation in successful hour | 368184 |
| Tracked library/port allocation-event peak | 276648 |
| Minimum sampled free heap / minimum largest free block | 52728 / 26624 |
| SDK sum of per-region low-water marks | 46896 |
| Owner stack observed use / reserved | 2584 / 12288 |
| Largest sampled heap / owner-stack use across final-firmware attempts, including failed 27-minute attempt | 370640 / 2712 |
| Final tracked live allocations / bytes | 0 / 0 |
| Final free internal heap / largest free block after runtime teardown | 393252 / 217088 |

At comparable full-load checkpoints after nine reconnects, allocated heap stays
291780–292104 B and tracked bytes 196444–196668 B; largest free blocks are
64512–73728 B. There is no monotonic growth across those checkpoints. During
active traffic the smallest logged largest-block sample is 27648 B alongside
61544 B free, 77 free blocks and 850 allocated blocks; the nominal 100 ms sampler
separately observes a 26624 B minimum. These are different observation times.
At the post-drain checkpoint before reconnecting peers, five-fabric heap is
189148 B and largest block 96256 B. The dedicated boot fixture proves idle FIFO
trim from eight blocks to one; periodic network samples do not resolve the
exact pool size at this checkpoint. Full teardown returns tracked allocations to
zero and passes `heap_caps_check_integrity_all(true)`; SDK/global task resources
still account for 31532 B, so this does not claim zero global SDK allocation.

The four test fabrics are removed with acknowledged responses, the original
fabric and durable label are restored, and the target ends in its controlled
stopped loop after `RUNTIME_PASS`. Reset restarts this laboratory firmware.
COM23 is released. Windows returns to its initially disconnected Wi-Fi state;
only the temporary test profile/XML are removed. IPv6 remains enabled as set by
the owner. The AP firmware/configuration is unchanged.

## Interpreting memory and fragmentation

Whole-system internal-heap observations include SDK resources and all reserved
task stacks. Do not add stack reservations to those totals. Tracked allocation
peaks include the C library, IDF adapters and Wi-Fi port, excluding SDK/PSA
internals and allocator headers. Whole-node maxima are sampled when the owner
pumps; blocking crypto/SDK calls can widen the nominal 100 ms interval and hide
transient maxima. SDK low-water values combine per-region minima and need not
represent one coincident instant.

Largest free block, total free space and allocated/free block counts are recorded
together. A largest/total ratio is an availability indicator across multiple
regions, not a mathematically exact fragmentation percentage. Compare the same
fabric/session/subscription occupancy before and after churn; legitimate event,
resumption and SDK cache retention must be distinguished from leaked memory.
Final runtime stop requires zero tracked live allocations and SDK heap integrity.
The public `tests/summarize.py` extracts selected counters and telemetry without
copying addresses, topology, attribute values, controller state or raw exceptions.

## Build, host regression and stack review

The core source is unchanged in this stage. A fresh comparison verifies all 162
host source/test/config hashes against the VM run. Linux CTest passes 95/95 in
the normal build and separately 95/95 with ASan/UBSan/LSan. The independent
two-instance, three-phase-meter scenario passes 6/6 under Memcheck and separately
6/6 with sanitizers. Memcheck reports zero errors, zero suppressed errors and
zero live blocks/bytes; sanitizer stderr is empty. Windows focused
`ctest -R "^test_runtime(_alloc)?$" --output-on-failure` passes 2/2. These host
checks cover core behavior; they do not execute the IDF/lwIP adapter.

Native IDF builds pass with the final adapter in both the soak/flash-code profile
and the default no-soak profile. The documented fresh overlay configuration also
builds. GCC logs contain no `warning:` diagnostics; SDK CMake tool-version and
Kconfig deprecation notices are retained as SDK notices, not called warning-free.
`python tools/matter/check_test_map.py` passes with 256 mapped files, 97 native
definitions, 59 core sources and 75 public headers. Node/Python syntax and diff
whitespace checks pass.

DWARF sizes are 104 B for the adapter, 1284 B per stable RX block and 80 B for
the optional observer (plus two process-lifetime 32-bit SDK-failure counters).
Eight RX blocks request 10272 B; idle trimming releases 8988 B of that capacity.
Compiler `.su` frames are 496 B for the physical FIFO/scope fixture, 176 B for
`app_main`, 192 B for observer control, 64 B for sampling, 48 B for RX capacity
maintenance and 32 B for adapter processing. These are individual frames, not
summed call-chain bounds; observed task watermarks complement them.

## Changed files and purpose

| Files | Necessary change |
| --- | --- |
| `components/matter_c_esp32/matter_idf_udp.c`, `.h` | Fair TX/RX service, stable demand-grown RX FIFO and stable interface scope across radio restart; appended queue telemetry. |
| `components/matter_c_esp32/CMakeLists.txt` | Private `esp_timer` dependency for RX idle trimming. |
| `examples/esp32-runtime/main/app_main.c` | Physical adapter fixtures, observer integration and target markers; existing runtime ownership/drain retained. |
| `examples/esp32-runtime/main/soak_lab.c`, `.h` | Optional application-owned sampling/fault controls, delayed completion and safe SDK failure counters. |
| `examples/esp32-runtime/main/CMakeLists.txt`, `Kconfig.projbuild` | Compile the observer; explicit default-off soak option. |
| `examples/esp32-runtime/sdkconfig.soak`, `sdkconfig.wifi-flash` | Reproducible optional profiles without changing project defaults or resource limits. |
| `examples/esp32-runtime/tests/soak.mjs`, `uart_capture.py`, `summarize.py` | Independent network oracle, serialized UART controls/capture and selective telemetry extraction. |
| Runtime/root READMEs, status and Memory15 report/results | Reproduction, measured envelope, failures and remaining limits. |

## Espressif reference and certification follow-up

The linked [optimization guide](https://docs.espressif.com/projects/esp-matter/en/latest/esp32c6/optimizations.html)
identifies its benchmark as ESP32-C3, IDF5.4.1 and a light example. It includes
shell/BLE/endpoint changes, smaller resource pools/buffers, and code placement
tradeoffs. Its heap figures are not a matched C6 comparison. Our suite preserves
the advertised budgets; no efficiency ratio is derived from those vendor figures.

The [certification guide](https://docs.espressif.com/projects/esp-matter/en/latest/esp32c6/certification.html)
connects declared PICS features to test scope and describes test attestation
material, TH preparation and product submission. Its IPv6 section specifically
calls out TC-SC-4.9/RIO, SLAAC and enough addresses, with IDF6.x native RIO support.
Our current configuration has SLAAC disabled, three IPv6 addresses and RIO
disabled; same-link success does not validate that routed scenario. This is a
separate follow-up, not a configuration change hidden in the concurrency test.
The public TEST CD is accepted by the controller's development policy despite
a parser finding; strict attestation and official CSA results are not established.

The C6 workload also differs from the separate three-phase host meter and the
compiled-only ESP-Matter reference. A root-node result is not a specification-wide
RAM bound, a product-model comparison or a certification claim.

Next task: compose the actual three-phase product model on C6 and repeat this
same maximum-load memory envelope before changing another memory representation.
