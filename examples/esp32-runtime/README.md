# ESP32-C6 runtime laboratory

Native ESP-IDF **v6.1** composition of the complete C runtime with application
owned IPv6 UDP, ESP mDNS, Wi-Fi and atomic checkpoint storage. No task is created
by the C runtime. The application explicitly starts/stops SDK radio, lwIP and
mDNS services, pumps all core calls from one owner, and retains ports through
stop/drain/delete. Defaults remain 128 events, 56 transport slots, three
subscriptions per fabric and the existing five-fabric limit.

This is a development laboratory with public TEST DAC/key/CD and passcode
20202021. Its initial UTC comes from build time, not a trusted clock service.
The controller's development attestation policy is not production validation.
Provisioning, a trusted clock and encrypted storage are application responsibilities.

## Dependencies and build

Use the unchanged official IDF v6.1 checkout and a separate official Espressif
`esp-protocols` checkout pinned to `mdns-v1.12.0`, commit
`db06b19b7be729c163d346f62ec0eba01047b7f1`. No SDK sources are vendored or patched.
The mDNS component retains its own Apache-2.0 license. Configuration/build does
not download dependencies. The application owns `mdns_init`, hostname, netif and
`mdns_free`; the adapter only installs/removes its exact service instance.

Keep `matter_lab_wifi.h` in ignored `local/` as described in the
[first laboratory](../esp32-memory/README.md). Use native activated IDF:

```powershell
$repo = (Resolve-Path .).Path
idf.py -C "$repo/examples/esp32-runtime" -B "$repo/build/idf61-runtime" `
  -D SDKCONFIG="$repo/build/idf61-runtime/sdkconfig" -D IDF_TARGET=esp32c6 `
  -D MATTER_C_LAB_CONFIG_DIR="<private-header-directory>" `
  -D MATTER_LAB_MDNS_DIR="<esp-protocols>/components/mdns" build
```

The component requires software ECC, TCP/IP core locking and disabled IPv6
reassembly. UDP validates the full IPv6 packet ceiling 1280 B, actual destination
and interface, rejecting fragments including atomic fragments. Supported hop,
routing and destination headers reduce available UDP payload by their size.
One RX slot allocates on activation. Observed overflow lets the owner grow a
stable FIFO to at most eight slots; extra free slots release after ten seconds
without RX. Growth OOM retains the current FIFO; a full queue drops datagrams
and relies on existing MRP. No allocation or Matter callback runs in raw RX.
The binding reserves its UDP port globally and filters the actual input netif;
paths retain a stable adapter scope key through Wi-Fi stop/start. TX maps that
key to the netif's current numeric lwIP index; RX reports the same stable key.
Accepted TX releases lwIP buffers before an owner-deferred completion; local
success is not a peer ACK. Stop's RX barrier does not cancel that obligation.

The laboratory explicitly selects the existing `CHIP` CASE resumption profile,
matching the host driver and Matter.js0.17.9. The peers use the previous ID for
`SessionResumptionKeys`; the core's default `SPEC` profile uses the new
Sigma2Resume ID and is unchanged. Set `CONFIG_MATTER_C_RUNTIME_CHIP_RESUMPTION=n`
only for a peer configured for that profile. No ciphertext-based autodetection.
After changing Kconfig options, run `idf.py reconfigure build` and inspect the
generated config plus the target's `CASE_PROFILE` marker.

## Partition and persistence

**The partition table differs from the earlier memory example.** It retains the
default SDK NVS/PHY regions, adds a dedicated 256 KiB `matter` NVS partition at
0x10000 and starts the application at 0x50000. Preserve a full device backup and
plan migration before changing an existing partition layout. Never flash the
older example over this partition: its app would overwrite Matter state.

For a first disposable lab setup, erase only the newly allocated `matter`
region after preserving original firmware/state. The app never erases the whole
partition, silently formats a damaged store or falls back to an older selected
checkpoint. Keep the partition across subsequent flashes/reboots.

Two NVS keys hold complete, unchanged TLV blobs, with a one-byte active selector.
Replacement writes/commits only the inactive candidate before changing that
selector. A selected blob's corruption/missing data is an error, not an empty
fabric set. The adapter is reviewed against IDF6.1's synchronous `set_item` and
no-op `commit` implementation: `REMOVE_FAILED` on the selector means publication
already occurred, so it succeeds and latches further writes offline. Other
physical storage errors also latch writes offline. A power interruption can
recover an entire old or new checkpoint; no partial model is published. Physical
flash-failure ambiguity is not equivalent to a deliberately rejected precommit.
Re-review these semantics on any SDK upgrade.

The 256 KiB partition budgets one node's 32768-byte blob ceiling, versions and
NVS GC plus the separate disposable test namespace. The earlier 128 KiB lab
layout ran out of staging space when the maximum-size fixture coexisted with
the live checkpoint. The final layout runs that fixture on every boot, including
after commissioning, then clears only its own namespace.
NVS partition initialization/teardown belongs to the application. Credentials,
fabric keys, controller state, firmware images, backups and UART captures stay
in ignored directories.

## Execution and local controls

The default first run faults every tracked runtime-constructor allocation and
tests adapter OOM/retry, scan cancellation, maximum checkpoint size, rejected
publication/reopen, and a durable fail-safe restart. Completed long tests are
marked in a separate lab namespace. Disable `CONFIG_MATTER_C_RUNTIME_OOM_SWEEP`
in a separate profiling configuration to exclude that fixture's startup work.
The owner runs at idle priority so synchronous crypto does not starve idle's
watchdog. This is not an asynchronous crypto or production latency guarantee.

Wait for `RUNTIME_READY`. Network requests go through the real runtime dispatcher,
PASE/CASE and IM authorization. Discovery follows runtime commissioning mode
and all live fabric identities, draining old records before replacing them.

- Send local UART `r` to persist a pending Wi-Fi recovery checkpoint and restart.
  This explicitly marked crash fixture preserves committed fabrics. The next
  boot forces actual Wi-Fi reconnect while admission remains closed, then clears
  the durable marker and emits `FAILSAFE_REBOOT_PASS`.
- Send local UART `q` to stop. Runtime retirement, UDP completions, MRP/IM delivery
  gates and advertisement withdrawal drain before any borrowed port is deleted.
  No timeout permits a force-free. `RUNTIME_PASS` requires zero tracked live
  allocations and SDK heap integrity. SDK process-wide resources can remain.

`MEMORY`, `TASK_MEMORY` and `NETWORK` expose heap/task and ingress-drop samples.
Tracked allocations include the C library, these IDF adapters and the Wi-Fi
backend; SDK/PSA internals and application fixtures are only in system heap.
All tracked allocations run on the owner, including the optional profiler.
Stacks are already in system heap. SDK low-water marks sum per-region minima;
neither those nor samples prove an exhaustive coincident whole-node peak.

Measurements and actual regression/physical-test scope are recorded in the
[Memory14 report](../../doc/oss/memory14-validation.md). A Wi-Fi AP with link-local
IPv6 suffices for same-link tests; routed IPv6/RA still requires separate
validation. The scoped one-hour concurrency envelope is recorded in
[Memory15](../../doc/oss/memory15-validation.md). No CSA result follows from this laboratory.

## Experimental RGB profile

Append `sdkconfig.rgb` to the fresh soak/flash-code configuration to enable
`CONFIG_MATTER_C_RUNTIME_RGB=y` (default off). DevKitM-1 GPIO8 drives a
WS2812-compatible GRB LED. EP1 adds OnOff, LevelControl and ColorControl:
On/Off/Toggle, MoveToLevel/WithOnOff, Stop/WithOnOff, MoveToHueAndSaturation and
StopMoveStep. The application advances transitions; RMT completion releases its
borrowed pixel buffer. Settings are volatile. This is an incomplete development
light profile: Identify, Groups, Scenes, XY/CT and other mandatory lighting
behavior are missing. See [Memory16](../../doc/oss/memory16-validation.md).

The composed model has171 attributes (38 on EP1). With the existing commissioned
controller state, test selected light commands/transitions and subscriptions:

```text
node examples/esp32-runtime/tests/rgb.mjs <node_modules> <scoped-C6-IPv6> <private-controller-state> Wi-Fi c6-memory14
```

Set `MATTER_SOAK_ATTRIBUTES=171` for the full-load soak; its default remains133
for the root-only model. Run mode requires a radio reconnect even if recovery
consumes the timed window. Final stop observes an actually held TX completion;
a host delay alone does not prove the packet was sent.

## Independent network oracles

Install the pinned `tools/matter/controller` package/lock into an ignored test
directory using `npm ci --ignore-scripts`. Keep its `node_modules` and controller
state outside version control. Run the public oracle with native Node.js:

```powershell
node examples/esp32-runtime/tests/controller.mjs <node_modules> `
  '<C6-link-local>%<PC-interface-index>' commission <private-state> Wi-Fi c6-lab
```

Use the same state/id for `reconnect` (remote persistent label, one fabric,
Read/Write and full Subscribe), `open` (ECM discriminator 1234), then `second`
(separate controller/fabric, full snapshot and acknowledged removal of that
fabric). `reconnect` saves an event watermark in private state; after local UART
`r`, use `recovered` to require all reported event numbers to exceed it. All
these commands use the default laboratory passcode and fixed first node ID.
The public unbound-client factory avoids the normal SDK wrapper's automatic
cached DataVersionFilters, so the snapshot assertion exercises actual wire data.

This pinned wrapper's known-address commissioning branch uses its default
development attestation policy and does not forward a custom failure callback.
It accepts a parser finding for the public TEST CD (`Structure element tags
should have an id.`). Commissioning success here does not validate attestation.

For discovery, install `zeroconf==0.147.0` in an isolated Python environment and
run `tests/discovery.py <PC-interface-index> <C6-IPv6-without-zone>
<service-type> <private-result.json>`. It checks target AAAA, PTR/SRV/TXT and port
5540; the initial `_matterc._udp.local.` case also checks the default 3840
discriminator subtypes and CM1. Use `_matter._tcp.local.` for operational
discovery, not the initial-window check for an ECM with discriminator 1234.

## Sustained concurrency laboratory

Enable `CONFIG_MATTER_C_RUNTIME_SOAK=y` in a separate build/configuration; its
default is off. Matter resource limits and the receive-slot size remain unchanged.
For a fresh soak configuration, append `sdkconfig.soak` to `SDKCONFIG_DEFAULTS`.
The optional `sdkconfig.wifi-flash` additionally places Wi-Fi hot code in flash,
trading throughput for RAM without reducing driver pools. Use a new `SDKCONFIG`
and build directory: an existing configuration takes precedence over defaults.
For example, add these arguments to the build command above:

```text
-B <fresh-build-dir> -D SDKCONFIG=<fresh-config-path> -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.soak;sdkconfig.wifi-flash"
```

For the C6 DevKitM-1's UART0 console at 1,000,000 baud, additionally append
`sdkconfig.uart-1m` to that defaults list and pass `--baud 1000000` to the
collector. This selects custom UART0 on the same GPIO16/17 pins. With an existing
ESP-IDF6.1 configuration, use menuconfig or remove the `# default:` marker for
the baud setting before setting its value explicitly; editing a marked default
alone lets the generator restore 115200. Check the generated
`config/sdkconfig.h` before flashing. Flashing baud is a separate setting, and
the existing ROM/bootloader output may still use 115200.

The owner samples internal heap nominally every 100 ms, emits `SOAK`/`MEMORY` every five
seconds and records allocator calls, live/peak bytes, largest free block and
free/allocated block counts. This is sampled whole-system telemetry, not an
exhaustive instantaneous heap trace; blocking crypto/SDK calls widen sampling
gaps. Region boundaries affect the largest-block
ratio; compare like-for-like quiescent states and retained workload as well.
Both records include current `heap_free`; `heap_min_sampled` is the minimum
observed by the sampler, while `MEMORY.heap_min` is the SDK aggregate low
watermark. Also compare `largest_free`, `largest_min_sampled` and block counts.
The selected pool is `MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT`: its allocated
bytes include Wi-Fi/lwIP/mDNS/crypto allocations and dynamically reserved task
stacks in that pool, including unused stack space. `core_peak` covers only
instrumented library allocations. Neither value includes static `.data/.bss`,
code in IRAM or allocations outside the selected capabilities. Stack high
watermarks measure observed use separately; do not add reserved stacks again
to the whole-heap peak. Per-region SDK minima need not occur simultaneously.
The [Memory20 report](../../doc/oss/memory20-validation.md) compares free heap at
startup, full load, recovery, drain and final release as well as peak use.
The observer allocates one small application-owned state object. All callbacks
and controls run on the owner. No allocation is added to raw lwIP RX.

The soak build also runs `UDP_FAIRNESS_PASS`: one looped-back datagram and its
accepted TX completion are both pending before one adapter process call. Both
callbacks must run in that turn. This guards against continuous TX starving RX
and its ACKs. The additional `UDP_FIFO_PASS` fixture verifies demand growth,
growth OOM, ordered delivery, idle trim and cleanup of the bounded RX FIFO.
`UDP_SCOPE_PASS` additionally restarts the physical radio, requires a changed
OS interface index and sends/receives through a path saved before that restart.

Keep UART captures, results, control files, controller credentials and topology
manifests in ignored directories. Start the native Python/pyserial collector:

```text
python examples/esp32-runtime/tests/uart_capture.py --port COM23 --output <private-uart-dir> --duration 10800 --reset
```

For a faster UART capture, use the optional `sdkconfig.uart-1m` above and pass
`--baud 1000000` to the collector. Both ends must use the same rate. It defaults to 115200
for existing images; the flashing baud is a separate setting. Check the actual
UART log for intact JSON records after changing the rate.

For startup subscription investigations, `tests/dispatch_trace.py` generates a
separate diagnostic dispatcher source. Apply it only to a disposable laboratory
checkout, keeping the original source intact:

```text
python examples/esp32-runtime/tests/dispatch_trace.py --source main/apps/matter/runtime/matter_dispatch.c --output <private-copy>/main/apps/matter/runtime/matter_dispatch.c
```

Build that copy with the same limits/configuration. The collector records
`TRACE26` metadata in `events.jsonl` and raw UART. `QUEUED.a` is the wire counter,
`QUEUED.b` the opcode; `TX.b` packs `(attempt <<16) | Matter_Result_T`.
`TIMER` includes the exact MRP deadline. `ACK_RX.a` is the acknowledged counter;
an OK result alone can be a no-op, so correlate it with `MRP_END` on the same
session/exchange/counter. `MRP_END.b` packs `(attempts <<16) | outcome`, with
outcomes 1 ACK, 2 timeout, 3 failed, 4 cancelled. `RX.b` packs opcode/result.
`CLOSE.line` and `RETIRE.line` refer to the generated source, and `state` is the
subscription enum. `init` is the local exchange role, opposite the received
packet's Initiator flag. The transaction's `ack` flag may still describe its
previous packet while a new one is pending; use the matching `MRP_END` counter.
`ESTABLISHED` means successful local SubscribeResponse TX,
not peer ACK. Keep the generated file/hash with the capture. The synchronous
logging changes timing, stack and layout; exclude it from headline memory
comparisons and final normal firmware. No fault injection is added by this tool.
`--failures-only` suppresses healthy packet traffic while retaining subscription
errors/closes and session lifecycle records for a second capture with less UART
timing overhead. It preserves the same core limits and transaction layout.

After `RUNTIME_READY`, run the pinned Node.js oracle:

```text
node examples/esp32-runtime/tests/soak.mjs <node_modules> <scoped-C6-IPv6> <private-controller-state> <private-uart-dir> 3600 Wi-Fi run wildcard
```

For core regressions without a board, the same oracle also supports the separate
[native wire fixture](../../doc/runtime-wire-tests.md). Use its Python runner,
which supplies fresh state and the loopback route; do not reuse this device's
controller state for host mode.

This fixture expects the original `c6-memory14` controller's first node to be
commissioned already. It preserves that fabric and creates only its own four
additional controller environments. The private topology manifest permits
recovery after a failed test. Do not erase it or reuse it for another device.
On success, only the four fixture fabrics are removed, the durable label is
restored and exactly one fabric must remain. `cleanup` performs that recovery
without starting the load; `probe` runs a shorter supplied duration and cleans
its fabrics, leaving the runtime serving. Neither mode substitutes for the hour.

Both workloads use separate CASE sessions, three protected sessions/subscriptions
per fabric, full 133-attribute wire snapshots and simultaneous Reads across all
five fabrics. `wildcard` requests all 133 attributes in each Read. `bounded`
(the default if omitted) requests three concrete attributes per fabric and adds
one full Read every 30 seconds. Record the selected workload with each result.
DeviceLoadStatus confirms 15 total/3 accessing-fabric subscriptions.
The oracle rejects unexpected subscription closure and tests fourth-session BUSY.
Periodic tests inject tracked allocation faults, drop ingress briefly and force
live radio reconnect, then require full workload recovery. Explicit fault-window
operation failures/subscription loss are counted separately from healthy traffic.
The oracle detects retired SDK session handles, closes the remaining load and
re-establishes all 15 protected sessions/subscriptions when needed. Rebuilds and
interrupted operations are reported; they do not mean uninterrupted service.
An operation failure outside the explicit fault/recovery window fails the run.
During recovery only, CASE `BUSY` admission retries have a 90-second deadline
and two-second backoff, counted separately. Session closes are staggered across
fabrics; a best-effort wire close can be lost and old protected slots must drain.
Initial setup and the fourth-protected-session BUSY probe do not use that retry.

Local UART controls are available only in this build: `m` samples, `1`..`9`/`f`
arms one tracked allocation failure (expires after 10 s), `a` clears it, `d`
drops RX for 3 s, `w` forces Wi-Fi reconnect and `h` delays one accepted-send
completion for 3 s. These are laboratory effects, not network commands or
production behavior. Final `q` tests runtime retirement while that completion
is still held; no borrowed packet/port is freed before drain. The UART collector
serializes control requests and acknowledges actual target markers using an
append-only reply journal, avoiding Windows replacement/read sharing races.
SDK failed-allocation attempts are counted separately from injected tracked
allocation failures; a fallback allocation attempt is not automatically a failed
protocol operation. See the [Memory15 report](../../doc/oss/memory15-validation.md)
for measured workloads, failures and configuration boundaries.

After capture, `python tests/summarize.py <private-run-directory> <summary.json>`
extracts selected telemetry and counters. `runtime_pass` means target drain and
heap integrity, while `controller.pass` means the requested workload completed;
require both for a successful `run`. Review the summary before publishing it.

Memory21 adds two optional diagnostic profiles, both default off:
`MATTER_C_RUNTIME_HEAP_AUDIT` samples settled post-stop heap through5s and
prints paginated maps; `MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS` adds a bounded
128-entry SDK queue/libc-lock attribution table. The table changes layout, so
use it for attribution rather than comparing headline free-heap figures.
The owner profile also identifies pthread TLS list heads. Its optional
`MATTER_C_RUNTIME_HEAP_SMALL_OWNERS` subprofile traces allocation requests up to
32 B using 1024 records instead of 128, adding 12296 B BSS in the C6 builds.
It follows free and realloc identities and reports overflow; use it to identify
small persistent SDK islands, separately from normal-image RAM measurements.
The final profile also tags small lwIP pools, distinguishing timeout nodes from
other same-size objects. `MATTER_C_RUNTIME_HEAP_SETTLE_LONG` adds samples through
65 seconds and a second settled map after the original 5-second map. Both are
default off. UART `q` completion then includes that observation delay after
protocol drain; the existing SDK/network timer periods are unchanged.
Walk callbacks copy at most eight descriptors and never format/allocate under
the SDK heap lock. Maps expose stable/complete flags and never print contents.
The normal lab now calls lwIP's public owner-thread cleanup after its last
network operation and full drain. It does not delete global SDK locks.

`MATTER_C_RUNTIME_COMPARE_SAMPLER` instead enables the same SDK-timer heap
observer as the [external ESP-Matter reference](../esp-matter-memory/README.md).
This catches blocking-crypto peaks missed by owner-loop sampling. Both modes
include SDK/Wi-Fi allocations and dynamic stack reservations in internal8-bit
heap; static RAM and IRAM remain separate. Task watermarks are measured bytes;
the owner reservation now uses `ESP_TASK_MAIN_STACK`, including IDF's extra512 B
in these builds, rather than only the configuration value. See the historical
correction and measured limits in [Memory21](../../doc/oss/memory21-validation.md).

Decode completed post-stop maps offline with the exact diagnostic ELF:

```text
python examples/esp32-runtime/tests/heap_audit_decode.py --events <private-uart-dir>/events.jsonl --elf <diagnostic-build>/matter_c_runtime.elf --addr2line <idf-toolchain>/riscv32-esp-elf-addr2line.exe --source-root <isolated-source-root> --sdk-root <esp-idf-root> --output build/heap-audit/decoded.json
python examples/esp32-runtime/tests/heap_audit_decode_test.py
```

The decoder checks page counts, fingerprints, bounds, overlap and attribution
overflow. It reports settled deltas and allocations separating free spans in
each heap region. In the owner-attribution image it resolves recorded SDK callers
against that ELF; the operator must still verify the flashed binary/ELF pair.
Keep addresses/raw logs in ignored output. Do not infer that a separating SDK
mutex can safely be deleted, or compare attribution-image free heap directly
with normal-image measurements. [Memory36](../../doc/oss/memory36-validation.md)
records the Memory34/35 fault-teardown comparison.

For RX attribution, `tests/rx_trace.py` generates observer copies in an isolated
laboratory tree; it refuses to overwrite its input. For example, from the repo root:

```text
python examples/esp32-runtime/tests/rx_trace.py --source components/matter_c_esp32/matter_idf_udp.c --output build/rx-observer/source/components/matter_c_esp32/matter_idf_udp.c
python examples/esp32-runtime/tests/rx_trace.py --layer core --source main/apps/matter/transport/matter_rx.c --output build/rx-observer/source/main/apps/matter/transport/matter_rx.c
```

Copy the remaining project sources into that private tree before building it.
The UDP observer stores 32 per-adapter records and reports overflow explicitly.
The raw lwIP callback neither allocates nor prints; the owner copies one small
record under the core lock and prints after unlocking. `RX_DROP` contains a
microsecond timestamp, occupied/total slots, size, reason and an untrusted eight-byte
wire prefix (session/counter), never decrypted payloads. Reasons1–7 mean inactive,
non-IPv6, wrong interface, empty, oversize, extensions and no free slot. A prefix
alone does not identify an ACK; correlate it with a matching peer/dispatcher trace.
`--layer core` adds owner-only `RX_BLOCK` metadata for queued admission and ACK
backpressure. The collector records both formats. These profiles change memory
layout and timing; use a normal image for headline RAM measurements and retain
raw logs only in ignored output. They change no queue ceiling or protocol timeout.

## Fixed peak profile and allocation-site audit

With the same physical soak setup, a collector running and a private controller
state copied/backed up as above, set `MATTER_SOAK_MEMORY_PROFILE=1` and
`MATTER_SOAK_ATTRIBUTES=171`, then invoke the `run wildcard` controller. In
PowerShell, for an explicitly labelled diagnostic corrected-peer run:

```powershell
$env:MATTER_SOAK_MEMORY_PROFILE='1'
$env:MATTER_SOAK_ATTRIBUTES='171'
$env:MATTER_TEST_PEER_ROLE='corrected'
node examples/esp32-runtime/tests/soak.mjs <node_modules> <scoped-C6-IPv6> <private-controller-state> <private-uart-dir> 180 Wi-Fi run wildcard
Remove-Item Env:MATTER_SOAK_MEMORY_PROFILE, Env:MATTER_SOAK_ATTRIBUTES, Env:MATTER_TEST_PEER_ROLE
```

This is a fixed-operation profile; `180` does not define its duration. After
five fabrics/15 sessions/subscriptions, it performs three five-way full-Read
rounds, three disposable-fabric label publications concurrent with five Reads,
and four own-fabric removals with live load plus survivor Reads. It validates
remaining subscriptions after every step, then shares close/trim, original-
fabric cleanup and held-completion drain with the soak. It changes temporary
fabric labels and removes its four temporary fabrics; preserve the original
controller/NVS backup. It does not inject OOM/reconnect; use the ordinary timed
soak for that coverage. Without the profile variable, existing behavior remains.
Enable `MATTER_C_RUNTIME_COMPARE_SAMPLER` for whole-heap100ms timer observations;
retain owner samples, SDK watermark, free heap, largest block and stack watermark
as different metrics. See [Memory29](../../doc/oss/memory29-validation.md).

`tests/allocation_trace.py` generates an allocator observer in an isolated source
copy, refusing to overwrite the input:

```text
python examples/esp32-runtime/tests/allocation_trace.py --source components/matter_c/matter_idf_memory.c --output build/alloc-observer/source/components/matter_c/matter_idf_memory.c
```

Copy the remaining sources/configuration into that private tree before building.
In that copy declare `void matter_alloc_audit_dump(const char* phase);` and call
it on the owner after runtime creation, at selected `m` checkpoints, and with
`"complete"` after full drain. Do not call it from SDK/allocator callbacks. The
observer keeps2048 live records and128 call sites with explicit overflow; blocks
above65535bytes invalidate attribution while allocation semantics remain intact.
It snapshots all site byte/count totals at each new core-byte peak. Metadata
uses18956bytes on C6 and changes layout/timing, so measure headline heap on a
separate normal image. No allocation or formatting occurs inside the hooks.

Preserve the exact flashed ELF and its hash. The checked decoder fingerprints
that supplied ELF, resolves RISC-V return addresses, validates every dump's sums
and requires a zero-live `complete` dump. It rejects overflow, missing sites,
unresolved symbols and incomplete cleanup. Example from an IDF-enabled shell:

```text
python examples/esp32-runtime/tests/allocation_decode.py --log <private-uart-dir>/uart.log --elf <observer-build>/matter_c_runtime.elf --addr2line <idf-toolchain>/riscv32-esp-elf-addr2line.exe --source-root <isolated-source-root> --output build/alloc-observer/decoded.json
```

The operator must match the ELF to the flashed image; symbol resolution alone
cannot prove identity. The map reports simultaneous live allocations at the
core-byte peak, not the sum of independent per-site maxima. Keep raw logs and
state private. A passing protocol run with observer overflow is invalid for
attribution. Restore normal firmware/original fabric state, verify RGB/drain,
and release COM/AP after the diagnostic run.
