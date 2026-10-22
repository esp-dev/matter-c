# Memory21: settled heap, SDK attribution and a physical reference

Memory20 was committed as `230e815` (`Share Read and Subscribe encoding storage
per dispatcher`). Memory21 changes laboratory observation and final owner-thread
cleanup only. It does not change core APIs, protocol limits, storage format,
fail-safe, snapshot lifetime, MRP, ACK or drain. Detailed public measurements and
firmware/source fingerprints are in [results](memory21-results.json). Private
UART/controller/flash evidence stays in ignored local laboratory directories.

## Why the largest free block did not return

Waiting for SDK tasks is useful, but did not recover the largest block:

| C6 run | Immediate free | Free after about5s | Largest immediate / after5s |
| --- | ---: | ---: | ---: |
| idle01, heap walk only |390108|390128|245760 /245760|
| full01, loaded/recovered |390108|390104|172032 /172032|
| idle02, thread-resource probe |390108|390104|303104 /303104|
| idle03, queue attribution |388548|388568|245760 /245760|
| full02, loaded/recovered with attribution |388560|388568|245760 /245760|
| idle04, libc attribution |388540|388536|245760 /245760|
| idle05, final owner attribution |388520|388552|245760 /245760|

All sizes are bytes. Actual timestamps are retained for the approximately5s
settle and intermediate nominal20/100/500/2000ms samples.
The first prototype printed an immediate paginated map before early deadlines,
so its earliest nominal20ms sample was delayed by UART output; later variants
defer maps until after the timed samples. Do not interpret those prototype
timestamps as accurately20ms apart. Heap integrity passes and tracked core live
allocations/bytes are zero after teardown in every completed probe.

Small changes in total free bytes/block counts show some deferred SDK activity.
They do not explain holes of tens or hundreds of kilobytes. Stable paginated
heap walks identify92-byte allocated mutex blocks between the largest free
regions. Exact-ELF `addr2line` decoding attributes their first lock acquisition
to IDF6.1's `rmt_acquire_group_handle` (`esp_driver_rmt/src/rmt_common.c:31`)
and `esp_crypto_mpi_lock_acquire` (`esp_security/src/esp_crypto_lock.c:118`).
The final attribution probe repeats both identifications with zero metadata
overflows. In that probe, a92-byte RMT lock precedes a247376-byte free region,
and a92-byte MPI lock precedes a55252-byte free region.

Source inspection confirms both are SDK platform singleton locks initialized
on first use. Deleting an RMT channel/group frees the group, not its singleton
platform mutex; finishing MPI work releases its lock, not the lock allocation.
Their placement depends on the allocation/first-use sequence, so the same core
produced largest-block values172032,245760 and303104. Memory20's original188416
observation remains valid; there is no evidence of a retained core encoder
allocation. This is an explanation of persistent SDK placement and fragmentation,
not a claim that changing core allocation order cannot influence fragmentation.
No global SDK mutex is manually deleted.

The SDK largest-block API is quantized by TLSF free-list bins: the walk's247376
bytes can be reported as245760. Compare the same API across runs. Walk callbacks
copy only eight descriptors into a bounded page, never allocate/format while
the SDK heap lock is held. Pagination is not atomic across the entire heap;
fingerprints and complete/stable flags expose mutations and truncation.
The optional128-entry attribution table itself shifts RAM/layout (about1.5KiB),
so attribution builds are excluded from headline reference measurements.

## A real, small owner cleanup

The lab main task survives indefinitely after its last socket/netif operation.
Its lwIP per-thread semaphore and pthread TLS entry would otherwise remain until
thread exit. The supported `lwip_socket_thread_cleanup()` releases that owner's
resource after all networking, runtime retirement and hardware teardown.
Final normal RGB testing measures390144 ->390256 free bytes (**112 B**), with
largest block unchanged at245760, zero tracked allocations/bytes and passing
heap integrity. Diagnostic observations also generally recover112 B; one page/
cleanup interval includes an additional20 B SDK change and reports132 B net.
This is a teardown saving, not a reduction of the serving peak.

The final normal configuration has no extra timer or queue-attribution table.
RGB wire readback, subscription updates, concurrent transitions, off state and
drain pass. The primary fabric is retained. Optional settled maps and the common
timer observer default off; protocol timers are never shortened.

## Same workload on two physical C6 boards

COM23 runs the C RGB fixture with IDF6.1. COM24 runs an external copy of the
ESP-Matter release/v1.6.1 light with IDF6.0.2, which compiled and ran successfully;
IDF6.0.1 was not required for this pinned checkout. The reference commits are
recorded in the [reference instructions](../../examples/esp-matter-memory/README.md).
Original SDK checkouts on the VM remain clean. Both boards had full flash backups
before changes. The AP is TL-MR3020; Windows Wi-Fi IPv6 was confirmed enabled.

The stock light enables XY and color temperature, but not Hue/Saturation.
The copied example enables the existing HS feature and uses its existing GPIO8
WS2812 driver path. Other stock features remain, including Scenes, OTA and shell.
Three Wi-Fi IRAM placement options match the C lab; no pool/resource limit was
raised. The full wildcard inventories differ: **171 C /202 reference attributes**.
Thus this is a matched workload on two complete lab firmware configurations,
not a pure, feature-identical core-library benchmark.

Both execute the same seven explicit Read paths, one Hue subscription path,
five fabrics, three live CASE sessions/fabric and15 subscriptions. Each performs
105 Reads/735 returned values, six NodeLabel writes,18 RGB/OnOff/Level invokes,
ten additional CASE resumptions, and90 Hue reports. Each subscription observes
Hue85 and170; no unexpected subscription closures occur. Six rounds each wait5s
in addition to operation time. Final cleanup explicitly closes sessions, waits
12s, creates fresh CASE, requires four successful own-fabric removal responses,
restores the label, ends off and retains the primary fabric. Common workload
time: **178.98s C /92.15s reference**, including setup and cleanup.

The C fixture starts with its existing primary fabric; the reference's run starts
uncommissioned, provisions Wi-Fi over local UART and performs its initial PASE.
Multi-admin PASE/CASE then runs on both. Initial precommissioning numbers are
therefore not presented as a matched cold-start comparison.

Both use the same100ms observer from the SDK timer task. This fixes a measurement
blind spot: the old owner-loop sampler could not run during blocking crypto.
On this C run it reports227600 B peak, while the SDK-timer observer sees256136 B.
Sampling can still miss sub100ms peaks. SDK aggregate free-watermark values are
reported separately, since regional minima need not occur simultaneously.

| Metric, bytes | C RGB / IDF6.1 | ESP-Matter / IDF6.0.2 |
| --- | ---: | ---: |
| Linker static D/IRAM used |110493|179798|
| Linker Flash Code category |1228198|1762656|
| Timer-sampled allocated heap peak |256136|143016|
| Timer-sampled minimum free heap |163804|206396|
| SDK aggregate minimum free heap |163648|202400|
| Minimum sampled largest block |147456|184320|
| Free heap after loaded rounds |198856|236628|
| Free heap after restoring one fabric |230404|241016|
| Largest block after restoring one fabric |196608|192512|

The C profile uses69305 B less static D/IRAM, but leaves37772 B less free heap
after these small-path loaded rounds. There is substantial remaining potential;
the data does **not** show universal C-stack RAM superiority. Raw allocated-heap
peaks alone would omit the reference's larger static footprint. Free heap gives
the practical remaining budget for the rest of the application. Heap figures
include SDK/Wi-Fi/lwIP/crypto allocations and dynamically reserved task stacks in
the selected internal8-bit pool. Static data/IRAM and other capability pools are
separate. Do not add stack reservations to heap use a second time.

The benchmark images predate the final promotion of owner-thread cleanup into
the normal teardown path and the stack-reservation reporting correction. Those
changes affect final teardown/reporting, not serving allocations. Final normal
firmware, default, audit and component profiles are separately compiled/checked.

## Stack correction

Earlier telemetry printed `CONFIG_ESP_MAIN_TASK_STACK_SIZE` as the reservation.
Both pinned IDF versions actually use `ESP_TASK_MAIN_STACK`, adding512 B when
nano formatting is disabled, as here. The helper now reports the actual macro.
Earlier reported absolute owner-stack use was **512 B too low**; unchanged-task
before/after differences remain valid. For example Memory20's reported
2760 ->2636 becomes **3272 ->3148 B**, with actual reservation12800 B.
Original raw historical observations are retained rather than rewritten.

The matched C run's minimum free main stack is9512 B, so observed use is3288 /
12800 B. The reference's CHIP task is configured8192 B (dynamic FreeRTOS task,
directly passed without the main-task extra); minimum free is2276 B, observed use
5916 B. It also has main4096 B with2152 B minimum free, console, Wi-Fi, tcpip,
timer and event tasks; these observations are not a total-system worst-case stack
bound. All task watermark records are retained, including repeated console names.
Compiler frames for new C telemetry are48 B timer callback,160 B formatted
report, and240 B paginated map. C6 main reserves12800 B; the frame bounds are
checked alongside observed high watermarks, not substituted for them.

## Regressions, exploratory failures and limits

The full02 C-only wildcard regression completes506.41s overall /301.74s sustained,
with five fabrics/15 sessions/subscriptions,76 full Reads/12996 values, one
tracked allocation-fault cycle, RX loss, radio reconnect, reentry rejection and
held completion/drain. OOM retires one subscription and the oracle explicitly
rebuilds/verifies the full load. Healthy-operation errors, unexpected closures,
SDK allocation failures and final tracked allocations/bytes are zero.
This is not a matched OOM/loss/reconnect campaign of the external reference.

Exploratory failures are retained:

* The unmodified reference lacks HS attributes; its first seven-path Read was
  incomplete. HS was explicitly enabled in the copied model.
* Seven subscription paths times15 exceeded the reference's stock shared path
  budget and returned `PathsExhausted` during third-fabric setup. Limits were
  preserved; the final common workload uses one subscription path on both.
* Immediate RGB readback preceded the reference's asynchronous update callback.
  Final tests poll for exact values for at most2s (six polls needed in the
  reference run, zero in C), without changing device/protocol timers.
* The initial C cleanup removed a fabric but timed out waiting for its response
  with multiple sessions still live. Final cleanup follows the existing soak's
  explicit session close/drain/fresh-CASE procedure and requires responses.
  Direct self-removal under fully live three-session load remains an unresolved
  test finding; the successful final fixture is not evidence that this edge
  case is fixed.

Windows CTest passes102/102. The existing native VM chip-tool two-instance
scenario passes six assertion groups in17.50s, with unchanged protocol timers.
No core host source changed here; Memory20's separate Linux Memcheck and
ASan/UBSan/LSan evidence remains historical, not a newly rerun Memory21 campaign.
New IDF profiles compile; no C/C++ compiler warnings were found in their logs.
Upstream Kconfig notices remain, and the reference emits an app-partition warning
with5% space left. No claim of a warning-free SDK build or full certification.
The reference collector's final partial-line redaction hardening is checked
with a synthetic UART fixture that splits a credential across serial timeouts.

Representative executed entry points (private arguments omitted):

```text
ctest --test-dir build/memory16/windows-gcc --output-on-failure
python tools/matter/check_test_map.py
node --check examples/esp-matter-memory/compare.mjs
python -m py_compile <both UART collectors> <reference preparation tool>
idf-v6.1.ps1 -C examples/esp32-runtime -B <RGB/default/audit/compare> build
idf-v6.1.ps1 -C examples/esp32-memory -B <component-profile> build
idf.py -B <VM reference build> -D IDF_TARGET=esp32c6 build
python -m esp_idf_size --format json2 <both maps>
addr2line -pfiaC -e <exact attribution ELF> <recorded hexadecimal PCs>
node examples/esp-matter-memory/compare.mjs <private matched arguments>
node examples/esp32-runtime/tests/soak.mjs <private wildcard fault arguments>
node examples/esp32-runtime/tests/rgb.mjs <private normal-image arguments>
```

## Files and purpose

| Files | Purpose |
| --- | --- |
| ESP runtime app_main.c / Kconfig / CMake | Optional diagnostic checkpoints, observers and link wrappers; normal owner cleanup |
| heap_audit.h / heap_queue_owners.c,h | Bounded SDK maps and lock attribution without formatting/allocation under SDK locks |
| esp32-common/matter_lab_heap_sample.h | Identical C/C++ timer sampling algorithm |
| esp32-common/matter_lab_memory.h | Report actual IDF owner-stack reservation |
| Both UART collectors | Private structured evidence and serialized checkpoint controls; reference credential redaction |
| esp-matter-memory/reference_memory.h / compare.mjs / README | External observation, common independent wire oracle and reproducibility |
| prepare_esp_memory_reference.py | Copy pinned upstream example without changing SDK checkouts |
| Reports, README/status/test map | Honest scope, measurements, historical stack correction and regression strategy |

No official CSA case was rerun. See the [regression strategy](memory-regression-strategy.md)
for fast chip-tool coverage versus applicable CSA automation and formal processes.
At completion both serial collectors are closed. COM23 contains the normal RGB
image with diagnostic observers off, corrected stack reporting and one retained
primary fabric; its explicit stop/drain completed. COM24 retains the reference
light and its primary lab fabric. Windows returned to its original disconnected
Wi-Fi state, the temporary profile/XML were removed, and IPv6 remains enabled.
Next: diagnose live multi-session own-fabric response retirement, then profile
the persistent constructed/runtime-started allocation split before choosing the
next peak-reduction change. Early SDK first-use placement can be studied at the
application boundary, without deleting globals or changing protocol limits.
