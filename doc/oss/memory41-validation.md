# Memory41: application headroom and lifecycle comparison

Optimization is closed at **Memory40 / f366c2c**. This stage changes comparison
tools and documentation only: all 162 files under `main/` match the frozen
Memory40 sources, and the C SDK configuration's complete normalized setting map
is unchanged. Regression and CSA campaigns running separately are not results of
this stage. [Sanitized measurements and provenance](memory41-results.json).

The practical result depends on whether Matter is running. With the same common
workload and a retained **65536-byte application allocation**, Wi-Fi-only CHIP
leaves **43912 B more minimum SDK free heap**. With no runtime instance, C leaves
**23876 B more current free heap**; after deletion and releasing that application
allocation, C leaves **38036 B more**. A smaller active footprint is therefore not
a universal advantage of this C implementation. Its instance lifecycle returns
memory for other work while the SDK network remains available.

## Devices, scope and measurement

Two ESP32-C6FH4 revision v0.0 boards, embedded 4 MiB flash, TL-MR3020 and the same
Windows IPv6 interface. COM23 uses the exact normal Memory40 binary and IDF6.1;
COM24 uses pinned ESP-Matter1.6.1/ConnectedHomeIP and IDF6.0.2. No SDK version was
changed. The pre-test full flash backups exactly match the recorded normal app
binaries. Original SDK checkouts stay clean; VM builds use separate projects.

Both perform five fabrics, three CASE sessions/fabric, fifteen one-Hue-path
subscriptions, 105 seven-path Reads /735 returned values, six NodeLabel writes,
18 RGB/OnOff/Level commands, ten additional CASE resumptions, 90 Hue reports,
four acknowledged own-fabric removals and restoration of the primary fabric.
The controller requires every subscription to observe Hue85 and170, without
unexpected closures. The identical workload is the one documented in the
[reference laboratory](../../examples/esp-matter-memory/README.md).

This compares complete lab firmware, **not two feature-identical certified
lights**. Inventories remain171 C /202 CHIP attributes. The reference retains
XY/temperature, Scenes, OTA and shell; the C RGB fixture remains incomplete.
C retains52 transaction slots, while reference exchange contexts remain8.
All resource ceilings are preserved. Wi-Fi buffers remain10/32/32 and the three
Wi-Fi IRAM-placement optimizations stay disabled on both sides. C keeps software
ECC, reference hardware ECC; no byte saving is assigned to that difference.

Internal `MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT` free heap includes Wi-Fi, lwIP,
crypto, NVS, drivers and heap-backed task stack reservations. Do not add those
stacks again. Static D/IRAM limits the available pool but is not part of the
dynamic allocated-heap counter. All sizes below are **bytes**; KiB means1024 B.

Both SDK timer observers sample every100ms independently of the Matter task;
shorter troughs may be missed. **SDK minimum free is the aggregate of regional
minima**, which need not occur together. It is reported separately from sampled
simultaneous free heap and is not an exact specification-wide worst case.

## Normal images, no application reservation

Two repeats/stack, original normal firmware. The reference has BLE compiled and
reports BLE deinitialization before the common workload. All four runs pass.

| Metric | C repeat1 /repeat2 | Standard CHIP repeat1 /repeat2 |
|---|---:|---:|
| Minimum SDK free |186672 /194340|206600 /206708|
| Minimum sampled free |187108 /196296|207836 /209464|
| Minimum sampled largest block |167936 /180224|188416 /188416|
| Free after loaded rounds |218048 /218084|236236 /236320|

The conservative observed SDK-counter gap is19928 B; steady loaded gap is about
18 KiB. The C minimum varies across repeats, so these are observations, not a
stable exact delta. Normal C initial one-fabric free heap is about251.6 kB versus
243.5 kB for this standard reference. That ordering must not be generalized to
the Wi-Fi-only configuration below.

## Identical 64 KiB application-budget experiment

Generated copies add lifecycle observation and retain a pattern-filled65536 B
allocation from before Matter creation through the entire workload and shutdown.
Every byte is checked before free. This is a concrete retained application
budget, **not an MQTT/HTTP/TLS measurement**. Reported free heap is additional
space beyond that occupied allocation, including allocator overhead.

The Wi-Fi-only reference disables `CONFIG_ENABLE_CHIPOBLE` and `CONFIG_BT_ENABLED`
with dependent Kconfig changes. Its Matter max/pool limits, hardware ECC and Wi-Fi
buffer settings remain unchanged. The only changed non-Bluetooth key is the
dependent UART hardware-flow-control compatibility switch. On-network PASE/CASE
and the complete common workload pass without BLE. One run/profile:

| Metric, application already holds65536 B | C | Standard CHIP | Wi-Fi-only CHIP |
|---|---:|---:|---:|
| Minimum SDK free |125396|141000|169308|
| Minimum sampled free |129684|143848|172160|
| Minimum sampled largest block |100352|122880|151552|
| Free after loaded rounds |152500|170728|198952|

Against Wi-Fi-only CHIP this leaves **122.5 versus165.3 KiB** at the lowest SDK
counter, and98 versus148 KiB at the minimum sampled largest block. Both carry
the additional64 KiB successfully; C has zero SDK allocation failures. There is
no equivalent SDK failure-counter hook in the reference; its successful protocol
oracle and reservation checks are not relabelled as such a counter.

Normal-image and reservation experiments must stay separate. In particular,
subtracting65536 B from a different run cannot establish a measured new minimum:
allocation order, crypto, SDK activity and placement vary. The Wi-Fi-only
reference was not additionally measured as a normal no-reservation image.

For application sizing, Memory40's **different, heavier C-only wildcard profile**
still reached88356 B SDK minimum free. It includes fifteen wildcard subscriptions
and overlapping full Reads/Fabric publications. It is not comparable to this
one-Hue-path subscription profile and is not a demonstrated64 KiB coexistence
test. Actual MQTT/TLS handshakes, HTTP connections and combined worst load need
measurement after integration; plain free heap alone cannot establish their cost.

## Instance absent, Wi-Fi still connected

The C probe uses its existing Wi-Fi bootstrap and retains the1592-byte lab App
scaffold. The reference initializes SDK Wi-Fi from its saved configuration before
creating the node or starting CHIP. Both wait65s with no runtime instance, then
create Matter and execute the workload. This also physically demonstrates
application-provisioned Wi-Fi before ESP-Matter startup; WPS itself was not tested.

After controller cleanup, C follows its existing stop/drain/delete sequence,
removes its owned discovery/transport/model/crypto/storage adapters and LED driver,
asserts zero tracked core objects/bytes, and retains Wi-Fi/netif/NVS for65s.
The reference destroys its model, calls `Server::Shutdown()`, stops and joins the
CHIP task, removes its IP/Wi-Fi event forwarding and shuts down PlatformManager.
Its CHIP task is absent from the subsequent task inventory. SDK tasks remain.
Both answer three external IPv6 pings after Matter shutdown.

| State | C | Standard CHIP | Wi-Fi-only CHIP |
|---|---:|---:|---:|
| Never created: current free after65s |331988|279908|308112|
| Never created: local SDK minimum /65s |329808|277736|305940|
| Never created: largest after65s |311296|262144|286720|
| Deleted,64 KiB still occupied: free after65s |266376|200004|228348|
| Deleted,64 KiB still occupied: local SDK minimum /65s |264012|197652|225996|
| After releasing64 KiB: current free after5s |331940|265560|293904|
| After releasing64 KiB: largest after5s |139264|139264|180224|

Never-created and deleted-with-reservation windows use the SDK's **local**
minimum monitoring API. After releasing the reservation its minimum counter
returns to workload history; those historical values in JSON must not be read
as a new inactive-window minimum. The final unreserved rows are0/5s checkpoints,
not a further65-second minimum campaign.

The C total free heap returns within48 B of its pre-instance observation, while
its largest block falls311296 ->139264 B on this allocation trace. This is a
placement/fragmentation limitation despite zero tracked core allocations. No
new heap-map attribution identifies which SDK objects separate the free regions.
The reservation itself also affects placement. Free total and largest block are
different application constraints; neither guarantees an arbitrary large buffer.

The C library's per-instance lifetime does not remove its firmware's static RAM,
SDK Wi-Fi or the application task. Conversely, CHIP can be shut down: this
experiment does not support the claim that it is impossible. Its path needs
several low-level operations, an actual task-exit barrier and ownership of SDK
event registrations. Static singleton/pool storage and some global setup remain.
ESP-Matter's `start()` guards its persistent `esp_matter_started` flag, which these
shutdown APIs do not reset; a complete public-wrapper restart was not tested.
Do not present this one-way experiment as a production stop/restart API or a
shutdown test with arbitrary outstanding TX, callbacks or other SDK consumers.

## Instrumentation, failures and validation

The standard lifecycle observers add24 B linker D/IRAM to each normal image:
C110493 ->110517; CHIP179798 ->179822. Wi-Fi-only CHIP is151760 B including its
observer. This removes28062 B versus the standard reference, without changing
Matter limits. Flash-code categories are retained in JSON. C normal and isolated
observer figures are never mixed as one matched image run.

The explicitly selected corrected test peer is the existing Memory26/27
Matter.js0.17.9 role helper, with its package-source hash checked. No package,
device timer, retransmission policy or runtime code is patched. Original-peer
exploration admitted15 reference subscriptions, then timed out after19 Reads;
it is excluded, and its cause is not established. Both normal repeats and all
reservation workloads use the same corrected peer and pass105 Reads,735 values,
15 subscriptions,90 reports and four fabric-removal responses each.

The **first shutdown observer lacked a verified task-exit barrier**. Its common
workload passed but FreeRTOS asserted in `xQueueGenericSend` after platform
teardown, and the board reset. Decoding the exact ELF also places the event-loop
task in the captured stack. `StopEventLoopTask()` requests exit asynchronously;
the corrected observer waits for the fixture's unique CHIP-named task to leave
before deleting queues/locks. Both standard and Wi-Fi-only repeats then finish
the full65-second Wi-Fi-up observation and ping checks. This is an observer
repair, not a change to upstream CHIP or a Memory40 regression.

Other retained exploratory failures: sandbox WinError623 when starting Windows
toolchains (same tools build outside it); two private final-probe helper mistakes
(missing controller label and a non-void argument for a void command), corrected
before successful final CASE/OnOff/readback; one SSH timeout after WLAN cleanup,
followed by successful ping and SSH. No cause is assigned to that transient.

Executed commands include `node --check .../compare.mjs`, `python -m py_compile
.../prepare_memory_comparison.py`, both generator kinds, IDF builds, normal and
reserved `compare.mjs` runs, `ping -6`, ELF/map size analysis and source/config
comparisons. Final observer builds after the user's request use
`IDF_PY_BUILD_JOBS=1`, `CMAKE_BUILD_PARALLEL_LEVEL=1` and a private Ninja `-j1`
wrapper; builds are serialized, including CHIP's nested Ninja. Earlier setup
builds precede that request. No compiler diagnostic is reported for the new C
observer's final build. Native core/CSA suites are not rerun or claimed here:
their source is unchanged, and the separate campaigns remain separate.

Original full flash images/primary fabrics are restored on both boards. Normal
Memory40 passes nine RGB updates/transitions and zero-live drain on COM23;
original standard reference passes CASE, one-fabric and OnOff/readback on COM24.
Collectors are stopped, ports/AP released, temporary WLAN profile/XML removed,
IPv6 remains enabled and VM is reachable. WLAN events verify that disconnected
Wi-Fi was the pre-test Windows state. No private keys, state, backups or AP
credentials are included in this report or its sanitized JSON.

| Changed file | Purpose |
|---|---|
| `examples/esp32-common/matter_lab_lifecycle.h` | Shared heap windows, retained application budget and data-integrity check |
| `examples/esp-matter-memory/reference_lifecycle.h` | Isolated external Wi-Fi bootstrap and checked one-way CHIP retirement |
| `tools/matter/prepare_memory_comparison.py` | Generate new copies; preserve normal runtime and SDK sources |
| `examples/esp-matter-memory/compare.mjs` | Optional explicit existing diagnostic peer, default behavior preserved |
| `examples/esp-matter-memory/README.md` | Reproduction, single-job builds, measurement/lifecycle constraints |
| `README.md`, `status.md`, this report/results | Close optimization at Memory40 and record measured application budgets |

Next: define the minimum required Wi-Fi RGB-light device type/features and audit
its mandatory clusters, then implement onboarding QR and the chosen recovery
gesture. The five-boot/five-second gesture is a proposed product policy, not a
claimed Matter requirement or an implemented feature of this measurement stage.
