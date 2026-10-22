# Memory26: C6 startup 14/15, UART 1M and ACK role tracing

Validation: 23 October 2026, local time. Memory25 is committed as `ac187cc`.
Production sources under `main/apps/matter`, resource ceilings, protocol timers,
snapshot ownership and ACK/drain rules are unchanged.

## Finding and its limits

Three startup replays without injected network faults pass 15/15, including a capture with
only failure/session logging and the original Memory23 NVS backup. The original
incident has no packet-level trace, so its initiating loss/delay cannot be proven
retroactively. These successful replays alone do not prove absence of a regression.

The controlled comparison identifies a concrete sensitivity of the pinned
Matter.js 0.17.9 test controller: after it has closed the initiating exchange,
its fallback ACK for a retransmitted SubscribeResponse has the wrong Initiator
flag. One deliberately ignored authenticated ACK is sufficient to obtain 14/15.
Our MRP correctly retains the original session/exchange/local-role/counter key,
does not accept the subsequent opposite-role ACKs, exhausts five attempts and
closes that subscription. Existing CASE sessions remain usable.

Changing only that fallback role in an isolated copy of the controller restores
15/15 under the same single-ACK fault. Both sides of the matched comparison use
the **same C6 firmware binary** and the same saved five-fabric state. The original
pinned modules are unchanged. This is a laboratory attribution experiment,
not a shipped SDK update or a relaxation of our ACK matching.

The relevant local dependency is
`@matter/protocol/dist/esm/protocol/MessageExchange.js`:

```diff
 static fromInitialMessage(context, initialMessage, options) {
   ...
-  isInitiator: false,
+  isInitiator: !initialMessage.payloadHeader.isInitiatorMessage,
   ...
 }
```

`ExchangeManager` uses this factory for an unsolicited reliable response after
the original exchange has gone. The source always selects responder in the
unmodified package; the packet trace independently shows the resulting role.
No claim is made about other Matter.js versions. The dispatcher source is
identical at Memory22 `13ffe87`, Memory23 `26ee0fd`, Memory24 `43fbd7c` and
Memory25 `ac187cc` (LF SHA256 in the results). This peer failure mechanism does
not depend on the Fabric image/TLV memory changes.

## Trace evidence

In the first effective cold negative control, subscription 5 belongs to actual
fabric 64, session token 4294967299, exchange 28824, response counter 72168179.
Only its first correctly addressed ACK is suppressed, after authentication and
before MRP accounting. It models a missing ACK at that boundary, not an RF jammer.

| C6 owner time, ms | Event |
|---:|---|
|141914 | SubscribeResponse queued and submitted; local role 0 |
|141993 | First matching ACK selected and deliberately suppressed |
|142293,142653,143334,144473 | Retransmit the same retained ciphertext/counter |
|142373,142703,143403 | ACK received for opposite local role 1; no matching transaction |
|145893 | MRP timeout after five attempts; subscription closes |

The controller logs four fallback ACK transmissions. Three are observed at the
C6 ACK callback with the opposite role. An ACK callback result of `MATTER_OK`
can be a no-op for an unknown key; it is not proof of delivery. Match the
counter and terminal `MRP_END=ACKNOWLEDGED`. Packet retries never create a new
ciphertext/counter, and cancellation still waits for actual UDP completion.

The matched single-ACK experiment's terminal outcomes are:

| Peer / exactly one ACK suppressed | TX attempts | Terminal MRP | Current subscriptions |
|---|---|---|---|
| Original Matter.js 0.17.9 | 5 | TIMEOUT | 14/15 |
| Private role correction | 2 | ACKNOWLEDGED | 15/15 |

All fifteen initial 171-attribute subscription snapshots complete in each
effective negative control. Full new-load Read/Subscribe acceptance is therefore
different from subsequent MRP survival. Five concrete Reads, one per fabric,
also succeed after the selected subscription times out; the target uses its
existing CASE session. The corrected-peer trial preserves all fifteen instead.

## Interpreting the historical counters

`totalSubscriptionsEstablished=16` includes the earlier RGB subscription and
fifteen new local SubscribeResponse TX completions. `count_sent()` increments
this value before peer MRP acknowledgement. `currentSubscriptions=14` excludes
closing/retiring/dead-fabric entries, so a later failed subscription can lower
the current count while the cumulative count remains 16. This does not indicate
that the fifteenth admission was refused.

The accessing fabric's count 3 can remain unchanged when the lost subscription
belongs to another fabric. The historical 548/544 values count admitted/sent IM
messages, not all UDP packets or Secure Channel standalone ACKs. Their difference
cannot by itself count lost ACKs. `matter_rx_im_received()` excludes duplicate IM
messages; successful retransmissions are counted once on TX.

This explains and reproduces the signature and the peer's failure to recover
after one missing ACK. It does **not** prove which event lost or delayed the
first ACK in the original uninstrumented Memory23 run.

## Executed C6 validation

Board: ESP32-C6-DevKitM-1, COM23, native Windows ESP-IDF 6.1, TL-MR3020,
Windows Wi-Fi IPv6 enabled, independent Matter.js 0.17.9 on Node 24.22.0.
COM24 is untouched. Each capture starts with the RGB oracle, including concurrent
transitions and a 171-attribute model readback. The startup oracle then checks
five fabrics, fifteen CASE sessions and fifteen full subscriptions, immediately
and after another six seconds. These are short startup probes, not a new hour soak.

| Capture | Instrumentation / peer | Initial / settled live count | Controller seconds |
|---|---|---|---:|
| `trace04` | Full trace, original peer INFO | 15 / 15 | 146.48 |
| `trace05` | Full trace, original peer DEBUG | 15 / 15 | 145.98 |
| `quiet01` | Failures only, original Memory23 NVS | 15 / 15 | 142.27 |
| `negative02` | Cold ACK control, actual other fabric selected | 14 / 14 | 149.21 |
| `single-old` | Preloaded five fabrics, single ACK loss, original peer | 14 / 14 | 92.07 |
| `single-fixed` | Identical firmware/state, corrected peer | 15 / 15 | 92.34 |

The first three and effective cold control use the existing initial-load sequence
that commissions four additional fabrics. The matched old/corrected-peer pair
restores a saved five-fabric NVS/controller snapshot, avoiding those four
commissioning operations. State and firmware are identical within that pair;
do not treat their elapsed times as cold commissioning measurements.

C6 preflight passes include IPv6 bounds, atomic NVS/model publication failures,
discovery/advertisement OOM, UDP simultaneous RX/TX fairness, bounded FIFO growth
OOM/order/idle trim, interface-index restart and runtime callback reentrancy.
The full constructor OOM sweep is cached as revision 2 in these NVS snapshots and
was **not rerun**; current native `test_runtime_alloc` is rerun separately.
The 13 tracked failures in C6 telemetry belong to deliberate boot probes and do
not increase during healthy startup. No SDK allocation failure is observed.
Adapter drops and MRP retransmissions are observed while the healthy load checks
pass; zero-drop networking is not claimed. No malformed application trace record is observed. The complete
second full capture has 6052 raw/parsed trace records with no parser errors.

## Memory and stack

| Healthy capture | Sampled allocated peak B | Sampled minimum free B | SDK minimum free B | Sampled minimum largest block B | Owner maximum observed used B |
|---|---:|---:|---:|---:|---:|
| `trace04` | 273496 | 145512 | 141676 | 126976 | 3160 |
| `trace05` | 273580 | 145420 | 141684 | 126976 | 3288 |
| `quiet01` | 273488 | 145520 | 141724 | 126976 | 3176 |

These are instrumented startup workloads, not memory savings or a worst-case
specification bound. The 100 ms owner sampler can miss blocking-phase peaks;
the SDK aggregate minimum is reported separately. Internal 8-bit heap includes
SDK/Wi-Fi/lwIP/mDNS and heap-backed task stacks, including unused stack space.
It excludes static data/IRAM and other capability pools. Core peak is requested
payload tracked by our allocator. Do not add reserved stacks again to whole-heap
use. The owner reserves 12800 B; its measured high-water mark is not a static
proof for every path. Full-trace helper's own static GCC frame is 128 B, before
the called printf/driver frames. Quiet logging keeps the same transaction layout.

Every completed capture reaches zero tracked live allocations/bytes after
runtime stop/delete. Largest-free-block values after teardown vary with SDK
allocation placement; that variation alone is not a leak.

## Implementation and reproducibility

| Files | Why changed |
|---|---|
| `examples/esp32-runtime/sdkconfig.uart-1m` | Explicit custom UART0 on DevKitM-1 GPIO16/17 at 1000000 baud |
| `examples/esp32-runtime/tests/dispatch_trace.py` | Generate a separate metadata-only dispatcher, optional failure-only capture; source patterns and SHA256 checked |
| `examples/esp32-runtime/tests/uart_capture.py` | Preserve trace metadata as structured records and identify malformed trace lines |
| Example README | Exact configuration, decoder fields and timing/stack limitations |
| Root README, OSS status, this report/results | Findings, measurements, verification and open historical attribution |

No trace or ACK fault hook is linked into final normal firmware. The ACK fault
and peer patch exist only in ignored test copies. Source/capture/firmware hashes,
counts and memory values are in `memory26-results.json`; raw UART, controller
logs, generated sources, commands and private state remain in ignored
`build/memory26` and `local/esp32-c6`.

Executed commands include native `idf-v6.1.ps1 ... build`, esptool read-flash and
verified write-flash, `dispatch_trace.py --source ... --output ...` with and
without `--failures-only`, the collector with `--baud 1000000`, RGB and initial
load oracles, Python syntax checks and test-map inventory. Generated full/quiet
sources match the corresponding compiled captures after LF normalization.

The current focused native CTest invocation is:

```text
ctest --test-dir build/memory16/windows-gcc -R '^test_(ack|ack_sender|retransmission|retransmission_sender|dispatch|runtime|runtime_alloc)$' --output-on-failure
```

It passes 7/7. Inventory passes 265 mapped files/99 native definitions/75 public
headers. C6 builds succeed; no new C warning is observed. ESP-IDF's existing
CMake include-export warnings and Kconfig deprecation notices remain. No
host-target/core changes were made, so Memory25's full Linux Memcheck and separate
sanitizer results are retained as prior evidence, not claimed as new executions.

## Setup failures retained and cleanup

One initial capture used 1M against an app regenerated to 115200 and was stopped
before any controller test. Two further pre-flash assertions rejected regenerated
115200 configurations. ESP-IDF 6.1 `# default:` markers caused edited defaults to
be reselected; explicit custom-UART settings with that marker removed retain 1M.
The final generated header and physical application logs/controls verify 1M.
ROM and the unchanged older bootloader still emit 115200 at startup.

The first attempted ACK control selected numerical fabric 2, but persisted fabric
indices are 64–67. No ACK was suppressed; the strict expected 14 oracle correctly
failed on 15/15. That attempt is retained as `negative01`, not counted as a passing
negative control. Selection now follows the observed primary/other fabric roles.

A fresh pre-test NVS backup is restored, followed by the **normal image without
TRACE26 or ACK-suppression code at 1,000,000 baud**. RGB wire tests pass again; owner telemetry
confirms exactly one original fabric, no SDK allocation failures and final zero
tracked live allocations/bytes. Final internal free heap is 390220 B,
largest block 221184 B. The image/ELF contain no trace markers/helpers.
COM23 is released; runtime/Wi-Fi stop completes. The temporary Windows Wi-Fi
connection, profile and private profile XML are removed. Windows IPv6 remains
enabled, COM24 is untouched, and TL-MR3020 configuration is unchanged/free.

## Limits and next task

No spontaneous 14/15 is captured, and no original first-ACK loss is attributed
retroactively. UART logging can perturb timing even at 1M. No new full sustained
soak, exhaustive OOM campaign, official CSA, phone-app pairing or certification
claim is made. The private peer correction was tested in this unicast laboratory
scenario, not qualified as a general SDK release.

Next: promote the single-lost-ACK old/corrected-peer comparison into the native
wire regression, explicitly labelling the peer patch and retaining strict
rejection of wrong-role ACKs. That supplies fast coverage before further RAM work.
