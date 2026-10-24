# Memory24: host isolation of subscription startup

Date: 2026-10-22. This is an investigation, not another memory optimization.
The original C6 Memory23 result of14 live subscriptions after15 successful full
initial snapshots remains an open finding. No portable production code, resource
limit, timeout, storage format or ACK/drain policy was changed in this campaign.
The pending Memory23 changes were preserved without committing them.

## Host comparison

A private native Windows fixture runs the real callback-driven runtime, RGB
model, storage publication, PASE/CASE, MRP and UDP/IPv6 on loopback. An independent
Matter.js0.17.9 controller creates five fabrics, three CASE sessions per fabric
and fifteen full subscriptions, each containing171 attributes. Every run uses
fresh, separate device/controller state. No physical device state is reused.

Memory22 is commit `13ffe87`. Its runtime/storage objects were compiled from
an exact Git export and linked ahead of the common static libraries. Memory23
uses the current pending implementation. The dispatcher and Subscribe model are
byte-identical between the two source versions. Private diagnostic copies of the
dispatcher log subscription establishment, closing, MRP failure and session
retirement; the same instrumentation is used in both versions.

| Schedule / workload | Memory22 | Memory23 |
|---|---|---|
| Owner sleep10ms, immediate local TX completion |15/15 |15/15 |
| Owner sleep10ms, local TX completion delayed25ms |15/15 |15/15 |
| Same delay, UDP polled after runtime, prior RGB subscription and disconnect |15/15 |15/15 |
| Same setup, concurrent full Read, Write and own-fabric removal | Pass | Pass |

The last two rows also notify runtime about RGB generation changes, as the C6
application does. The prior one-path RGB subscription raises lifetime established
subscriptions to16, matching that detail of the original C6 workload. Its deliberate
disconnect is distinguished from an unexpected full-load closure.

In the active workload, each version completes25 further full Reads (4275
attribute reports), retains all15 subscriptions, rejects a fourth protected CASE
on the first fabric, and receives all four own-fabric RemoveFabric responses.
The final diagnostic count is3 subscriptions on the surviving original fabric.
No unexpected subscription closure or healthy-operation error is accepted.
Accepted socket sends, deferred completion and runtime stop are drained before
deleting the fixture. These tests do not increase the existing limits.

## Missing-ACK control

A separate diagnostic build intercepts authenticated ACK processing for the
SubscribeResponse of subscription5 (the first full subscription on the second
fabric, after the RGB warmup). It leaves the production implementation untouched.
In both versions, the ignored ACK is logged at26453ms. MRP reaches its existing
timeout at30922ms in Memory22 and30750ms in Memory23; dispatcher confirmation then
closes that subscription. The session is not evicted to make room for another.

Both controllers still complete all15 initial full snapshots. The unmodified
load requirements then fail with14 current subscriptions,3 on the querying
fabric and16 lifetime established subscriptions. Thus the verifier detects the
injected failure instead of silently repairing it. Both fixtures subsequently
drain and delete successfully. These are two expected negative controls, not
two passing healthy workloads or a reproduction of the original physical cause.

This demonstrates that a missing SubscribeResponse ACK can produce the same
subscription-count signature in both versions. It does not prove packet loss on
the C6, explain the original difference in IM sent/received counters, or rule out
another timeout/ordering problem. The original C6 run has no per-subscription
close-reason trace, so that attribution cannot be made retrospectively.

The diagnostic fixture supplies a known loopback operational route to the
controller. It does not exercise mDNS discovery, the Wi-Fi driver, lwIP, NVS,
FreeRTOS scheduling, UART blocking or C6 heap fragmentation. Its simulated Wi-Fi
callbacks are application ports, not a physical radio. Host pointer sizes and
allocator behavior cannot replace the previous C6 memory measurements.

## Validation and reproducibility

The incremental native build succeeds; CTest passes102/102 with local socket
access. This includes dispatcher ACK/drain tests and the existing allocation-fault
tests for runtime, Store, Read/Subscribe, RX and other components. The new wire
workload does not inject allocation faults: its OOM coverage must not be confused
with those unit/component tests. Linux Memcheck/sanitizer results remain the
separate Memory23 evidence; they were not rerun for this documentation/UART change.

Commands executed from the repository root include:

```text
cmake --build build/memory16/windows-gcc -j 3
ctest --test-dir build/memory16/windows-gcc --output-on-failure
python build/memory24/build_host.py
python build/memory24/run_host.py host22-active 0 22
python build/memory24/run_host.py host23-active 0 23
python examples/esp32-runtime/tests/uart_capture.py --help
```

For the active comparison, environment variables are `MATTER_TICK_MS=10`,
`MATTER_COMPLETION_MS=25`, `MATTER_POLL_AFTER=1`, `MATTER_WARMUP=1`, and
`MATTER_ACTIVE_MS=20000`. The requested active window is separate from commissioning,
startup and controller shutdown. The private runner supplies171 expected
attributes and the pinned controller modules. Compiler commands, private generated
fixtures, per-run command/environment files, controller summaries and traces are
retained under ignored `build/memory24`; these are investigation artifacts, not an
installed host application or an automatic CTest wire case.
The eight healthy comparisons are listed separately from the two intentional
missing-ACK failures in the JSON. End-to-end elapsed times include controller
shutdown, which varied from about81 to126 seconds in the active comparison;
its workload acceptance itself completed in about77–78 seconds. This is not a
benchmark of CPU speed or a promised maximum test duration.

## UART and hardware scope

The UART collector now accepts `--baud 1000000`, validates a positive rate, and
keeps its115200 default for existing images. Help and rejection of `--baud 0`
were executed without opening a port. Its README explains the matching
`CONFIG_ESP_CONSOLE_UART_BAUDRATE=1000000` image setting and the separate flashing
baud. No new C6 image was built/flashed and no1Mbaud capture was physically
verified in this host-first campaign. COM23, COM24 and the access point were not
used. No new whole-device heap, stack or fragmentation measurement is claimed.

## Conclusion and next step

The healthy host comparisons have not reproduced the original C6 startup failure.
This narrows the investigation but does not establish that Memory23 is free of a
timing-sensitive regression. Keep the host fixture for fast ACK/order/OOM work;
the remaining C6 check needs the same per-subscription MRP/close/session traces
to identify the actual reason for the missing subscription. Do not change limits
or silently rebuild a lost subscription to make the original acceptance pass.

The machine-readable measurements accompany this report in
`memory24-results.json`. No new CSA or phone-app acceptance is claimed.

## Files changed in this investigation

| Files | Reason |
|---|---|
| `examples/esp32-runtime/tests/uart_capture.py` | Select UART baud without breaking existing captures; reject invalid rates before opening the port |
| `examples/esp32-runtime/README.md` | Document matching firmware/receiver baud and physical verification requirement |
| `README.md`, `doc/oss/status.md` | Record host-first findings while keeping the original C6 issue open |
| This report and `doc/oss/memory24-results.json` | Separate healthy tests, deliberate failures, exact observations and unverified hardware behavior |

The other dirty runtime/storage/test files belong to the pre-existing Memory23
work and were not edited by this investigation. `git diff --check` passes;
Git still reports the existing CRLF-to-LF notices for some pending Memory23 files.
