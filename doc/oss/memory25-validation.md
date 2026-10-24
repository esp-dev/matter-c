# Memory25: reusable native runtime wire regression

Validation: 2026-10-22 UTC (22–23 October local time). The requested previous work
is committed separately: Memory23 as `26ee0fd`, Memory24 as `43fbd7c`. This change
adds a repeatable test foundation; production sources under `main/apps/matter`
are unchanged from those commits. No memory optimization or protocol fix is
claimed in Memory25. The original physical C6 startup14/15 finding remains open.

## Implementation

The native `runtime-wire-host` target compiles instrumented copies of the real
core/runtime and portable RGB model. It reuses the existing runtime test's
application ports and development identity. The allocation tracker, ACK shim,
retained RX and deferred runtime TX notifications exist only in this executable.
They are not linked into installed libraries or firmware. Large retained RX bytes
are heap-owned; teardown requires zero tracked allocations and bytes.

The controller extends the existing C6 `soak.mjs` with an explicit loopback-only
host mode. Existing commissioning, CASE, Read, subscription, admission, recovery
and control-reply operations are shared instead of copying another controller.
Host scenarios live in a separate module. A tracked npm lockfile pins Matter.js
and its dependencies; CMake never downloads them automatically. Every invocation
creates fresh private state. The two CTest entries are opt-in through
`MATTER_WIRE_NODE_MODULES`; the fixture executable builds with the native tests.

Both cases create five fabrics, fifteen protected CASE sessions and fifteen full
171-attribute subscriptions. They verify the fourth protected CASE is rejected,
concurrent full Reads, Write, actual RX reordering, full close/reconnect, and stop
while an accepted TX notification is held. ACK ordering is measured against the
matching exchange and packet counter. The delayed case must observe ACK processing
before its matching local completion notification, not just configure a delay.

The extended case also fails the1st,3rd and7th subsequent tracked allocations,
one per named phase. The exact consuming operation can vary with concurrent
heartbeats; each fault must be consumed once and full healthy load must recover.
Recovery may explicitly rebuild subscriptions in a fault window; that is logged,
not counted as uninterrupted survival. Outside named fault/teardown windows,
unexpected subscription loss fails the test.

A separate negative control suppresses authenticated ACK processing for one
SubscribeResponse on the second fabric. All15 initial snapshots must complete,
then one MRP failure and a diagnostic count14/15 must be observed. Reads must
still work on the existing CASE sessions, including that subscription's session.
The fault is disabled and15/15 must be explicitly rebuilt. This characterizes a
failure mechanism; it does not attribute the original C6 event.

## Executed validation

| Platform / instrumentation | Existing native CTest | New wire cases | Full two-instance scenario |
|---|---|---|---|
| Windows/MinGW, Node24.22.0 |102/102 |2/2, registered CTest | Not rerun on Windows |
| Linux, Memcheck3.22.0, Node22.20.0 |99/99 without instrumentation |2/2 under Memcheck |6/6 groups under Memcheck |
| Linux, separate ASan/UBSan/LSan build |99/99 with sanitizers |2/2 with sanitizers |6/6 groups with sanitizers |

Windows' final single CTest invocation passes104/104 in459.77s. Its CTest entries
take85.78s (`before`) and348.07s (`after`). Controller elapsed times, excluding
some runner startup overhead, are:

| Instrumentation | Short `before` | Extended `after` |
|---|---:|---:|
| Windows normal |84.03s |346.92s |
| Linux Memcheck |113.99s |448.44s |
| Linux sanitizers |82.40s |312.34s |

All six wire cases finish with zero tracked allocations/bytes. Each extended
case consumes exactly three allocation faults, exercises the missing-ACK control,
confirms CASE usability after that failure and closes fifteen peer sessions after
runtime drain. Both wire Memcheck logs and the complete pair report zero errors
and zero bytes/blocks at exit. Separate sanitizer executions exit successfully
with leak detection and halt-on-error enabled. Compiler warnings are errors in
these targets; no new C warning was observed. Inventory, JavaScript syntax,
runner help and `git diff --check` were also checked.

Hashes for173 core/header/fixture/controller/configuration files match the tested
VM export. Binary hashes, per-case counts, memory payload peaks, deliberate
fault/rebuild counts and source hashes are in `memory25-results.json`. Raw logs,
commands, private state and development failures remain in ignored
`build/memory25` and the configured build's `wire-results` directories.

## Development failures retained

The first RX fixture attempt let its hold expire without actually reordering
traffic. Its coverage assertion correctly rejected the run. The fixture now
allows a later packet through and releases retained bytes in a separate runtime
turn; a reorder counter increment is mandatory.

An initial Linux extended run reached successful runtime drain at400.58s but hit
the driver's420s watchdog while disposing an outstanding peer Read. It is not
counted as a pass. The final oracle explicitly force-closes peer exchanges only
after runtime deletion/zero-live checks; the successful Memcheck run's peer cleanup
took about8ms. The driver watchdog is540s and fixture lifetime guard600s to allow
instrumented recovery. Matter request/MRP/subscription timeouts are unchanged.
Final runs use ordinary malloc semantics in the test allocator, not implicit
zeroing of malloc payloads.

## Files and usage

| Files | Purpose |
|---|---|
| `tools/matter/tests/runtime_wire_host.c` | Owner-driven runtime/RGB/UDP fixture and bounded fault controls/drain |
| `tools/matter/tests/wire_dispatch.c`, `wire_alloc.c`, `wire_faults.h` | Test-only authenticated ACK interception, packet identity/order checks and allocation accounting/faults |
| `tools/matter/tests/runtime_wire.py` | Fresh-state runner, strict exit/coverage/leak checks and optional Memcheck |
| `tools/matter/tests/wire_scenarios.mjs`, `examples/esp32-runtime/tests/soak.mjs` | Shared independent controller and host-specific fault/recovery scenarios |
| `tools/matter/tests/wire-controller/package*.json` | Reproducible public test dependencies, without vendored modules/state |
| `cmake/tests/CMakeLists.txt`, `doc/oss/test-map.json` | Separate instrumented target, optional CTest entries and source inventory |
| README/status, `doc/runtime-wire-tests.md`, this report and JSON | Setup, exact scope, acceptance rules, results and limitations |

The [runner guide](../runtime-wire-tests.md) supplies dependency setup and commands.
Executed commands include:

```text
cmake --build build/memory16/windows-gcc -j 3
ctest --test-dir build/memory16/windows-gcc --output-on-failure
python tools/matter/tests/runtime_wire.py --host <native-fixture> --modules <pinned-node_modules> --output <ignored-directory> --case all --memcheck
```

The last command runs only on Linux; sanitizers use a separate build and omit
`--memcheck`. For quick subsequent feedback, select just `runtime_wire_before`
with CTest; run both for allocation/lifetime changes.

## Limits and next task

The host identity and platform snapshots are synthetic.171 attribute paths do
not make their byte sizes identical to C6 data. `core_peak` is the maximum tracked
requested payload, including fixture objects; it excludes allocator metadata,
internal Mbed TLS, OS networking and Node.js heap. It is not ESP32 total heap,
minimum free heap, fragmentation or stack use. No hardware RAM saving is claimed.

TX delay is injected at the adapter-to-runtime notification boundary; the socket
adapter may already have completed its own borrow. Existing native component
tests cover lower-level UDP borrowing/drain as a separate track. Known loopback
routing bypasses mDNS discovery. Wi-Fi/lwIP, NVS durability, C6 timing/stack/UART,
phone apps and official CSA were not retested. COM23/COM24 and the AP were unused.

The next task remains a short C6 startup capture with per-subscription MRP/close
and session traces, and a physically checked1Mbaud console, to identify the actual
reason for the original14/15 result. Host regression can now precede that check.
