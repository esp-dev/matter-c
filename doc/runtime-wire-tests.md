# Native runtime wire regression

`runtime-wire-host` runs the real runtime and portable RGB model with an
independent pinned Matter.js0.17.9 peer over IPv6 loopback. It creates five fabrics,
fifteen protected CASE sessions and fifteen full subscriptions of171 attributes.
It uses the same controller/load helpers as the C6 soak; it does not require a
board, UART, access point or a previously commissioned controller.

The application owns the process loop and all network callbacks. Fault hooks,
allocation replacement and fake application Wi-Fi/storage ports live only in
the test executable. Normal libraries and firmware contain none of those hooks.
Device state is in RAM and fresh per process. Operational routing uses a known
loopback address, so this does not test mDNS discovery or Wi-Fi commissioning.
The identity/platform snapshots are synthetic;171 paths do not imply identical
C6 payload sizes. TX delay holds the adapter's notification to runtime; lower-level
UDP borrow tests remain a separate component regression.

## Prepare the peer

Supply Node.js and Python3.9+ plus the normal native CMake/MinGW or Linux build
prerequisites. The lockfile pins the controller and transitive dependencies;
neither CMake configuration nor CTest installs/downloads them automatically.
For example, prepare dependencies in an ignored directory:

```text
cmake -E make_directory build/wire-controller
cmake -E copy tools/matter/tests/wire-controller/package.json tools/matter/tests/wire-controller/package-lock.json build/wire-controller
npm ci --prefix build/wire-controller --ignore-scripts --no-audit --no-fund
```

Raw controller logs and controller state contain generated development credentials.
Keep the build and `--output` directories private/ignored. Every runner invocation
creates a new child directory; it never reuses C6 controller state or deletes
another run. No controller packages or device credentials are vendored here.

## Run directly

Build the CMake target `runtime-wire-host`. On Windows the executable ends in
`.exe`; on Linux it has no suffix. This command selects the short healthy case:

```text
python tools/matter/tests/runtime_wire.py --host build/host/cmake/tests/runtime-wire-host --modules build/wire-controller/node_modules --output build/wire-results --case before
```

Use `--node <node-executable>` when Node.js is outside PATH. Use
`--interface <interface-name>` when the peer needs a particular existing interface
for its mDNS service startup. Actual runtime traffic uses `::1` and a chosen
ephemeral UDP port. No interface configuration is changed. A port collision or
bind failure fails the run.

`--case after` selects the allocation/ACK-fault case. `--case single` runs four
single-lost-ACK comparisons, with the original and explicitly corrected peer
in both loop orders. `--case all` (the runner's default) runs all six cases.
Each case has a bounded controller timeout and requires an
orderly fixture stop. Forced process termination is a failure, not a passed drain.
The runner's540-second watchdog bounds a full fault case; it does not change
any Matter timeout. The fixture has a separate600-second lifetime guard.

| Case | Owner loop | Local completion | Required coverage |
|---|---|---|---|
| `before` | Poll UDP before runtime,1ms sleep | No extra delay | Full load, concurrent Reads, Write, RX reordering, explicit close/reconnect and held-TX stop |
| `after` | Poll UDP after runtime,10ms sleep |25ms extra delay | Same coverage plus three one-shot OOM positions and one missing-ACK negative control/recovery |
| `single-{original,corrected}-{before,after}` | Corresponding loop order above | Corresponding delay above | Exactly one lost ACK, terminal MRP attempts/outcome, wrong-role rejection, 15 existing CASE Reads, reconnect and drain |

Both cases require ACKs after their matching packet's local completion. The
delayed case additionally requires ACKs while that same packet's accepted TX
completion is still deferred. This is checked against exchange and message counter,
not inferred from the configured delay.

## Register with CTest

The executable always builds with native tests. The six wire tests are registered
only when the operator supplies the dependency directory. Use absolute paths:

```text
cmake -S . -B build/host -DMATTER_WIRE_NODE_MODULES=<absolute-node_modules>
cmake --build build/host -j 3
ctest --test-dir build/host -R ^runtime_wire_before$ --output-on-failure
ctest --test-dir build/host -R ^runtime_wire_ --output-on-failure
```

The existing Mbed TLS configuration/build options still apply. Optional cache
variables `MATTER_WIRE_NODE` and `MATTER_WIRE_INTERFACE` select the executable and
interface. Missing/wrong dependencies fail explicitly. Wire tests run serially;
the ordinary test inventory remains available without Node.js.

## Fault and acceptance rules

The RX fixture retains one datagram, permits a later datagram to pass it, then
delivers the held bytes in a separate runtime turn. A bounded500ms fallback avoids
an indefinite hold. The oracle requires an actual reordering counter increment;
arming a hook without exercising it does not pass. Storage for retained RX bytes
is heap-owned and freed at teardown.

OOM commands fail exactly the1st,3rd and7th subsequent tracked allocation, once
per phase. The oracle checks that each fault was consumed exactly once, logs
rejected operations and requires successful full Reads and15 subscriptions after
recovery. Scheduling can determine which concurrent operation consumes that
allocation; these are reproducible ordinal faults, not fixed allocation-site
identities. Exhaustive component allocation tests remain separate CTest cases.

The ACK negative control targets one SubscribeResponse on the first non-primary fabric by
session, exchange and packet counter after authentication. Its ACK processing is
suppressed until the existing MRP failure closes that subscription. All15 full
initial snapshots must still finish, then the diagnostic count must become14
(three on the querying original fabric). This is an expected negative control,
not a healthy15/15 pass. After disabling the fault, Reads must still succeed on
the existing CASE sessions, including the one whose subscription ended. The lost load is explicitly rebuilt
and15/15 is required again. It does not attribute the original C6 Memory23 finding.

The single-ACK cases suppress only the first authenticated matching ACK. With
the original pinned peer, fallback ACKs carry the wrong exchange role: the
oracle requires an observed wrong-role ACK, five attempts, TIMEOUT and14/15.
The corrected peer requires ACKNOWLEDGED on attempt2 and15/15. Both require
exactly one suppression and successful Reads on all15 existing CASE sessions
before any reconnect. A core accepting the wrong role fails the negative oracle.
The test-only `peer_role.mjs` override uses the original factory with an explicit
`isInitiator` option inverse to the incoming role, checks the UTF-8/LF source SHA256,
and records its provenance in the result. It never edits installed dependencies.
`MATTER_TEST_PEER_ROLE=corrected` explicitly enables the same diagnostic override
for the C6 soak; absent that variable the peer is unchanged. Such a run must be
reported as a corrected diagnostic peer, never as unmodified Matter.js acceptance.

Finally, the peer closes/reopens the full load. The fixture holds an actual accepted
TX completion, receives stop, releases that completion after200ms and drains before
deleting runtime, UDP, RGB and crypto objects. The oracle requires zero tracked
allocations/bytes and a successful fixture exit. The outstanding peer Read can
fail during this deliberate stop window; a healthy-operation failure still fails
the test. Only after runtime drain succeeds, the oracle explicitly closes its
peer sessions/exchanges to avoid waiting for another peer MRP timeout during
controller disposal.

The runner writes command files, logs, controller summaries and `results.json`.
An empty/partial results list after failure is not a pass; use the process exit
status as well as the per-case coverage assertions.

## Memory tools and limits

On Linux, `--memcheck` runs the fixture under Valgrind with full leak checks,
origin tracking and an error exit code. It additionally requires zero errors and
zero bytes/blocks at exit. Run sanitizers separately in a CMake build configured
with `-DMATTER_SANITIZE=ON`; never combine Memcheck and ASan in one process.

`core_bytes`/`core_peak` count requested payload bytes in the instrumented C
fixture, including its application objects and retained RX. They exclude allocator
metadata, internal Mbed TLS allocations, OS networking and the Node.js process.
Memcheck/sanitizers also observe real allocations behind these wrappers. These
numbers are not ESP32 heap, largest-free-block or task-stack measurements.

The short case is intended for quick regression feedback; the fault case adds
recovery and peer timeouts. Hardware timing, lwIP/Wi-Fi, NVS/fail-safe durability,
UART behavior, whole-device RAM/fragmentation and phone-app acceptance still need
their own C6 checks. These tests are independent laboratory regressions, not CSA
test results or certification.
