# CSA30: General Diagnostics, Node time and transport interfaces

CSA29 was committed as **`1387bd0`**. CSA30 fixes two integration defects and
executes original semi-automated **TC-DGGEN-2.1**, TH run **463**.
**Final result: ERROR**, completed 2026-10-18 17:47:39 UTC. The full first
7,500,000 ms wait completes, but the next read encounters a TH/chip-tool
WebSocket keepalive timeout. It obtains no second hours value; the later
3,900,000 ms wait and remaining steps are not executed. Neither original wait
was shortened. The matrix remains **97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL,
704 NA**: this infrastructure-interrupted case has no completed acceptance.

## Defects and specification

An independent chip-tool read on the preceding binary observed UpTime
**3,412,724 s** after only **3.777 s** of process lifetime. The executable passed
OS monotonic uptime directly to its runtime and clusters. The diagnostics
backend correctly interpreted that value as Node System Time, also adding
pre-existing OS hours to a fresh simulated Node's TotalOperationalHours.

Core R1.6.1 **11.12.6.3** requires UpTime since the Node's last reboot, using
the same System Time source as the server's other system-time values.
**11.12.6.4** requires lifetime operational hours, reset only by factory reset.
The host now owns a monotonic boot origin in each Node and subtracts it for
all runtime, application-cluster, callback and shutdown ticks. One process is
one simulated Node. UTC/certificate time remains separate. This does not change
the portable runtime's clock contract or authorize resetting an actual device's
clock on a mere service restart.
Existing stored hour counters are retained, including any old overcount. The
fix prevents new OS-uptime additions; it does not silently reset lifetime data.

The full composition also still exposed a constant simulated Wi-Fi interface:
zero hardware address, no IP addresses and false operational state. Core
**11.12.5.6** and **11.12.6.1** require descriptions of the Node's logical
interfaces, their current link-layer/unicast addresses (including link-local
IPv6) and operational advertising/receive state. The existing encoder's
eight-byte zero-prefixed representation of a six-byte MAC was already correct.

An optional application-owned network snapshot port now supplies the complete
General Diagnostics interface list. It runs on the owner thread into existing
heap-owned diagnostic storage. Failure, excessive counts and malformed snapshots
invalidate reads; stale data is not presented as current. The omitted-port
behavior remains compatible with existing radio-derived backends. The host
connects the port to its actual selected NIC, independently of its simulated
Wi-Fi commissioning backend. No new scheduler, thread or large stack buffer is
introduced. Consumers must rebuild and zero-initialize optional configuration
fields after this public structure extension; function signatures are retained.

## Original Test Harness execution

Run463 uses unchanged TC-DGGEN-2.1, SHA-256
`695593b7bd95e321167e4c0e5b5ebc0a0bdd0078b388923c17014200bb447830`,
and unchanged root-profile PICS SHA-256
`21ec86cad497f4054e3cc0d14c2f4478d2a7df842817d0494bb1a9bd57dff4fb`.
TotalOperationalHours remains enabled. A 12,500-second execution timeout
accommodates both original waits and lifecycle operations. Certification mode
is disabled. A temporary development PAA is explicitly trusted; signature and
chain verification remain enabled.

Final TH states are **28 passed, 5 not applicable, 1 error, 12 pending**.
Passed steps include commissioning after
factory reset, RebootCount increase, the NetworkInterfaces operator check,
UpTime advance/decrease across restart, BootReason, three fault-list
subscriptions/reads, initial TotalOperationalHours=0 and its full **2 h 5 min**
wait. At 17:46:09 UTC the next read errors with `keepalive ping timeout` and
`no close frame received` on the TH/chip-tool WebSocket. Cleanup subsequently
cannot reconnect that WebSocket. This is not an assertion that the DUT returned
a wrong counter: the second value was not obtained. The precise reason for
losing the controller connection remains undiagnosed. The log also contains a
late prompt-timeout/Step1a entry during the long wait; its origin is not yet
established and is not assigned as the cause.

The operator fixture stops/restarts only its own process and preserves the store
on reboot. Factory reset removes only that stopped fixture's explicit store,
then recommissions using the original YAML QR identity. The network verification
uses an actual read by an unmodified chip-tool process in TH's SDK container,
with an isolated copy of controller configuration. Its decoded MAC and address
lists are compared against the VM interface. It does not take over the active
controller's single WebSocket connection. The privileged one-shot helper has
finished; the remaining test execution ran as the ordinary lab user.

The default TestEventTriggersEnabled value is false. The test takes its disabled
branch; this does not verify an enabled test-event handler. Operator decisions
and timestamps are retained; the final manual evidence-upload step was not
reached. The collector retained final results/logs and confirmed cleanup: the
disposable node is stopped, port5581 is released, the matching temporary PAA is
removed and TH is idle.

Two setup attempts are preserved separately: run461 was cancelled because the
external operator runner did not initially account for TH's step-label prefix.
Run462 reached an error after factory reset because the isolated discriminator
did not match the original YAML's default QR. The retry selects **3840**, matching
that original QR and the existing QR oracle; no test source/PICS change hides
these attempts. Neither attempt is counted as a PASS or as a new matrix result.

## Independent acceptance already completed

The new [chip-tool scenario](../../tools/matter/tests/test_general_diagnostics_chip.py)
passes **31 checks under Memcheck** and **28 separately with ASan/UBSan/LSan**.
Each run covers three host boots: fresh attested commissioning, a ten-second
real-time uptime sample, clean restart with fresh CASE and retained counters,
then factory-reset store/recommissioning. It checks actual NIC MAC/IPv4/IPv6,
operational publication, empty fault lists and disabled test triggers.

Memcheck totals **59,140 allocations and 59,140 frees**, zero errors and zero
live bytes, without suppressions. All six host stderr files are empty. The
external controller is not instrumented. Eight captured uptime conditions and
six network conditions pass the actual driver predicates; seven negative
controls reject OS uptime, ahead/stalled uptime, wrong MAC, false operational
state, missing link-local IPv6 and an incorrect address count.

Six focused CTests pass in each Linux build: `test_diagnostics`, `test_runtime`,
`test_runtime_alloc`, `test_store`, `test_time_host`, `test_ota_update`.
The normal installed-consumer test also passes. Runtime regressions exercise
callback failure, oversized/malformed output, recovery, live state, default
backend isolation and constructor allocation failures. Successful Linux build
logs contain no compiler warnings.

Windows `matter-node` and `matter-desktop` compile in a separate output directory.
Four Windows CTests pass: runtime, allocation failures, diagnostics and pairing
QR. Existing paired applications were not replaced or restarted. This does not
constitute a new manual Apple/Google Home or GUI presentation test.

The initial local helper expected six MAC bytes and an operational simulated
interface; that failed attempt is retained. Its corrected assertions use Core's
eight-byte MAC encoding and actual NIC data. The first build invocation named
two nonexistent CMake targets; the final invocation uses real targets and the
previous transport build budget of 128. These setup failures are not passing
test results.

## Changed files and reproduction

| Files | Purpose |
| --- | --- |
| `tools/matter/host/matter_node.c` | One Node clock origin; actual selected-interface callback and publication state. |
| `matter_diagnostics.h`, `matter_runtime.h/.c` | Optional network snapshot port, bounded integration and failure handling. |
| `tools/matter/host/matter_server.h/.c` | Pass the application port through the host adapter. |
| `tools/matter/tests/test_runtime.c` | Callback errors, oversized/invalid output, recovery and instance isolation. |
| `tools/matter/tests/test_general_diagnostics_chip.py` | Independent real-time/CASE/NIC/restart/factory-reset acceptance. |
| `doc/runtime.md`, test inventory, README, status, roadmap and this report/JSON | Clock/ownership contract, reproduction and final infrastructure ERROR with unexecuted assertions. |

```sh
cmake --build /path/to/normal -j 3 --target matter-node test_diagnostics test_runtime test_runtime_alloc test_store test_time_host test_ota_update
ctest --test-dir /path/to/normal --output-on-failure -R '^(test_diagnostics|test_runtime|test_runtime_alloc|test_store|test_time_host|test_ota_update)$'
# Repeat in the separate sanitizer build, configured with MATTER_SANITIZE=ON.
ctest --test-dir /path/to/normal --output-on-failure -R '^installed_consumer$'
python tools/matter/tests/test_general_diagnostics_chip.py \
  --exe /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/paa --credentials /path/to/credentials --interface 2 \
  --output /path/to/fresh-memcheck-directory --valgrind
# Repeat separately with the sanitizer binary, without Valgrind.
cmake --build /path/to/windows -j 3 --target matter-node matter-desktop test_runtime test_runtime_alloc test_diagnostics test_gui_pairing
ctest --test-dir /path/to/windows --output-on-failure -R '^(test_runtime|test_runtime_alloc|test_diagnostics|test_gui_pairing)$'
python -m py_compile tools/matter/tests/test_general_diagnostics_chip.py
python tools/matter/tests/test_general_diagnostics_chip.py --help
python tools/matter/check_test_map.py
git diff --check
```

## Limits and next action

The NIC address list is the selected host adapter's startup snapshot. The shared
I/O API does not expose link type, so Type is explicitly Unspecified. Unused OS
adapters are outside this simulated Node, and NIC address changes require host
restart. Physical Wi-Fi, actual firmware reboot/flash, ecosystem UI and 128 kB
device RAM fit are unverified. Raw logs, controller stores and credentials stay
outside Git. The inventory contains 238 files, 87 native definitions, 59 core
sources and 75 public headers. No full CTest/catalog rerun or certification is
claimed.

**Next action: reproduce and diagnose the TH/chip-tool WebSocket loss with a
short fixture, then repeat the unchanged full case once the infrastructure is
stable.** Preserve run463's ERROR; do not classify local checks as official PASS.
