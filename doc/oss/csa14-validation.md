# CSA14: connected Wi-Fi host simulation and CNET 4.1/4.4

## Change and its boundary

The host already simulated two APs but started with no configured/connected
network. On-network commissioning over its real IPv6 transport did not configure
the simulated radio. Both selected official tests therefore failed their
connected-network precondition on the CSA13 binary.

- `tools/matter/host/matter_server.c/.h` adds host-only
  `matter_server_new_sim` options. With `wifi_connected=true`, the initial
  simulator state uses the existing primary AP's SSID and credentials, enabled
  interface and matching association. The existing constructors retain their
  defaults, including optional OTA setup. The portable runtime/API, Wi-Fi cluster,
  simulator command logic and storage format are unchanged.
- `matter_node.c` exposes `--wifi-sim-connected`, requiring credentials. Without
  it, Networks remains empty on fresh state. Existing storage overrides the seed
  before the cluster is constructed, even if the stored Networks list is empty.
  No OS network interface is changed. This models initial association rather
  than implementing physical Wi-Fi connection or BLE commissioning.
- `runtime_pair_host.c`, `test_discovery_startup_linux.py` and
  `chip_tool_three_phase.py` pass the option through the two-instance scenario
  and check connected attributes, fail-safe rejection, armed general/directed
  scans, missing SSIDs, Breadcrumb updates and rollback.

The seed reuses the existing heap-owned simulator configuration, checked for
allocation failure and erased/freed after construction. No new global state,
threads, timers or runtime resource limits are introduced. Options are borrowed
only during construction. Read attributes and diagnostic observation use the
same existing simulator association, rather than independent canned values.

Core 1.6.1 sections 11.9.6.2 and 11.9.6.6-8 define Networks and the last
connection/status/error attributes, including initial establishment. The current
Wi-Fi constructor already initializes them from the loaded connected network;
the missing element was host fixture state, not a new attribute implementation.

## Unchanged official tests

| Case | Run | Result | Observation |
| --- | --- | --- | --- |
| TC_CNET_4_1 baseline | 327 | FAIL | No connected Networks entry; 7 passed, 1 failed, 4 pending records |
| TC_CNET_4_4 baseline | 328 | FAIL | No connected Networks entry; 5 passed, 1 failed, 5 pending records |
| TC_CNET_4_1 final | 329 | PASS | Complete attribute check; 12 passed records |
| TC_CNET_4_4 final | 330 | FAIL | Connection found; ScanNetworks returns FailsafeRequired; 6 passed, 1 failed, 4 pending records |

TH v2.15.1+summer2026 and SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf` are unchanged. Both script hashes
match CSA01; no PICS, protocol deadline, test assertion or test body was changed.
The explicit difference in final DUT startup is the connected simulation option.
[Result delta](csa14-results.json) retains all four attempts and artifact hashes.
The cumulative matrix is **89 PASS, 16 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**;
unselected rows are inherited. This is not certification or a full-catalog rerun.

## CNET 4.4 discrepancy requiring resolution

The supplied Core 1.6.1 section 11.9.7.1 requires ScanNetworks without an armed
fail-safe to return FAILSAFE_REQUIRED. The installed TC_CNET_4_4 commissions the
node, reads its attributes, then sends ScanNetworks in step 4, expecting success.
It does not arm a new fail-safe after CommissioningComplete. The DUT correctly
returns Interaction Model status **0xCA**, decoded by the official controller
as `InteractionModelError: FailsafeRequired (0xca)`.

Reproduction: start a fresh host with `--wifi-sim-connected`, commission normally,
then run the unchanged CNET 4.4. No special timeout or injected failure is needed.
The current script SHA-256 and full official-log hash are in the result delta.

The item to resolve with CSA/test maintainers is whether the test should arm and
later clean up a fail-safe before scanning, or whether a normative exception is
intended for this procedure. No such exception, response or waiver has been
obtained. Keep the official FAIL; do not disable the guard or count an externally
prepared, differently preconditioned run as the original test passing. No report
has been sent externally as part of this task.

## Independent validation

- Linux GCC build: successful, no compiler warnings in captured logs.
- CTest **6/6 PASS**, normally and separately with ASan/UBSan/LSan:
  `test_root`, `test_root_alloc`, `test_diagnostics`, `test_runtime`,
  `test_runtime_alloc`, `test_store`. These cover existing Wi-Fi error/rollback,
  runtime lifetime, allocation-failure and persistence behavior.
- The full pair scenario with explicit connected simulation passes under
  Memcheck, then separately with ASan/UBSan/LSan and reverse commissioning order.
  Both real CASE connections can read their network, receive FAILSAFE_REQUIRED
  before arming, scan successfully after arming, receive NetworkNotFound for a
  missing SSID, preserve Breadcrumb on that failure, and retain their connection
  after rollback. Existing subscriptions, meter services, selective teardown and
  both final RemoveFabric replies also pass.
- Memcheck: **0 errors, 0 bytes/blocks at exit, 48,801 allocations/frees,
  no suppressions**. Sanitizers complete without diagnostics. The earlier shorter
  pair run also passed; the recorded final hashes refer to the expanded guard,
  general-scan, Breadcrumb and rollback scenario.
- A separate local constructor/store probe passes normally and with sanitizers:
  legacy empty default, connected seed, persisted empty state reopened with the
  flag enabled, and persisted connected state reopened with the flag disabled.
  It checks Networks, LastNetworkingStatus, LastNetworkID and LastConnectErrorValue.
  Its first fixture omitted mandatory hardware/software version strings and was
  rejected; adding those required identity fields corrected the probe. This
  ad-hoc probe and its source/log hashes remain in the ignored lab evidence.
- The source manifest matches all 353 C/header files locally and in the VM.
  Controller/runner hashes also match. Inventory: 228 mapped files, 85 native
  definitions, 59 core sources and 75 public headers. `git diff --check` passes.

Build/check commands, with local paths supplied explicitly:

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_root test_root_alloc test_diagnostics test_runtime test_runtime_alloc test_store
ctest --test-dir build/final --output-on-failure -R '^(test_root|test_root_alloc|test_diagnostics|test_runtime|test_runtime_alloc|test_store)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# test_discovery_startup_linux.py: explicit executable/controller/PAA/credentials,
# --wifi-sim-connected --mode memcheck; separately --mode sanitize --reverse.
python -m py_compile tools/matter/tests/test_discovery_startup_linux.py tools/matter/tests/chip_tool_three_phase.py
python tools/matter/check_test_map.py
git diff --check
```

Windows, Google Test Suite, physical radios/devices and firmware integration
were not tested. Supplementary scans check status/lifecycle/Breadcrumb behavior;
they are not a substitute for all CNET 4.4 assertions or CSA approval. Lab paths,
addresses, credentials and raw state remain ignored.

**Next: CSA15 - Wi-Fi connection/configuration fixture, TC_CNET_4_9/4_11.**
Retain the CNET 4.4 discrepancy while preparing explicit simulated SSID/AP
parameters and checking connection errors/configuration recovery.
