# Development and acceptance roadmap

The target is Matter 1.6.1. Passing selected tests is not certification. The
current failures and measured coverage remain in [status](oss/status.md).

## 1. Complete the declared profile and CSA acceptance

Implement the remaining standard clusters and behavior, then run **all applicable
CSA tests** for the declared device types, features and PICS. Maintain a test
matrix with executable/version, PICS, result and evidence for every case. Record
unsupported, blocked and manual cases explicitly; do not count a skip as PASS.
Resolve the four existing failures and any new failures before leaving this
stage. Private extension semantics need separate controller tests; CSA composition
tests do not validate their meaning.

MP02 (three-phase measurements), MP03 (source registers) and MP04 (Identify,
Meter Identification and Time Synchronization) are implemented on x86.
**Next task: MP05 - Commodity Metering on x86, with explicit source mapping.**
Tariff support and complete meter device-type declarations follow their actual
dependencies. Acceptance must also address the recorded multi-node discovery race.
Keep full-host checks with independent controllers, two instances in one process,
failure paths, Memcheck and separate ASan/UBSan/LSan throughout development.

## 2. Google Test Suite and manual ecosystem acceptance

After the CSA matrix is complete, run the applicable Google Test Suite and manual
checks: commissioning, discovery/reconnection, subscription recovery, controls,
data presentation, restart, fabric removal and multi-admin use. Distinguish
protocol support from what the ecosystem UI displays. Save evidence and resolve
failures before optimization; do not change the declared device type to disguise
missing ecosystem support.

## 3. Memory and code-size optimization

Measure an accepted baseline (flash/text/rodata, stack, steady-state and peak
heap). Replace oversized fixed-capacity arrays with per-instance dynamic
allocations sized to actual configuration, with explicit ownership, bounded
limits, overflow checks, OOM handling and complete cleanup. Do not introduce
unbounded allocation in latency-sensitive paths. Replace unexplained numeric
literals with named `#define` limits/IDs/units; retain intentional protocol
constants with documented meanings. Avoid changing wire behavior or public
contracts unnecessarily. Re-run affected CSA and ecosystem cases plus memory
and multi-instance checks, and compare measured savings to the baseline.

## 4. Downstream provisioning and firmware integration

Only after those gates: persist manufacturing/field provisioning and integrate
the library with the target firmware in a separate downstream repository.
Hardware callbacks, credential ownership, storage, boot/update lifecycle and
resource budgets belong to that integration. This repository supplies the
portable library, public contracts and host tests, without product-specific code.
