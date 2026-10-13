# Development and acceptance roadmap

The target is Matter 1.6.1. Passing selected tests is not certification. The
current failures and measured coverage remain in [status](oss/status.md).

## Iteration strategy

Work in successive passes over this roadmap, narrowing the unresolved scope
each time. At the start of each pass review the declared profile, specification
requirements, CSA matrix, ecosystem acceptance, resource measurements and
integration prerequisites. Record what changed and what is still blocked.
Reviewing every area does not waive the ordered acceptance gates below.

Each pass selects a coherent group of failures or missing mandatory behavior,
checks the normative requirements and unmodified CSA assertions, implements the
fix, then runs the affected official cases and necessary independent regressions.
At the end of a pass refresh the full applicable CSA matrix against one identified
revision. Reuse unaffected evidence during development; avoid repeatedly running
local tests that cannot resolve the observed interoperability failure. Record
PASS, FAIL, SKIPPED/NOT_APPLICABLE, BLOCKED, MANUAL and NOT_RUN separately, with
reasons and the next concrete action. A skipped or unavailable case is not a pass.

Full CSA acceptance of the current declared profile takes priority over adding
tariffs or other optional capabilities. New capabilities enter a later pass with
their own PICS and acceptance coverage. The existing source registers stay available.

## 1. Complete the declared profile and CSA acceptance

Inventory and run **all applicable CSA tests** for the current declared device
types, features and PICS; use failures and mandatory coverage gaps to select
implementation work in the next pass. Maintain a test
matrix with executable/version, PICS, result and evidence for every case. Record
unsupported, blocked and manual cases explicitly; do not count a skip as PASS.
Resolve the four existing failures and any new failures before leaving this
stage. Private extension semantics need separate controller tests; CSA composition
tests do not validate their meaning.

MP02 (three-phase measurements), MP03 (source registers) and MP04 (Identify,
Meter Identification and Time Synchronization) are implemented on x86.
MP04a identifies the startup discovery selection failure in the pinned controller's
`onnetwork-long` path. The pair oracle now uses its discriminator-checking QR-code
path, with browsing active before DUT startup and no announcement-settling delay.
See [evidence and remaining tool limitation](oss/mp04a-validation.md).

**Next task: CSA01 - first full CSA matrix pass for the current x86 profile.**
Freeze the profile/PICS and runner version, enumerate every applicable case and
endpoint, then run the matrix and triage failures against the specification. The
four historical failures must be rerun on the current revision, with original
expectations retained. Close actual implementation defects or document a supported
specification/test-version discrepancy; do not silently waive failures.
Include the separate MP04a Memcheck RemoveFabric timeout under concurrent
subscriptions in the regression list. Correct discovery does not close this
later failure in the full pair scenario.

MP05 (Commodity Metering), Commodity Tariff/Price and complete utility-meter
device-type declarations are deferred until this acceptance priority is met.
Do not advertise a device type whose mandatory dependencies are missing.
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
