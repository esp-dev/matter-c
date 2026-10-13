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
Resolve the historical failures and newly observed failures before leaving this
stage. Private extension semantics need separate controller tests; CSA composition
tests do not validate their meaning.

MP02 (three-phase measurements), MP03 (source registers) and MP04 (Identify,
Meter Identification and Time Synchronization) are implemented on x86.
MP04a identifies the startup discovery selection failure in the pinned controller's
`onnetwork-long` path. The pair oracle now uses its discriminator-checking QR-code
path, with browsing active before DUT startup and no announcement-settling delay.
See [evidence and remaining tool limitation](oss/mp04a-validation.md).

CSA01 establishes the first complete installed-catalog [matrix](oss/csa01-matrix.json)
for the frozen five-endpoint x86 profile. The [report](oss/csa01-validation.md)
records the actual official runs, PICS, baseline, failures and unexecuted coverage.
All four historical failures reproduced. A complete matrix does not mean a
completely passed profile: manual procedures and missing fixtures remain open.

CSA02 addresses commissioning, fail-safe and selective fabric/session teardown.
The [report](oss/csa02-validation.md) and [recheck evidence](oss/csa02-results.json)
retain the original failures, exploratory runs and final-source acceptance.
Host table holes and waiting for an unavailable PASE ACK are separate defects.
Exact duplicate-root and PASE RevokeCommissioning response expectations require
explicit CSA/test resolution, not implementation workarounds. Keep the MP04a
concurrent RemoveFabric scenario as a regression; a later pass alone does not
prove the cause of its historical intermittent timeout.

**Next task: CSA03 - Descriptor and endpoint composition against Device Library.**
Resolve IDM 10.5 for the actual advertised device types and server/client lists,
including OTA Requestor and the meter-service clusters. Run the corresponding
official composition/PICS tests on all affected endpoints. Do not add unsupported
mandatory dependencies or tariff declarations merely to silence conformance.

Subsequent passes must resolve Descriptor device-type composition, report timing,
read validation, diagnostics, discovery and resource limits, and prepare the
missing three-phase triggers, OTA, Wi-Fi and manual/attestation fixtures. Retain
test/specification discrepancies for explicit CSA resolution, not silent waivers.
Refresh the matrix after each coherent fix and rerun the full applicable suite
before closing this stage. Do not discard the initial failures or count test
credentials and skipped production checks as certification evidence.

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
