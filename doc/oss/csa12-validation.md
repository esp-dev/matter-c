# CSA12: incorrect passcodes and commissioning-window closure

## Reproduction and repair

The unchanged TC_CADMIN_1_9 fails on the CSA11 binary (run 321). Its twenty
incorrect-passcode attempts are rejected, but the subsequent correct passcode
successfully commissions the device. The failing assertion is `ChipStackError
not raised`. The window had a timeout, but no failed-PASE attempt budget.

Supplied Core 1.6.1 section 5.5.1 requires leaving Commissioning Mode after
20 failed attempts. The repair covers failures during PASE in both the initial
window and an Administrator-opened enhanced window:

- `session/matter_pase.c/.h` adds the optional `matter_pase_on_failure` owner
  notification. Install it once before receive/process. It fires once for a
  protocol error, peer failure or timeout, after clearing session secrets.
  Repeated process calls, explicit cancellation/deletion and success do not
  produce another failure. The borrowed callback user must outlive the attempt;
  callbacks cannot reenter the engine/dispatcher.
- `runtime/matter_runtime.c` counts failures per runtime/window. The twentieth
  closes admission immediately. The next owner process pass closes the Admin
  window, erases its verifier and drives discovery withdrawal through existing
  callbacks. Existing CASE administration is preserved. A newly opened window
  resets the count and gets a new epoch; stale attempts cannot debit that new
  window. Epoch exhaustion fails closed. Failed attempts do not extend the
  original window deadline.
- `test_pase.c` verifies one-shot notifications for wrong PIN, malformed messages,
  peer failure and timeout, with no notification on success/cancel. `test_runtime.c`
  uses public RX/runtime APIs to send malformed PBKDF requests and duplicates:
  the initial window remains open through 19 attempts, closes at 20, and the
  other runtime remains commissionable. The same test fails at attempt 20 against
  the previous runtime implementation.

There are no new allocations, threads, global state or resource-pool changes.
Existing function signatures/configuration layouts remain unchanged; the new
notification API is additive. Runtime lifetime already exceeds that of its
dispatcher/PASE engines. Standalone PASE users can omit the hook; owners of a
commissioning window must implement its attempt policy.

The first native fixture incorrectly modeled every UDP send as offline. That
prevented ACK cleanup and admission of later attempts. The fixture now completes
accepted sends asynchronously and allows exchange cleanup before the next attempt;
the production admission/transport rules were not relaxed to make it pass.

## Official acceptance

| Case | Run | Result | Coverage |
| --- | --- | --- | --- |
| TC_CADMIN_1_9, baseline | 321 | FAIL | Correct PIN still accepted after twenty failures |
| TC_CADMIN_1_9, final | 322 | PASS | Twenty failures, correct-PIN rejection, reopen and revoke; 8 TH records |
| TC_CADMIN_1_11, final | 323 | PASS | Two administrators, commissioning, competing open/BUSY, revoke and fabric removal; 13 passed records, 4 N/A |

The four N/A records in CADMIN 1.11 are the Basic Commissioning feature branch;
the declared Administrator cluster supports Enhanced Commissioning only.
Both official scripts are byte-identical to the CSA01 baseline. TH
v2.15.1+summer2026, SDK `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`, the frozen
profile and execution PICS are unchanged. No script assertions, passcode attempt
count, feature flags or timeouts were weakened.

[Result delta](csa12-results.json) retains all three official attempts and hashes
of scripts, PICS, logs, source manifest and final binaries. The cumulative matrix
is **87 PASS, 18 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**; unselected rows are
inherited, not rerun. This is not certification or a full-catalog rerun.

## Native and memory validation

Five CTest targets pass normally and separately with ASan/UBSan/LSan:
`test_pase`, `test_dispatch`, `test_root`, `test_runtime`, `test_runtime_alloc`.
GCC 13.3 with official Mbed TLS 3.6.0 builds with no compiler warnings in the
captured build logs. The inventory check covers 228 mapped files, 85 native
definitions, 59 core sources and 75 public headers.

The full two-instance Linux scenario passes Memcheck with **zero errors,
zero bytes/blocks at exit, 48,574 allocations/frees and no suppressions**.
The separate ASan/UBSan/LSan scenario starts the instances in reverse order and
also passes. These exercise real commissioning, CASE reads/subscriptions,
selective teardown and clean exit. The source manifest matches all 353 C/header
files locally and in the VM after the old-code control was restored.

Executed build/check commands (dependency paths supplied locally):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_pase test_dispatch test_root test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_pase|test_dispatch|test_root|test_runtime|test_runtime_alloc)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# test_discovery_startup_linux.py with explicit executable/controller/PAA/credentials:
# --mode memcheck; then separately --mode sanitize --reverse.
python tools/matter/check_test_map.py
git diff --check
```

Private scripts, logs, lab addresses, credentials and states remain ignored.
Windows, physical devices and Google Test Suite were not rerun. The epoch guard
against a late failure from an old window was statically reviewed; this campaign
does not inject that race through a controller. Failures after successful PASE,
including counting repeated later-stage commissioning failures, remain outside
this repair/acceptance and need a separate Core 5.5.1 review. No waiver of earlier
CSA/test discrepancies is implied.

**Next: CSA13 - TC_CADMIN_1_19, full fabric table and failure status.** Reproduce
the historical RESOURCE_EXHAUSTED versus expected table-full result and trace the
failing commissioning step against Core and the unchanged official assertions.
