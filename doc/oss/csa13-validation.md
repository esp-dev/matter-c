# CSA13: full fabric table and commissioning failure status

## Reproduction and repair

The unchanged TC_CADMIN_1_19 fails on the CSA12 binary (run 324). Five fabrics
commission successfully, but the sixth attempt fails at AddTrustedRootCertificate
with IM ResourceExhausted (0x89). The controller exposes this as error 1417;
the official assertion expects error 11, the controller mapping of the
NOCResponse TableFull status. Baseline TH reports 18 passed records and one
failed record; those partial passes do not make the case pass.

Supplied Core 1.6.1 section 11.18.6.8 assigns the full-fabric-table result to
AddNOC: when CommissionedFabrics equals SupportedFabrics, return NOCResponse
StatusCode TableFull (5). Section 11.18.6.13 defines RCAC admission, signature
validation and fail-safe restrictions for AddTrustedRootCertificate. The
implementation already has a separate pending-root journal entry, so admission
does not require a free operational fabric slot.

`runtime/matter_fabric_host.c` removes the premature fabric-count rejection
from root admission. The existing AddNOC capacity check produces TableFull.
RCAC profile/signature verification, duplicate handling, one-root-per-fail-safe
restriction and atomic storage errors remain active. Existing journals handle
rollback. There is no new allocation, capacity increase, public API/layout change,
storage-schema change or controller-specific error translation. The public view
comment now describes the extra pending certificate accurately.

`test_fabric.c` adds a full-table regression with a distinct, independently signed
synthetic RCAC. It covers bad signatures, simulated storage failure, idempotent
root admission, visibility of the pending root, rejection of a different second
root, TableFull, rollback and recovery of an unfinished root-only journal.
All five installed records remain byte-identical and their operational keys
still sign verifiable messages. The record snapshot is heap-owned and released.
The same regression fails against the old fabric host with IM ResourceExhausted.

An initial test-fixture restart attempted to delete Operational Credentials while
its unsuccessful AddNOC still owned a CSR. The lifecycle guard correctly refused.
The test now explicitly rolls back that attempt, then separately stages a
root-only journal to test restart recovery. No production lifecycle guard changed.
This is in-memory image recovery, not a full-table power-cut/file-crash test.

## Official acceptance

| Case | Run | Result | Coverage |
| --- | --- | --- | --- |
| TC_CADMIN_1_19, baseline | 324 | FAIL | Sixth attempt fails prematurely at root admission |
| TC_CADMIN_1_19, final | 325 | PASS | Five fabrics, sixth rejected at AddNOC, removal, count recovery, window subscription/revoke; 19 TH records |
| TC_OPCREDS_3_1, final | 326 | PASS | Unchanged Operational Credentials regression; 3 legacy TH wrapper records |

OPCREDS 3.1 executes its internal Python steps; its three wrapper records are
not three individual protocol checks. Both official scripts are byte-identical
to CSA01. TH v2.15.1+summer2026, SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`, declared profile and endpoint PICS
remain unchanged. CADMIN 1.19 uses the same 1500-second outer test budget for
baseline and final; the runner restores the project configuration afterwards.
No protocol deadline, assertion, status expectation or test body was altered.

[Result delta](csa13-results.json) preserves all attempts and hashes of scripts,
PICS, logs, source manifest and binaries. The cumulative matrix is **88 PASS,
17 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Other rows are inherited, not rerun.
This is selected-case acceptance, not certification or a full-catalog rerun.

## Native and memory validation

Six CTest targets pass normally and separately with ASan/UBSan/LSan:
`test_fabric`, `test_opcreds`, `test_dispatch`, `test_root`, `test_runtime`,
`test_runtime_alloc`. Captured GCC build logs contain no compiler warnings.
The source manifest matches all 353 C/header files in the lab after the old-code
control was restored. Inventory validation covers 228 mapped files, 85 native
definitions, 59 core sources and 75 public headers.

The full two-instance Linux scenario passes Memcheck with **zero errors,
zero bytes/blocks at exit, 48,589 allocations/frees and no suppressions**.
The separate ASan/UBSan/LSan scenario starts the instances in reverse order and
also passes. Both exercise real commissioning, CASE reads/subscriptions,
selective teardown and clean process exit with the final binaries.

Executed build/check commands (dependency paths supplied locally):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_fabric test_opcreds test_dispatch test_root test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_fabric|test_opcreds|test_dispatch|test_root|test_runtime|test_runtime_alloc)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# test_discovery_startup_linux.py with explicit executable/controller/PAA/credentials:
# --mode memcheck; then separately --mode sanitize --reverse.
python tools/matter/check_test_map.py
git diff --check
```

Private lab scripts, logs, addresses, credentials and state remain ignored.
Windows, physical devices and Google Test Suite were not rerun. The full-table
scenario runs in official TH and the focused native sanitizer regression;
the two-instance memory scenario exercises general runtime lifecycle and does
not itself fill five fabrics. Earlier test/specification discrepancies remain
open without a CSA waiver.

**Next: CSA14 - Network Commissioning Wi-Fi fixture and TC_CNET_4_1/4_4.**
Prepare a connected simulated network for the on-network host, reconcile its
reported attributes with the specification, and rerun the unchanged official
cases. This does not imply a physical Wi-Fi radio test.
