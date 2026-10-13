# CSA09: invalid CASE input and failure report delivery

## Reproduction and correction

The unchanged official TC_SC_3_4 fails on the CSA08 binary at its first fault
injection: Sigma1 contains a resumption ID without an initiator resume MIC.
The controller expects INVALID_CASE_PARAMETER (84/0x54), but receives a timeout
(50/0x32). Initial commissioning and the preceding valid CASE connection succeed.

Core 1.6.1 section 4.14.2.3's Validate Sigma1, Validate Sigma1 Destination ID and
Validate Sigma3 procedures require the corresponding Secure Channel failure
StatusReport and no further handshake processing. The engine already rejected
these inputs, erased secrets and exposed the report while returning
MATTER_PORT_ERROR/MATTER_CASE_FAILED. The runtime dispatcher interpreted that
terminal crypto result as immediate exchange teardown and discarded the report
before submitting it to MRP. Engine-only negative tests could not detect this
composition defect.

`main/apps/matter/runtime/matter_dispatch.c` now sends an available failure
report and retains its immutable MRP packet until acknowledgement, exhaustion
or explicit cancellation. Additional handshake data cannot abort that report;
RX/MRP still handles control ACKs. Failure never activates a secure session or
takes keys, and failures without an output report still close locally. An earlier
in-flight handshake packet is drained before a queued failure report is sent.
The acknowledged failure closes without invoking the success confirmation API.

`main/apps/matter/session/matter_case.h` documents the existing terminal-error
plus-output contract. `tools/matter/tests/test_dispatch.c` adds a regression
through the real CASE engine, ingress, dispatcher and MRP. Its malformed Sigma1
must be rejected before any fabric load/sign callback. It verifies report bytes,
an identical retransmission including counter, rejection of further handshake
data, absence of session allocation, and cleanup after ACK, retry exhaustion and
stop during borrowed TX. The same new test compiled with the previous dispatcher
fails at the missing queued-report assertion; the corrected dispatcher passes.

Certificate, signature, destination-ID and MIC validation are unchanged. No
public signatures, storage formats, wire schemas, threads or production memory
allocations were added.

## Official results

| Case | Previous binary | Corrected binary |
| --- | --- | --- |
| TC_SC_3_4, endpoint 0 | run 309: FAIL, missing error reply | run 310: PASS, all 13 recorded steps |

The ten protocol scenarios cover incomplete resumption field pairs, invalid
resumption MIC with successful fallback to full CASE, invalid destination ID,
corrupted Sigma3 integrity, invalid initiator NOC and ICAC, invalid signature,
and signed invalid initiator/responder ephemeral public keys. Required rejection
codes reach the real controller; the fallback case must establish a session.

The installed CSA Test Harness is v2.15.1+summer2026, SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`. The actual TC_SC_3_4 source hash is
`4e01c772d7123f0f43b5a480c01ac362ec7b355078e8b0369432c8a2e5522bb5`, unchanged
from CSA01. Both executions use the same frozen endpoint-0 PICS. No test code,
expectations or PICS were weakened. [Results](csa09-results.json) retain both
attempts, source/PICS hashes and raw evidence hashes.

Latest cumulative matrix: **84 PASS, 21 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**.
Only TC_SC_3_4 was rerun here; other rows retain previous evidence. This is not
a full-catalog rerun or a certification claim.

## Local validation and limits

Seven focused Linux CTest targets pass normally and separately with
ASan/UBSan/LSan: `test_case`, `test_case_mrp`, `test_dispatch`, `test_rx`,
`test_unsecured`, `test_runtime`, `test_runtime_alloc`. Successful builds use
GCC 13.3 and upstream Mbed TLS 3.6.0 and contain no compiler warnings.
During test setup an unavailable target name was corrected; the new fixture
was also corrected to service a pending standalone ACK before expecting its
retransmission. Neither adjustment changed the official test.

The full Linux two-instance discovery/commissioning/CASE read/subscription and
selective-teardown scenario passes under Valgrind Memcheck 3.22: **0 errors,
0 bytes/blocks at exit**, 48,560 allocations and frees, no suppressed errors.
A separate ASan/UBSan/LSan scenario with reversed startup order also passes.
These integration checks are not additional CSA PASS entries.

Executed commands (private dependency paths omitted):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_case test_case_mrp test_dispatch test_rx test_unsecured test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_case|test_case_mrp|test_dispatch|test_rx|test_unsecured|test_runtime|test_runtime_alloc)$'
# Repeated in build/sanitize with -DMATTER_SANITIZE=ON.
# Full pair, with explicit executable/controller/PAA/credentials/interface/output:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
python tools/matter/check_test_map.py
git diff --check
```

| Artifact | SHA-256 |
| --- | --- |
| Source manifest, 353 matching C/H files | `8e0e57c71a6818bbf6a70f341ba6919b6ed47669ade370d2a47301122e9c92ed` |
| Previous matter-node | `3326b48499cddde0dbc992d52e389ff975ff7ecfc155e70ec016dfc597937609` |
| Final matter-node | `e75205ed2949257f7c127efa5cf45f8da80b84234ed02631411152f0c44759e0` |
| Memcheck runtime-pair-host | `b2e578ac9c8ac2dfc84c2018527fc02e31b2e80ed3741d5932eab53f05f5f054` |
| Sanitized runtime-pair-host | `22c9e3cdaa454f6b3ee34eedc39d6818331975bb72c8c2f82e17e04024ad58f3` |

Raw controller logs, credentials, state and lab paths remain outside tracked
files. Windows, physical devices, Google Test Suite and production attestation
were not revalidated in CSA09. Remaining CSA failures still require resolution.

**Next: CSA10 - Commissionable Node Discovery (TC_SC_4_1)**, starting with the
unchanged official test and its current advertisement/subtype validation result.
