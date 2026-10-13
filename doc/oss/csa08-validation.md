# CSA08: General Diagnostics runtime acceptance

## Defects reproduced and corrected

Both unchanged official cases failed against the CSA07 binary. TC_DGGEN_2_4
received a null PosixTimeMs despite a non-null Time Synchronization UTCTime after
SetUTCTime. TC_DGGEN_2_5 observed zero IM and subscription counters before and
after establishing three subscriptions across two fabrics. The cluster could
encode both attributes, but the full runtime had never connected their sources.
The earlier focused diagnostics fixture supplied counters explicitly, which
did not validate the full runtime composition.

The supplied Core 1.6.1 sections 11.12.7.2/11.12.7.3 require a correlated system
and wall-clock snapshot. PosixTimeMs cannot be null when the node supports Time
Synchronization and its UTCTime is non-null. The runtime now reads the attached
cluster's actual UTC and converts microseconds since 2000 to POSIX milliseconds.
Absent/unsynchronized UTC remains null; certificate Last Known Good time and an
independent host wall clock are not substituted. The application's clock tick
also supplies SystemTimeMs and system-time event timestamps.

Core 11.12.5's DeviceLoadStruct requires lifetime IM counts excluding retries,
active subscriptions for the node/accessing fabric, lifetime established
subscriptions and saturating counters. The runtime now composes these values
from the dispatcher. Incoming standard IM is counted after validated admission
with replay classification, including messages later rejected by a handler.
Outgoing standard IM is counted on successful local UDP completion once per
message, independent of MRP acknowledgement/retransmission. Failed sends,
standalone ACKs, secure-channel and BDX messages do not increase IM TX counts.
Subscriptions become established after successful local SubscribeResponse
delivery; reservations do not count. Closing/released/retired subscriptions stop
contributing to current totals, without decrementing the lifetime total.

Changes are scoped to runtime/diagnostics/RX and their existing regression files:
`matter_runtime.c` supplies the snapshot, `matter_dispatch.c/.h` exposes load,
`matter_rx.c/.h` counts admitted IM, and `matter_diagnostics.c/.h` includes active
PASE subscriptions only in the node total. No threads or new large stack buffers
were introduced. The added public snapshot field requires consumers to rebuild;
existing constructors, callbacks, storage format and wire schemas remain intact.

## Official results

| Case | Previous binary | Corrected binary |
| --- | --- | --- |
| TC_DGGEN_2_4 | run 305: FAIL, null PosixTimeMs | run 307: PASS |
| TC_DGGEN_2_5 | run 306: FAIL, counters remain zero | run 308: PASS |

The corrected DeviceLoadStatus read changes from 0 to 3 active subscriptions,
0 to 2 for TH1's fabric, and 0 to 3 lifetime establishments. Both IM counters
increase from 32 to 45. TimeSnapshot's two system/UTC samples advance together
by 1025 ms. TC_DGGEN_2_5 completes all steps including TH2 fabric removal.
The recorded final step summaries contain 3 and 11 passed steps respectively,
with no failed/pending steps. TC_DGGEN_2_4 takes its Time Synchronization branch;
the alternative no-Time-Synchronization branch is not an additional official
acceptance result.

Test Harness **v2.15.1+summer2026**, SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`. Actual installed source hashes match
CSA01: TC_DGGEN_2_4
`c4e4e7bcd0b5aa7555b22f6bb2343a31abac95c59ac4f7d03d40c104ffd50c06`,
TC_DGGEN_2_5
`929fe4b4efc82b15de9e7adcccd36fe732888409c2636328884afdaa13653ef7`.
No official assertions/scripts, cluster revision, feature declarations or PICS
were changed. All four runs use fresh isolated DUT state and the same execution
PICS hash `ac5938f6f10a8df788347ca006935dfa466e1f5fc3a777a53f11b910cef71c5f`.

[All attempts](csa08-results.json) retain failures and final results, source/log
hashes and the previous-result chain. The latest combined matrix is **83 PASS,
22 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Only these two cases were rerun;
unselected rows retain earlier results. This is not certification or a full
catalog rerun. The CSA06 test/specification disputes and CSA07 historical
discovery attribution uncertainty remain open.

## Native and memory validation

Six focused CTest targets pass both normally and separately with ASan/UBSan/LSan:
`test_diagnostics`, `test_dispatch`, `test_rx`, `test_runtime`,
`test_runtime_alloc`, `test_time_host`. New regressions check duplicate RX,
backpressure, malformed input, failed admission, independent counters, failed TX,
retries, reservations versus established subscriptions, fabric/PASE scope,
cancellation, counter saturation and UTC conversion including UINT64_MAX.
The runtime test uses the real Time Synchronization cluster and verifies absent,
unsynchronized and valid UTC while retaining two independent runtimes. Existing
allocation-failure coverage runs against the expanded composition.

The full Linux two-runtime controller scenario also passes under **Valgrind
Memcheck**, with **0 errors, 0 bytes/blocks at exit**, 48,541 allocations and frees,
and no suppressed errors. A separate ASan/UBSan/LSan scenario in reverse startup
order passes. Both cover discovery before DUT startup, coherent DNS-SD records,
commissioning, CASE reads/subscriptions and selective teardown. These are local
integration checks, not extra CSA PASS entries. Successful build logs have no
compiler warnings. The first private shell invocation failed on Windows line
endings before compilation; its script was corrected before these builds.

Executed commands (private dependency paths omitted):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_diagnostics test_dispatch test_rx test_runtime test_runtime_alloc test_time_host
ctest --test-dir build/final --output-on-failure -R '^(test_diagnostics|test_dispatch|test_rx|test_runtime|test_runtime_alloc|test_time_host)$'
# Repeated in build/sanitize with -DMATTER_SANITIZE=ON.
# Full pair, with explicit executable/controller/PAA/credentials/interface/output:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
python tools/matter/check_test_map.py
git diff --check
```

| Artifact | SHA-256 |
| --- | --- |
| Source manifest, 353 matching C/H files | `5cbb7890a44eed971c27709c5e991a5d1e0f5b1fcb6c25833fb19f62c4ed7d5c` |
| Previous matter-node | `091cd7434c723e32a7dd044b9ce24788b9b8f2240a1cb37f2fe8a80813cd5e12` |
| Final matter-node | `3326b48499cddde0dbc992d52e389ff975ff7ecfc155e70ec016dfc597937609` |
| Memcheck runtime-pair-host | `481ab3970303f24df104b66d2c2267aac1399a7e32316ef77f8b2212a937c8f3` |
| Sanitized runtime-pair-host | `f23ef9852ac92e64aebd02395a5dc55f0e9268cfa1766cddbc8bb699965d24f7` |

Raw logs, lab configuration, captures and fixture paths remain in ignored lab
artifacts. Windows, physical devices, Google Test Suite and production
attestation were not revalidated in CSA08. The full catalog must still be rerun
after resolving remaining failures.

**Next: CSA09 - invalid CASE input (TC_SC_3_4)**, beginning with the existing
invalid-parameter response timeout and unchanged official test.
