# CSA04: subscription reporting and fabric-removal notifications

This pass follows CSA03 on the same five-endpoint x86 profile and the locally
supplied Matter Core R1.6.1. It preserves commissioning policy, test credentials,
PICS and official test assertions. It is partial acceptance, not certification.

## Findings and changes

- TC_IDM_4_3 failed at step 4 on unchanged Basic Information reports. The host's
  periodic meter notification marked every subscription dirty; Root did not opt
  into its existing DataVersion reporting policy. Repeated NodeLabel values built
  up in the test's queue. The reported short interval was a queue-observation
  interval, not evidence that consecutive wire ReportData packets were closer
  than the negotiated minimum. Root's Descriptor, Basic Information and General
  Commissioning now suppress unchanged values using their existing versions.
  Reads, authorization checks, heartbeats and the minimum/maximum interval
  arithmetic are unchanged. This implements the delta-report intent of Core 8.5.
- After that correction, the same unmodified test advanced to step 10 and exposed
  PATHS_EXHAUSTED: its all-clusters request contains separate cluster selectors,
  not a single empty wildcard path. The subscription's attribute-only selector
  capacity is now the named `MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS` (32), independent
  of its nine-item chunk plan and bounded capture work. Expanded results remain
  capped at 320 and snapshots at 16 KiB. Mixed attribute/event requests retain
  the nine-path limit and advertised guarantee. This is additional capacity for
  the test's request form, not a claim that the previous nine-path guarantee
  itself violated Core 2.11.2.2. There is no silent truncation or wildcard bypass.
- TC_CADMIN_1_25 failed at step 29: removing the window-opening fabric did not
  clear AdminFabricIndex. The cluster already implemented the operation, but
  runtime composition never invoked it. The fabric adapter now publishes an
  optional owner-thread notification after successful removal or rollback;
  runtime connects it to Administrator Commissioning and subscription change
  notification. Failed persistence emits no notification. Core 11.19.7.2/3
  requires the index to become null while the open window and original VendorID
  remain unchanged. Last-fabric reset follows the same notification contract.

`Matter_Fabric_Host_Events_T` gains an optional callback at the end; consumers
must rebuild against the updated header. Existing function signatures, wire
formats and durable state formats remain unchanged. Callback users stay borrowed
and must not reenter the fabric adapter. No tasks, locks or global timer registry
are introduced. Timer/deadline deduplication and a runtime next-wakeup API are
recorded for the later optimization stage in the roadmap.

Changed implementation: `matter_root.c`, `matter_im_subscribe.c/.h`,
`matter_im_read.h`, `matter_fabric_host.c/.h`, `matter_runtime.c`.
Regressions in `test_root.c` cover real Root NodeLabel subscriptions, unrelated
notifications, minimum-boundary behavior and DataVersion wrap; `test_fabric.c`
covers exactly-once successful removal notifications and absence on failures.
`test_subscribe_selectors.h` covers concrete/wildcard selector limits, chunking
and rejection before reservation; `test_subscribe_complex.h` tracks the new
attribute-only overflow boundary. Existing mixed-path tests remain enabled.

## Official acceptance

Both original failures reproduced on the CSA03 binary (runs 271/272). The first
correction passed CADMIN (274) and advanced IDM from step 4 to step 10 (273),
where the selector limit was exposed. Final-source rechecks are:

| Case | Run | Result |
| --- | --- | --- |
| TC_IDM_4_3 | 275 | PASS, all 12 scenario steps |
| TC_CADMIN_1_25 | 276 | PASS, including removal while the window remains open |
| TC_IDM_4_2 | 277 | PASS |
| TC_CADMIN_1_22 | 278 | PASS |
| TC_OPCREDS_3_8 | 279 | PASS |

[Result delta](csa04-results.json) preserves all nine attempts with step states,
source, execution-PICS and evidence hashes. The cumulative matrix becomes
**80 PASS, 25 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**. Only these five entries
were rechecked; earlier results and the linked CSA01/CSA02/CSA03 evidence remain.


TH v2.15.1+summer2026 and SDK `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`
are unchanged. The five selected test source SHA-256 values match CSA01. Endpoint
0 execution PICS retains SHA-256
`ac5938f6f10a8df788347ca006935dfa466e1f5fc3a777a53f11b910cef71c5f`.
No conformance bypass or SDK-CI flag is enabled. Each official run uses a fresh
DUT state; intermediate failures remain in the result delta. Unselected matrix
rows inherit their previous results and have not been rerun.

## Native and memory-safety acceptance

GCC 13.3.0 and official mbedTLS 3.6.0 at
`2ca6c285a0dd3f33982dd57299012dacab1ff206`. Normal and separate ASan/UBSan/LSan
builds pass the six-test selection: fabric, subscription, PASE, Root, runtime
and runtime allocation-failure injection. Final builds report no compiler
warnings under `-Wall -Wextra -Werror`. All 350 tracked C/H files match the lab.

| Artifact | SHA-256 |
| --- | --- |
| Source manifest | `e6fc831524c7b09c5e2a5baa2332491d28a65bf02c05635c304860a7a921bec1` |
| Official-test matter-node | `db095b109466a5441e6b81299ecbb99b380091223e8996a6b7c489d66f19d94c` |
| Memcheck runtime-pair-host | `462aa6a3c73321af1a4ccc22275ca8b70f1cf468e0a4e014c4aded6181b85980` |
| Sanitized runtime-pair-host | `b8ad49991557c792d05c70d60bc070f779886e9806378fa2d98f4af98e8632cd` |

The full two-instance Linux scenario passes under Memcheck (A then B) and,
separately, ASan/UBSan/LSan (B then A). Both include discovery before DUT startup,
commissioning, CASE reads/subscriptions, independent clocks/Identify/measurements,
removal of one instance while the other remains active, and both final-fabric
responses before clean process exit. Valgrind reports **0 errors, 0 bytes in
0 blocks at exit**, 48,513 allocations/frees and no suppressed errors. The
sanitized run has no sanitizer diagnostics. Test-map inventory passes (226 files,
84 native definitions, 59 core sources, 75 public headers); `git diff --check`
passes. These are local integration checks, separate from official CSA results.



Representative commands, with local lab paths omitted:

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_runtime test_runtime_alloc test_root test_im_subscribe test_fabric test_pase
ctest --test-dir build/final --output-on-failure -R '^(test_runtime|test_runtime_alloc|test_root|test_im_subscribe|test_fabric|test_pase)$'
# Separate build with -DMATTER_SANITIZE=ON, same targets and CTest selection.
# Full pair: test_discovery_startup_linux.py with explicit executable,
# chip-tool, PAA, credential, interface and output paths:
# --mode memcheck; then separately --mode sanitize --reverse.
python tools/matter/check_test_map.py
git diff --check
```

Raw logs, state and build manifests remain in ignored `build/csa04/` and the
isolated lab. No physical-device, Windows, Google Test Suite, production identity
or full-catalog recheck is implied. The historical intermittent final-fabric
response timeout is not attributed to these changes.

**Next: CSA05 — invalid Read/Subscribe paths**, starting with TC_IDM_2_2 and
shared path-validation rules, then the related official regressions. Keep CASE
resource pressure, diagnostics/discovery failures and production-identity/manual
fixtures in the subsequent CSA passes; tariffs remain deferred.
