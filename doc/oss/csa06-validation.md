# CSA06: Access Control validation

## Outcome and scope

All four applicable Access Control cases in the installed catalog were rerun
against the frozen x86 profile. Latest results are **2 PASS and 2 FAIL**.
TC_ACL_2_8 first failed during discovery and then passed without a source or
configuration change; that intermittent failure remains open. The two repeatable
ACL failures are documented test/specification discrepancies requiring explicit
CSA resolution. Neither is waived. No production implementation was changed.

The preceding CSA03-CSA05 work was committed as `0014b0a`. CSA06 adds regression
coverage and evidence. It does not establish complete Access Control acceptance
or certification.

## TC_ACL_2_4: deprecated ProxyView

The unchanged test stops at scenario step 16: writing privilege value 2
(ProxyView) is expected to succeed, but the DUT returns ConstraintError.
Core 1.6.1 section 9.10.5.2 marks this enum value **D**. Section 7.3.8 defines D
alone as disallowed for the current revision, while earlier revisions may
support it. The existing `matter_acl.c` validator accepts View, Operate, Manage
and Administer and rejects ProxyView; this behavior was preserved.

This is a mismatch between the supplied September 16, 2026 Core 1.6.1 document
and the installed SDK test expectation, not authorization to silently change
either. Scenario steps 17-45 remain unexecuted after that failure. Local negative
tests do not substitute for their official acceptance.

## TC_ACL_2_6: three operations, three statuses

The full-list encoding passes, including rejection of group ID 0 and the event
check. The test then repeats using legacy list encoding and fails at scenario
step 6. The legacy WriteRequest contains these operations:

| Operation | DUT WriteResponse status |
| --- | --- |
| Replace ACL with an empty list | Success |
| Append the valid CASE administrator | Success |
| Append the invalid group-0 entry | ConstraintError (0x87) |

The test asserts `result[0].Status == ConstraintError`, inspecting the successful
clear operation instead of the rejected append. A separate diagnostic DUT logged
the encoded response during the unchanged official test: modern `[135]`, legacy
`[0, 0, 135]`. The failure is not acceptance of group 0.

Core 1.6.1 sections 8.7.3.3 and 8.7.3.4 require status generation for processed
data and inclusion of each generated AttributeStatusIB in WriteResponses.
Section 10.6.4.3.1 describes clear/append list encoding and cautions clients not
to assume unchanged contents after a list-write error. Consequently, the valid
operations can change the list and generate events while the invalid entry
must not. Section 10.6.2.4 permits null ListIndex only in AttributeDataIB, so
adding it to a status path would not resolve this correctly.

The diagnostic build adds only private response-status logging before output.
It is separate from the normal/sanitized builds, and its result is labelled
diagnostic, not a final acceptance result. Source bytes were restored and all
352 C/H manifest entries rechecked. Official test scripts were never modified.

## Official attempts

| Case | Run | Result and boundary |
| --- | --- | --- |
| TC_ACL_2_4, CSA05 binary | 284 | FAIL, ProxyView at step 16 |
| TC_ACL_2_6, CSA05 binary | 285 | FAIL, legacy first-status assertion |
| TC_ACL_2_2 | 286 | PASS, attributes and supported limits |
| TC_ACL_2_4 | 287 | FAIL, same ProxyView expectation |
| TC_ACL_2_6 | 288 | FAIL, same legacy assertion |
| TC_ACL_2_8 | 289 | FAIL, mDNS timeout in legacy scenario step 3 |
| TC_ACL_2_6, diagnostic build | 290 | FAIL; confirms all three encoded statuses |
| TC_ACL_2_8, unchanged final binary | 291 | PASS, modern and legacy multi-fabric ACL/events |

In run 289, the modern multi-fabric checks passed. During the legacy repetition,
TH1 commissioned successfully, opened another commissioning window, then TH2
timed out in CommissionOnNetwork discovery. Run 291 completed on the same binary.
A multicast capture was retained for that passing recheck; there is no matching
packet capture for the failed attempt. The failure's cause is not established,
and the recheck must not be described as a discovery fix.

The successful TC_ACL_2_8 has the test's own skip of the recursive rerun marker
on its second pass; TH also labels its optional Show test logs step not
applicable. This is not a claim of zero skipped/not-applicable steps. ACL
Extension cases 2.3/2.5/2.7/2.9/2.10 and ManagedDevice case 2.11 remain NA under
the existing PICS; those features were not enabled just to expand test counts.

Test Harness v2.15.1+summer2026, SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`; all four actual script hashes match
CSA01. Each run starts with fresh DUT state. Execution PICS SHA-256 is unchanged:
`ac5938f6f10a8df788347ca006935dfa466e1f5fc3a777a53f11b910cef71c5f`.

[All attempts](csa06-results.json) retain failures, diagnostic provenance,
source/PICS/evidence hashes and step states. The cumulative **latest-status**
matrix remains **81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Unselected
rows are inherited. These counts do not close run 289's intermittent failure.

## Regression and memory checks

`tools/matter/tests/test_acl.c` adds 16 invalid privilege/auth-mode/subject
vectors, each through REPLACE and ADD. It checks rejection without persistence,
data-version changes or events, retention of the administrator, and isolation
of the other fabric. It also submits encoded modern and legacy WriteRequests
through the real IM write executor and ACL cluster callbacks, decodes every
returned status, and checks storage/version/event effects. Legacy clear/add
produces only the valid administrator's Removed/Added events; group 0 is absent.
Large fixtures and request buffers use checked heap allocations with cleanup.

Six focused tests pass normally and separately with ASan/UBSan/LSan:
`test_acl`, `test_acl_alloc`, `test_im_write`, `test_fabric`, `test_runtime`,
`test_runtime_alloc`. GCC 13.3.0, official mbedTLS 3.6.0 commit
`2ca6c285a0dd3f33982dd57299012dacab1ff206`; successful build logs contain no
compiler warnings. No API, persistence format, limits or scheduling changes.

The full two-instance Linux scenario passes under Valgrind 3.22.0 Memcheck
(A then B) and separately ASan/UBSan/LSan (B then A). It covers discovery before
startup, commissioning, CASE reads/subscriptions, independent meter/clock/Identify
callbacks and deletion/final-fabric responses. Memcheck: **0 errors, 0 bytes in
0 blocks at exit**, 48,540 allocations and frees, no suppressed errors. The
separate sanitized run exits cleanly. These are integration regressions, not
additional official CSA results.

| Artifact | SHA-256 |
| --- | --- |
| Source manifest | `f1804b465ccfb1ce67183e1ab78f721c1137f6d12fb4d298bd61428108e2fd8d` |
| Official-test matter-node | `3d9a196ed4623175e82881901af28985408a40d11c2727e8a01231dd7d12db36` |
| Diagnostic matter-node | `f52aa7c8841bcf5b8335074ee2cc30c6a961949bd321499ef9a555f40733b535` |
| Memcheck runtime-pair-host | `742968d17e59675d2787ce080d0867a272590b26895a05e8ed6fc0942624f668` |
| Sanitized runtime-pair-host | `96da843725b702bb26f04dbc89c6bb5a78ba053d7b2248b43052eb46d116bf03` |

Representative executed commands (private lab paths replaced):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_acl test_acl_alloc test_im_write test_fabric test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_runtime|test_runtime_alloc|test_acl|test_acl_alloc|test_im_write|test_fabric)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# Full two-instance controller scenario, with explicit private fixture paths:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
# Run the exact-case TH runner separately for TC_ACL_2_2, 2_4, 2_6 and 2_8.
python tools/matter/check_test_map.py
git diff --check
```

The test inventory remains 227 mapped files, 84 native definitions, 59 core
sources and 75 public headers. Specifications, raw logs, packet captures,
diagnostic instrumentation, manifests and private fixtures stay outside tracked
files in ignored build data/the lab. Windows, physical firmware, Google Test
Suite, production attestation and the complete CSA catalog were not rerun.

## Questions prepared for CSA resolution

No issue or message has been sent externally. The evidence above supports two
specific questions for the pinned test release:

1. Which revision should TC_ACL_2_4 step 16 enforce, given ProxyView's D
   conformance in Core 1.6.1 section 9.10.5.2? How should the subsequent steps
   be accepted without introducing a disallowed privilege?
2. Should TC_ACL_2_6 legacy step 6 inspect the failed append's status among the
   returned AttributeStatusIBs, or does the Python helper contract require
   aggregating them? The current assertion reads only `result[0]`; the DUT
   returns `[Success, Success, ConstraintError]` and stores no group-0 entry.

**Next: CSA07 - repeated commissioning discovery**, starting with the unresolved
TC_ACL_2_8 timeout. Capture the failing window transition and correlate queries,
announcements and controller cache state before selecting a fix. General
Diagnostics failures and remaining catalog gaps follow in the next acceptance
passes. Tariffs, timer consolidation and allocation optimization remain deferred.
