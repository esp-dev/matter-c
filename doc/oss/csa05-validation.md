# CSA05: invalid Read/Subscribe attribute paths

## Defect and normative basis

The unchanged TC_IDM_2_2 reproduced the earlier failure in run 280 on the CSA04
binary: step 18 read a non-global attribute with a wildcard cluster and received
data instead of InvalidAction. Both Read and Subscribe decoded that combination
without checking whether the attribute was global. The old native wildcard test
also incorrectly expected all eight presence masks to work for a non-global ID.

Core 1.6.1 section 8.9.2.6 applies the same valid-path table to Read and Subscribe.
A specific attribute with a wildcard cluster must be global, independently of
whether the endpoint is concrete or wildcard. Section 7.21.2.2 assigns global
attributes the Standard prefix and suffix range 0xF000..0xFFFE. Checking only the
suffix, or allowing only today's implemented global attributes, would be wrong.
The supplied specification was inspected locally; its text and raw lab records
are not included in this repository.

## Implementation and regression scope

`matter_im_paths_internal.h` provides one allocation-free grammar predicate used
by both request decoders in `matter_im_read.c` and `matter_im_subscribe.c`.
InvalidAction rejects the entire request before enumeration, attribute access,
value reads or subscription reservation. An earlier valid path does not cause
partial execution when a later path is invalid. Existing existence/ACL checks,
wildcard omissions, global wildcard reads, filters and report chunking remain.
No public ABI, persistent format, default capacity or scheduling change is made.

`test_im_path_grammar.h` sends 256 encoded requests to each real decoder. It covers
all eight selector masks, global-range edges, reserved values, manufacturer
prefixes, and an earlier valid path followed by each candidate path. It checks
the status response and absence of callbacks/resources for malformed requests,
and successful reads plus reservation/release for valid grammar. These are
synthetic model fixtures for grammar, not claims that reserved IDs exist in the
host profile. `test_im_wildcard.h` corrects the old invalid expectation; the
existing malformed TLV, event path, unsupported path, filter and ACL tests remain.

The new helper is private in `cmake/sources.json`. Both decoder tests include the
new fixture, recorded in `doc/oss/test-map.json`; CTest entrypoints are unchanged.

## Official acceptance

| Case | Run | Result |
| --- | --- | --- |
| TC_IDM_2_2, CSA04 baseline | 280 | FAIL, step 18 |
| TC_IDM_2_2, corrected source | 281 | PASS, all 21 scenario steps |
| TC_IDM_4_2 | 282 | PASS, including global-attribute wildcard subscriptions |
| TC_IDM_4_3 | 283 | PASS, including broad cluster subscriptions and change reports |

All steps in the three final runs passed; none were skipped. Test Harness
v2.15.1+summer2026, SDK `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`, test sources
and endpoint-0 PICS are unchanged from CSA01. Actual SDK source files and version
were checked against the baseline hashes. Execution PICS SHA-256 remains
`ac5938f6f10a8df788347ca006935dfa466e1f5fc3a777a53f11b910cef71c5f`.
No certification bypass or modified official test was used; each run started
with a fresh DUT state.

[Result delta](csa05-results.json) retains the reproduced failure and all final
runs, with evidence/source/PICS hashes and step counts. The cumulative matrix
is **81 PASS, 24 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. Only the three selected
rows were rerun. Read negative paths have direct official coverage in steps
18/19; the exhaustive negative Subscribe grammar matrix is a native wire test,
not a separate official CSA result.

## Build and native acceptance

GCC 13.3.0 and official mbedTLS 3.6.0 at
`2ca6c285a0dd3f33982dd57299012dacab1ff206`. Six focused CTest cases pass normally
and separately with ASan/UBSan/LSan: Read, Subscribe, Root, runtime, Read
allocation failures and runtime allocation failures. Both successful builds
report zero compiler warnings under `-Wall -Wextra -Werror`. All 352 C/H files in
the source manifest match the lab. The initial private build script referenced
a nonexistent Subscribe allocation target; its target selection was corrected
before the complete successful build/test runs.

| Artifact | SHA-256 |
| --- | --- |
| Source manifest | `70e4ae1501d4e5e39c5aad591dd0aca3264f38243ee3251094174f6e72bff820` |
| Official-test matter-node | `3d196051ddf92788bd45f4cf48d7bd5b796c18c62b00ac4b7008bbcf77db4b0a` |
| Memcheck runtime-pair-host | `44d8ccc1f15c18cf8d01c2a09a6c301dabb1b384d32f9a4599975d396f32cb5c` |
| Sanitized runtime-pair-host | `db7fef6114e0495c488b3de5203fe95894dbbe8e1861122d5289b20579c00834` |

The full two-instance Linux scenario passes with an independent chip-tool under
Valgrind 3.22.0 Memcheck (A then B) and separately ASan/UBSan/LSan (B then A).
Both cover browsing before startup, commissioning, CASE reads/subscriptions,
independent measurement/clock/Identify callbacks, selective instance deletion,
and both final-fabric responses before clean exit. Memcheck reports **0 errors,
0 bytes in 0 blocks at exit**, 48,532 allocations and 48,532 frees, with no
suppressed errors. The separate sanitized run has no sanitizer diagnostics.
These are integration regressions, not additional CSA PASS entries.

Test-map inventory passes: 227 mapped files, 84 native definitions, 59 core
sources, 75 public headers. `git diff --check` passes. All test-owned nodes exit
and the Test Harness returns to idle.

Representative commands (local lab paths omitted):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_im_read test_im_read_alloc test_im_subscribe test_root test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_runtime|test_runtime_alloc|test_root|test_im_subscribe|test_im_read|test_im_read_alloc)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# Full pair, explicit executable/controller/PAA/credentials/interface/output:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
python tools/matter/check_test_map.py
git diff --check
# Official exact-case runner, once for each selected case:
python tools/matter/th/run_exact.py --project-id PROJECT_ID --tests-list TC_IDM_2_2 --title CSA05 --no-color
```

Raw TH logs, manifests, state and credentials stay in ignored `build/csa05/` or
the private lab. No Windows, physical-device, Google Test Suite, production
identity or full-catalog recheck is implied. Node/ListIndex/tag-compression and
provisional nonzero wildcard-flag limitations have not been expanded here.

**Next: CSA06 - Access Control validation**, starting with the remaining
TC_ACL_2_4 ProxyView acceptance and TC_ACL_2_6 ConstraintError failure. Check the
exact writes against Core 1.6.1 and rerun the unchanged official ACL scenarios;
retain other diagnostics, discovery, resource and fixture gaps for subsequent
passes. Tariffs and timer consolidation remain deferred.
