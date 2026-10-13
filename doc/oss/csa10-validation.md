# CSA10: Commissionable Node Discovery

## Cause and implementation

Unchanged TC_SC_4_1 fails on the CSA09 binary (run 311): direct lookup of the long
discriminator succeeds, but enumeration returns no commissionable subtypes.
The installed `MdnsDiscovery.get_commissionable_subtypes()` obtains service
types through `AsyncZeroconfServiceTypes.async_find()` and filters their names
for `._sub._matterc._udp.local.`. Our host responder did not answer the
`_services._dns-sd._udp.local.` meta-query at all.

Core 1.6.1 section 4.3.1 uses DNS-SD, with discriminator and commissioning-mode
subtypes specified in 4.3.1.3. [RFC 6763 section 9](https://datatracker.ietf.org/doc/html/rfc6763#section-9)
describes enumeration of base service types. Listing subtype browse names in
the same response is an extension used by the
[CHIP minimal advertiser](https://github.com/project-chip/connectedhomeip/blob/master/src/lib/dnssd/Advertiser_ImplMinimalMdns.cpp)
(`SetReportInServiceListing(true)` on base and subtype responders) and expected
by the installed TH. This change deliberately supports that interoperability
behavior; subtype enumeration is not presented as an explicit RFC requirement.

`tools/matter/host/matter_mdns_windows.c` now answers that meta-query with the
base service and the currently configured subtype names. Commissionable and
operational publications use the same mechanism. The response uses shared PTRs
without cache flush and does not append unrelated instance SRV/TXT/address
records. Virtual record bits reuse existing names and response machinery;
there is no second record array, new allocation or thread. Public APIs,
persisted state and direct instance/subtype lookup are unchanged.

The new records participate in known-answer suppression, TC continuations,
duplicate-answer suppression, QU/legacy routing and existing publication/stop
gates. They are not unique names to probe or assert with NSEC. Existing shared
publication announcements and goodbyes are unchanged. In Extended Discovery,
the published list no longer contains `_CM`; other instances keep their own
publication state.

## Official acceptance

| Case | Previous binary | Corrected binary |
| --- | --- | --- |
| TC_SC_4_1 | run 311: FAIL, subtype enumeration empty | run 312: PASS |
| TC_SC_4_3 | previously PASS in the matrix | run 313: PASS, operational discovery recheck |

TC_SC_4_1 passes enhanced OpenCommissioningWindow discovery (`CM=2`), long and
short discriminator subtypes and `_CM`, consistent instance/host names, SRV,
TXT and AAAA records, then Extended Discovery after RevokeCommissioning (`CM=0`,
no `_CM`). **21 recorded steps pass and 9 are N/A**: the Basic Commissioning
Window feature is absent in this existing profile. Those steps are not claimed
as executed. TC_SC_4_3 passes all 15 recorded steps.

TH remains v2.15.1+summer2026 with SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`. Both official script hashes match
CSA01; the discovery helper hash was also recorded. The endpoint-0 profile and
execution PICS are unchanged. No script, expectation or capability declaration
was altered to obtain PASS. [Results](csa10-results.json) preserve all three
attempts, including the baseline failure, and their evidence/source hashes.
Hashes linking tracked baseline/previous reports use Git blob bytes (LF), so
they survive Windows working-copy newline conversion. Private execution/build
artifacts retain byte-for-byte hashes of the actual tested files.

Latest cumulative matrix: **85 PASS, 20 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**.
Unselected rows are inherited; this is not a full-catalog rerun or certification.

## Regression and memory evidence

`test_discovery.c` covers exact listing names for commissioning modes 0/1/2 and
operational discovery, supported subtype capacity, wire TTL/class, PTR/ANY,
case-insensitive names, no negative assertion on the shared name, known-answer
thresholds, TC completion, co-owner duplicate suppression, QU/legacy replies
and the publication gate. `test_mdns_known_answers.h` can construct virtual
records for these cases while retaining its existing tests.

`test_mdns_linux.py` adds real multicast enumeration and TTL59/60 known-answer
checks to the independent wire oracle. On the previous binary it fails at the
new enumeration assertion after ordinary discovery succeeds. On the corrected
binary **35/35 checks pass**, including existing TC, NSEC, address-family,
duplicate-response and clean-stop checks. Logs/captures and source/result hashes
are retained separately from official CSA results.

Six focused Linux CTest targets pass normally and separately with ASan/UBSan/LSan:
`test_discovery`, `test_discovery_alloc`, `test_mdns`, `test_mdns_alloc`,
`test_node_discovery`, `test_runtime`. The successful GCC 13.3/upstream Mbed TLS
3.6.0 builds contain no compiler warnings. An initial enum-comparison warning
in the new compile-time mask bound was corrected before these builds.

The full two-instance scenario passes under Valgrind Memcheck 3.22 with **0 errors,
0 bytes/blocks at exit**, 48,545 allocations/frees and no suppressed errors.
A separate ASan/UBSan/LSan run with reversed startup order also passes. They
exercise discovery before startup, two independent runtimes, commissioning,
CASE reads/subscriptions and selective teardown.

Executed commands (private paths omitted):

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_discovery test_discovery_alloc test_mdns test_mdns_alloc test_node_discovery test_runtime
ctest --test-dir build/final --output-on-failure -R '^(test_discovery|test_discovery_alloc|test_mdns|test_mdns_alloc|test_node_discovery|test_runtime)$'
# Repeated in build/sanitize with -DMATTER_SANITIZE=ON.
python tools/matter/tests/test_mdns_linux.py --node /path/to/matter-node --interface 2 --credentials /private/credentials --output /private/wire-results
# Full pair, with explicit executable/controller/PAA/credentials/interface/output:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
python -m py_compile tools/matter/tests/test_mdns_linux.py
python tools/matter/check_test_map.py
git diff --check
```

| Artifact | SHA-256 |
| --- | --- |
| Source manifest, 353 matching C/H files | `0cafd4480af4d240deef9a52f02b146e6de3ea933e1f49598b3b8a8cf7b4bf93` |
| Previous matter-node | `e75205ed2949257f7c127efa5cf45f8da80b84234ed02631411152f0c44759e0` |
| Final matter-node | `6422f697931995146e4adfd403f5f6f6acf19ec28b1ceaace625a24c506449e6` |
| Memcheck runtime-pair-host | `ff057a81c823c47cde5efe18a35ce6d637bede143284ed735540b3dd9c90de41` |
| Sanitized runtime-pair-host | `7eabc2a1891fd251f5ea8cb83a87f1b4b8d93652d45b8be0a6cd2b4e9cf232df` |

Private credentials, state, LAN captures and raw TH logs remain outside tracked
files. Windows, physical devices, Google Test Suite and production attestation
were not revalidated. Historical discovery timeout attribution from CSA07 is
not broadened by this independent enumeration fix.

**Next: CSA11 - resource pressure and concurrent subscriptions (TC_RR_1_1).**
Reproduce its session/subscription timeout against the declared CapabilityMinima
and repair the actual lifetime or admission issue without weakening the test.
