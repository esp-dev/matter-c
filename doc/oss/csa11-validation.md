# CSA11: resource minima and concurrent subscriptions

## Reproduction and repair

The unchanged TC_RR_1_1 reproduced a Subscribe timeout on the CSA10 binary
(run 314), while establishing client 13 of 15. The test commissions five fabrics
and three controllers per fabric, fills ACL entries and subscribes to NodeLabel,
Operational Credentials and Descriptor. All declared session/subscription pools
already provided these minima; increasing array sizes would not fix the cause.

Periodic host measurement notifications marked every subscription dirty.
Operational Credentials did not opt into the existing DataVersion reporting
policy, so unchanged NOC/fabric lists were repeatedly transmitted and chunked.
Enabling that policy reduced traffic, but run 315 still timed out at client 14:
the subscription engine continued sending empty reports on every unrelated
notification. The log near that failure contains repeated 43-byte ReportData
messages. Both sources of excess traffic had to be addressed.

- `matter_opcreds.c` uses its existing cluster/fabric revision for subscription
  reporting of scalar, metadata and fabric attributes. Current-value Reads,
  fabric filtering, and authorization are unchanged. VID, label, credential,
  removal and rollback mutations remain covered by that revision.
- `matter_im_subscribe.c/.h` returns an attribute-only update to IDLE without
  output when no selected data/status changed and the maximum interval is not
  due. It preserves the last-report and last-activity clocks, so unrelated dirty
  notifications cannot postpone heartbeats. Access failures, terminal reports,
  initial priming, real changes and maximum-interval empty reports still execute.
  Event/mixed subscriptions keep their existing cursor/report behavior.

Run 316 then passed RR, and run 317 passed its optional unchanged-session-ID
assertions. The reporting recheck TC_IDM_4_3 (run 318) exposed a third issue:
the old clock guard terminated an idle subscription if the owner loop ran even
one millisecond after MaxInterval. Earlier excess reports had masked this by
continually refreshing liveness. The final engine treats MaxInterval as due work,
requests the heartbeat on a late wakeup and keeps the existing timeout on exchange
admission/delivery. It does not silently cancel an idle subscription for normal
scheduler jitter. Peer errors and exchanges that cannot progress still terminate
and release their reservation. Applications must still honor returned deadlines;
this is not permission to schedule arbitrarily late.

This follows supplied Core 1.6.1 sections 2.11.2.1/2 (per-fabric Read and Subscribe
minima) and 8.5 (delta reporting, minimum interval and maximum-interval liveness).
The 3 CASE sessions and 3 subscriptions per fabric, 9 Read paths, 3 Subscribe
paths, transport quotas, application-owned scheduling and public function
signatures remain unchanged. No new allocation, thread or global state is added.

## Official acceptance

Final results and every preceding attempt are in [the result delta](csa11-results.json).
The passing TC_RR_1_1 runs show all 15 controllers establish subscriptions,
receive the changed NodeLabel without resubscription and read it back, alongside
the nine-path Read and fabric/ACL checks. A further run enables the script's
existing `check_local_session_id_unchanged:True` option to check the same local
CASE session IDs and exactly one session per controller. The final binary passes
that stricter RR run (319) and all 15 TH records of TC_IDM_4_3 (320).
The latter covers empty heartbeats, minimum/maximum intervals, changes,
KeepSubscriptions replacement/retention, mixed reports and wildcard attributes.

The cumulative matrix is **86 PASS, 19 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**.
Only these two selected rows were rechecked; other results are inherited.

TH v2.15.1+summer2026 and SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf` are unchanged. Script hashes match CSA01;
the endpoint-0 profile and execution PICS remain unchanged. No official test
source, expectation, client count or reporting interval was weakened. The
1500-second harness timeout is the same as the baseline run; only the additional
session-ID assertion differs in the stricter run. Temporary parameters are
restored after each execution.

RR uses the legacy script format: TH records three wrapper steps, not individual
numbered scenario steps. UserLabel (step 9), legacy Groups/group-key filling
(steps 12-15), and Groupcast (16-21) are not exercised because their prerequisite
clusters are absent. This is not full group-resource or production certification.
Optional Software Diagnostics heap-watermark assertions are not enabled.

## Regression and memory checks

`test_fabric_subscribe.h` exercises real five-fabric NOCs/Fabrics, filtered and
unfiltered chunk reassembly, suppressed unrelated updates, and subsequent VID
changes. Existing rollback subscription coverage also passes. `test_root.c` and
`test_im_subscribe.c` cover no-output updates, retained heartbeat deadlines,
minimum intervals, DataVersion wrap, real changes and authorization failure.
Running the new tests with the old Operational Credentials source and separately
with the old subscription source fails at the expected no-output assertions.
Restoring just the old exact-tick expiry also fails the late-wakeup regression;
the final tests additionally check delayed transport submission, the next actual
TX-based deadline and bounded expiry while waiting for exchange admission/status.

Seven Linux CTest targets pass normally and separately with ASan/UBSan/LSan:
`test_opcreds`, `test_fabric`, `test_im_subscribe`, `test_dispatch`, `test_root`,
`test_runtime`, `test_runtime_alloc`. GCC 13.3 and official Mbed TLS 3.6.0 builds
complete without compiler warnings under the existing warning-as-error policy.

The full two-instance Linux scenario passes under Valgrind Memcheck: zero errors,
zero bytes/blocks at exit, 48,556 allocations/frees, no suppressions. The separate
sanitized run starts the instances in reverse order and also passes. These cover
real commissioning, CASE reads/subscriptions, selective teardown and clean exit.
An earlier pair attempt overlapped the TH DUT and failed before DUT launch:
chip-tool could not bind its own UDP port 5551. Its logs are retained privately;
the final memory scenarios run sequentially with TH to avoid that lab collision.

Executed checks include:

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_opcreds test_fabric test_im_subscribe test_dispatch test_root test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_opcreds|test_fabric|test_im_subscribe|test_dispatch|test_root|test_runtime|test_runtime_alloc)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# test_discovery_startup_linux.py with explicit executable/controller/PAA/credentials:
# --mode memcheck; then separately --mode sanitize --reverse.
python tools/matter/check_test_map.py
git diff --check
```

Private raw TH logs, credentials, states, captures, lab scripts and build manifests
remain ignored. Tracked result links hash Git blob bytes (LF); execution/build
artifacts use byte-for-byte hashes. Windows, physical devices, Google Test Suite
and the full CSA catalog were not rerun. Earlier test/specification discrepancies
remain open; no CSA waiver is implied.

The result delta includes SHA-256 identities of the final normal/sanitized node
and pair host, the 353-file C/header manifest, official scripts/PICS and retained
logs. Local and VM source bytes match that manifest after the old-code controls
were restored. Both memory scenarios use these final binaries.

**Next: CSA12 - repeated incorrect passcodes and commissioning-window behavior
(TC_CADMIN_1_9).** Reproduce the rejection/rate-limiting failure and reconcile the
window lifecycle with Core, without weakening the official test.
