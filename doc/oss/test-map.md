# Test inventory

test-map.json enumerates 228 test, fixture, fuzz and controller files. Run
`python tools/matter/check_test_map.py` to verify coverage, current dependency
source membership and the closed public-header set.

CMake defines 85 native test variants, with explicit platform/privilege filters.
Default CTest totals: 86 on Windows, 83 on Linux, including inventory, crash
recovery and a relocated installed-package consumer with two runtimes.
`test_node_discovery` drives the real host advertisement composition through
deferred removal and rapid window reopening with a deterministic backend.
`test_dispatch` also drives malformed CASE input through ingress and the real
engine into reliable failure-report delivery, retry and ACK/exhaustion/stop drain.
`test_discovery` covers service/subtype enumeration and shared-record suppression;
`test_mdns_linux.py` verifies enumeration and known-answer thresholds on multicast
alongside its existing TC/NSEC/address/duplicate-response checks.
`test_opcreds` exercises five-fabric NOCs/Fabrics subscription chunking and
DataVersion suppression; `test_root` and `test_im_subscribe` cover unrelated
notifications, retained heartbeat deadlines, late owner-loop wakeups and bounded
exchange/status timeouts. CSA11 retains failing controls with the old behavior.
`test_pase` also checks one-shot failure notifications and success/cancel
exclusions. `test_runtime` and its allocation variant inject failed PASE requests
and duplicates through public ingress, checking the twentieth-attempt closure
and isolation of another runtime. CSA12 records a failing old-runtime control.
`test_fabric` also fills the fabric table and admits a distinct pending RCAC,
checks signature/storage errors and TableFull, then verifies rollback/root-only
journal recovery without changing installed records or keys. CSA13 records its
failing old-host control and the unchanged official CADMIN 1.19/OPCREDS 3.1 results.

External CHIP/TH, Matter.js network scenarios, fuzz campaigns and privileged
IPv6 injection are optional, not implied by default CTest results. Their scripts
and prerequisites are retained in tools/matter/tests and fixtures. See each
entrypoint and the map for exact routes; generators are not build prerequisites.
No CSA test distribution is bundled, and no local result waives open CSA failures.
