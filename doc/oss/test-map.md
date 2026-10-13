# Test inventory

test-map.json enumerates 228 test, fixture, fuzz and controller files. Run
`python tools/matter/check_test_map.py` to verify coverage, current dependency
source membership and the closed public-header set.

CMake defines 85 native test variants, with explicit platform/privilege filters.
Default CTest totals: 86 on Windows, 83 on Linux, including inventory, crash
recovery and a relocated installed-package consumer with two runtimes.
`test_node_discovery` drives the real host advertisement composition through
deferred removal and rapid window reopening with a deterministic backend.

External CHIP/TH, Matter.js network scenarios, fuzz campaigns and privileged
IPv6 injection are optional, not implied by default CTest results. Their scripts
and prerequisites are retained in tools/matter/tests and fixtures. See each
entrypoint and the map for exact routes; generators are not build prerequisites.
No CSA test distribution is bundled, and no local result waives open CSA failures.
