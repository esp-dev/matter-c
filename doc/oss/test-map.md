# Test inventory

test-map.json enumerates 226 test, fixture, fuzz and controller files. Run
`python tools/matter/check_test_map.py` to verify coverage, current dependency
source membership and the closed public-header set.

CMake defines 84 native test variants, with explicit platform/privilege filters.
Default CTest totals: 85 on Windows, 82 on Linux, including inventory, crash
recovery and a relocated installed-package consumer with two runtimes.

External CHIP/TH, Matter.js network scenarios, fuzz campaigns and privileged
IPv6 injection are optional, not implied by default CTest results. Their scripts
and prerequisites are retained in tools/matter/tests and fixtures. See each
entrypoint and the map for exact routes; generators are not build prerequisites.
No CSA test distribution is bundled, and no local result waives open CSA failures.
