# Test inventory

test-map.json enumerates 230 test, fixture, fuzz and controller files. Run
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
The optional `--wifi-sim-connected` mode of `test_discovery_startup_linux.py`
passes through to `runtime-pair-host` and its CHIP controller. It checks each
instance's connection, rejects unarmed scans, then exercises armed general and
directed scans, missing SSIDs, Breadcrumb and rollback during the full pair
lifecycle. This supplementary scenario is not TC_CNET_4_4 acceptance.
CSA15 extends the same optional scenario with exact network-list checks,
wrong-password rejection/error clearing, second-AP connection, rollback,
CommissioningComplete retention and isolation of the other runtime. It does
not switch OS interfaces and is not TC_CNET_4_11 acceptance. The unchanged
official TC_CNET_4_9 result and its runner parameter fixture are documented
in [CSA15](csa15-validation.md).

[CSA16](csa16-validation.md) reproduces unchanged TC_CADMIN_1_10 step 9 on
the CSA14 binary. Its PASE RevokeCommissioning response expectation conflicts
with Core 1.6.1 11.19.8.3. The official FAIL is retained pending CSA/test
resolution; no implementation regression or native/memory rerun was added.

[CSA17](csa17-validation.md) adds the opt-in MTRID change/reset test event
triggers to the meter-services host and `runtime-pair-host --test-event-key`.
The pair scenario `--meter-triggers` verifies changed/reported/cleared
identity on one runtime, unchanged identity on the other, and wrong-key or
unknown-event rejection. `chip_tool_meter_triggers.py` covers run/disabled/
restart modes on a disposable node. These are laboratory regressions, not
official TC_MTRID_3_1 acceptance, which is recorded separately.
The [follow-up](csa17-review-validation.md) executes the stricter oracle: four
SET/CLEAR reports, no unchanged identity reports on unrelated samples, instance
isolation, restart and last-fabric reset. Readback uses a separate controller
connection so asynchronous A reports cannot contaminate B's identity check.
Full pair Memcheck and separate ASan/UBSan/LSan pass; official MTRID 3.1/2.1
pass in runs336/337. Historical failures remain in the earlier report.

CSA18 extends `test_energy_sim` with profile-specific normal source rates and
counter continuity across generator/STOP transitions. The existing pair
`--meter-triggers` oracle also exercises load/STOP on all four EPM endpoints of
both nodes, varying phase voltage, invalid targets/codes, peer/phase isolation,
aggregate export growth and no rollback after STOP. Official EPM/EEM results
and skipped optional steps are recorded separately in
[CSA18](csa18-validation.md); these local checks do not replace them.

CSA19 adds `test_ota_chip_provider.py`: an unmodified CHIP OTA provider,
attested commissioning, QueryImage/Busy timing, BDX, signed simulated install,
restart and fresh CASE readback. `--mode update --valgrind` covers both boots;
a separate sanitized executable covers ASan/UBSan/LSan. It is optional and is
not part of native CTest. Official TC-SU-2.1 is a manual TH procedure; its
prompt decisions and attached evidence are recorded separately in
[CSA19](csa19-validation.md) and the [fixture contract](../ota-host.md).

External CHIP/TH, Matter.js network scenarios, fuzz campaigns and privileged
IPv6 injection are optional, not implied by default CTest results. Their scripts
and prerequisites are retained in tools/matter/tests and fixtures. See each
entrypoint and the map for exact routes; generators are not build prerequisites.
No CSA test distribution is bundled, and no local result waives open CSA failures.
