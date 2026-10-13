# Development status

CSA02 fixes host clock scanning after removal from a sparse fabric table and
fail-safe cleanup waiting for a peer ACK after the commissioner has evicted PASE.
The expiry response now drains its local UDP operation before session-context
retirement and rollback. See [lifecycle acceptance](csa02-validation.md) and
[recheck evidence](csa02-results.json). The original CSA01 matrix below remains
the historical baseline; unselected tests have not been rerun.
The seven final rechecks yield **4 PASS and 3 FAIL**, moving the combined matrix
to **77 PASS, 28 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**. The three remaining
selected failures are documented test/specification discrepancies, not waived
results. Full two-instance Linux scenarios pass under Memcheck (zero errors and
zero live allocations at exit) and separately ASan/UBSan/LSan. Next: CSA03,
Descriptor and endpoint composition.

CSA01 establishes the complete installed-catalog matrix for the current x86
profile: `--three-phase --source-registers --meter-services`, endpoints 0/1/3/4/5.
Final matrix: **73 PASS, 32 FAIL, 21 BLOCKED, 32 MANUAL and 704 NA**; no PLANNED
entries. There were 112 official runs for 109 entries, including retained attempts.
The [acceptance report](csa01-validation.md) and [matrix](csa01-matrix.json) retain
official results, endpoint-local PICS, versions, evidence hashes, manual procedures
and missing fixtures. This is a first broad acceptance pass, not certification.
All four historical failures reproduced; additional failures affect composition,
fabric/session lifecycle, reporting, discovery, diagnostics and resource pressure.
Some failures instead concern lab prerequisites, development identity or possible
test/specification discrepancies; none is silently waived.

MP04a: startup discovery failure traced to the pinned chip-tool `onnetwork-long`
selection path, which accepts an unrelated unsolicited announcement. Captured
PTR/SRV/TXT records have the correct discriminator/instance/port relationships.
The pair oracle uses unmodified chip-tool's `pairing code` path, which checks the
returned discriminator. The startup regression begins browsing before both full
runtimes start, without an announcement-settling sleep. The legacy tool path
remains unreliable in this situation; the C responder/API is unchanged.
See [MP04a evidence](mp04a-validation.md).
Discovery/commissioning selected the correct ports in all four final QR-path
runs. Three complete pair scenarios passed; the Memcheck A-then-B run failed
later at RemoveFabric (request ACK received, Invoke response timed out). That
independent acceptance failure remains open alongside the CSA01 failures;
it is not relabelled as a full-pair PASS.
CSA02's two final full-pair rechecks did not reproduce that timeout. Its cause
remains unestablished, so the historical issue is not considered fixed.

MP04 implemented: opt-in `--three-phase --meter-services` adds Identify and
Meter Identification on EP1 and Time Synchronization on EP0. Each instance owns
its callbacks/clock; the host persists Last Known Good time in an atomic sidecar.
Focused official CSA tests passed; this is not complete utility-meter support.
See [MP04 report](mp04-validation.md), [contracts](../meter-services.md) and the
[ordered acceptance roadmap](../roadmap.md).

MP03 implemented: opt-in `--three-phase --source-registers` adds a configurable
manufacturer-specific source cluster. It preserves tariff/quadrant/demand
registers, directional values, metadata and volume channels with explicit
units/provenance/nullability. Complete host and two-instance controller runs
passed under Memcheck and separate ASan/UBSan/LSan. Official TC_DESC_2_1 passed
with the new cluster attached; private schema checks remain separate.
See [MP03 report](mp03-validation.md)
for actual coverage, RAM cost and limitations. No firmware integration.

MP02 implemented and accepted for the x86 complete-pair simulator: opt-in
three-phase profile, Descriptor/TagList, multi-measurement EPM and explicit
EEM register mode. The default profile and constructors remain available.
Focused official CSA acceptance: 10/10 PASS. Independent chip-tool Read/Subscribe,
restart and two complete instances passed, including separate full Linux
Memcheck and ASan/UBSan/LSan runs. See [MP02 report](mp02-validation.md) for
commands, native tests, source-availability limitations and storage migration.

Protocol work targets Matter 1.6.1; this is an experimental partial implementation.
Complete callback-driven runtime, PASE/CASE/IM, commissioning, ACL, diagnostics,
power/energy measurement and simulated OTA are present. Linux/Windows host
adapters and an installable CMake package are included. Hardware integration and
a production OTA bootloader are outside the current validated scope.

The four historical official CSA failures remain unresolved and are reproduced
in CSA01. They are no longer the complete failure list:

- TC_CGEN_2_2: trusted-root count during the fail-safe scenario.
- TC_OPCREDS_3_4: RevokeCommissioning response timeout over PASE.
- TC_ACL_2_4: deprecated ProxyView behavior/profile expectations.
- TC_ACL_2_6: legacy ConstraintError expectation.

Later focused OPCREDS3.8/ACL2.8 runs passed, including separate Memcheck and
ASan/UBSan/LSan scenarios. These historical results do not constitute a complete
CSA matrix, certification or a fresh acceptance run of this public snapshot.
See validation.md for the publication snapshot and mp02-validation.md for the
subsequent three-phase acceptance; neither is a full-stack certification.

**Next task: CSA02 - commissioning, fail-safe and selective fabric/session teardown.**
Full applicable CSA acceptance takes priority over new tariffs. Work proceeds in
successive passes over the [roadmap](../roadmap.md), with explicit coverage gaps,
evidence and follow-up actions. Address the connected CGEN/OPCREDS/CADMIN lifecycle
failures as one coherent implementation pass, including the independent
concurrent-subscription RemoveFabric regression from MP04a. Retain the remaining
CSA01 failures and blocked/manual coverage for subsequent passes.
