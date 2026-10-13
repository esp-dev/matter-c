# Development status

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
independent acceptance failure remains open alongside the four historical CSA
failures below; it is not relabelled as a full-pair PASS.

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

Prior official CSA Test Harness acceptance remains partial. Four known failures
are unresolved; they are not waived by local tests or this source export:

- TC_CGEN_2_2: trusted-root count during the fail-safe scenario.
- TC_OPCREDS_3_4: RevokeCommissioning response timeout over PASE.
- TC_ACL_2_4: deprecated ProxyView behavior/profile expectations.
- TC_ACL_2_6: legacy ConstraintError expectation.

Later focused OPCREDS3.8/ACL2.8 runs passed, including separate Memcheck and
ASan/UBSan/LSan scenarios. These historical results do not constitute a complete
CSA matrix, certification or a fresh acceptance run of this public snapshot.
See validation.md for the publication snapshot and mp02-validation.md for the
subsequent three-phase acceptance; neither is a full-stack certification.

**Next task: CSA01 - first full CSA matrix pass for the current x86 profile.**
Full applicable CSA acceptance takes priority over new tariffs. Work proceeds in
successive passes over the [roadmap](../roadmap.md), with explicit coverage gaps,
evidence and follow-up actions. The four historical failures remain open; MP04a
does not rerun or waive them.
Include the newly observed concurrent-subscription RemoveFabric timeout in the
first pass's regression work and compare it with the official applicable cases.
