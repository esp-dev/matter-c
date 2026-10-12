# Development status

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

**Next task: MP04 — Identify, Meter Identification and Time Synchronization
on x86, preparing Meter Reference Point before tariff support.** The four failures above
remain separate unresolved conformance work, required before certification.
