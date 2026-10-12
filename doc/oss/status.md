# Development status

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
See validation.md for checks actually executed on this export.

**Next task: resolve TC_CGEN_2_2 and TC_OPCREDS_3_4 against the specification
and unmodified CSA tests.**
