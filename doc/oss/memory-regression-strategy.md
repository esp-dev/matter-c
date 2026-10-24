# Regression after memory optimization

The Memory01..20 branch changes allocation/lifetime in Fabric publication,
storage, commissioning/fail-safe, PASE/CASE/resumption, events, Read/Subscribe,
Invoke/Write, RX/TX and MRP retirement. Unchanged public APIs and limits do not
prove unchanged protocol behavior. Before integrating that whole branch, run
the full applicable automated campaign for the chosen device profile/PICS and
pinned Test Harness revision. Repeat manual/long cases where those subsystems
are involved. Preserve original official outcomes, including known failures;
independent acceptance does not convert them to official PASS.

For daily work use three complementary lanes:

| Lane | Scope | Evidence / practical limit |
| --- | --- | --- |
| Fast host | Focused CTests, OOM/lifecycle invariants, two-instance chip-tool | Current existing native two-instance scenario took17.50s for six assertion groups; no protocol timer changes |
| Short physical | Common C6 CASE/Read/Write/RGB/Subscribe workload, free heap and stack checks | Real radio/SDK/NVS and independent Matter.js; smaller coverage than a CSA campaign |
| Full / scheduled manually | Applicable CSA automation plus timeout, recovery, reboot, endurance and prolonged concurrency cases | Keep required waits; selecting fewer cases is legitimate, shortening their normative timers is not equivalent coverage |

The measured fast scenario covers two complete three-phase host instances,
attestation/CASE/subscriptions, independent application state, Identify/UTC,
survival of the second instance when the first is active/deleted, and both
last-fabric responses. These are **six groups**, not six official CSA cases.
It uses the existing `chip_tool_three_phase.py` with `--source-registers` and
`--meter-services`, plus the runtime-pair host. Its17.50s result is native VM
coverage; the VM's NAT interface did not reach the C6 link-local addresses.
Physical C6 coverage in Memory21 uses Windows/Matter.js, not chip-tool.

Yes, the same controller-side integration frameworks used with ESP-Matter can
test an independently implemented DUT: ConnectedHomeIP documents YAML tests
backed by chip-tool and Python/Mobly tests, with local, CI and Test Harness
execution. C++ unit tests linked to CHIP internals cannot simply be reused as
unit tests of this C implementation. Select tests according to supported PICS,
and retain packet-level diagnostics for disagreements with normative clauses.
See [ConnectedHomeIP integration testing](https://github.com/project-chip/connectedhomeip/blob/master/docs/testing/integration_tests.md).

Formal product certification requires the applicable approved process and an
authorized test provider; it does not follow from using an ESP32 or ESP-IDF.
The current library and RGB fixture are experimental and not certified.
For an already certified product, FastTrack has qualification and change-scope
requirements; this allocation/lifecycle branch must not be assumed eligible
without review. See [Espressif certification](https://docs.espressif.com/projects/esp-matter/en/latest/esp32c6/certification.html)
and [Matter FastTrack requirements](https://handbook.buildwithmatter.com/certification/fast-track-recertification-faq/).

Espressif's optimization table is useful as a measurement template: static
D/IRAM/Flash, free heap before/after commissioning, and BLE release. Its actual
reference environment is C3 with IDF5.4.1, despite the C6 documentation URL;
its byte counts are not directly comparable with our C6/IDF6.1 measurements.
Reducing pools, event retention or feature capacity would be a separate product
configuration choice, not a measured saving with the current limits preserved.
See [Espressif optimization methodology](https://docs.espressif.com/projects/esp-matter/en/latest/esp32c6/optimizations.html).
