# CSA73: frozen memory-branch integration and regression gates

Integration begins on 2026-10-24. Baseline: `e75885b`; common ancestor:
`6977da4f97fbd3b17dcfa173bda912d31d6d6808`. Import only the 40 committed changes
through Memory39, `6c9835a986ec869c5d49f2d380f0818e307bf78d`. Memory40 was dirty at
capture and is excluded, as are any later commits. The separate memory checkout
continues independently; do not reset, clean, commit or switch its worktree.

The merge candidate is `ff3a732` on a separate integration branch. Main remains
at its baseline until acceptance. It merged without conflicts, retains CSA70..72
evidence, and its core C/header inputs match the selected Memory39 commit.
No GitHub publication, paired-node replacement, physical-device flashing or
shared network/service changes are part of this integration.

## Gates before advancing main

1. Check the campaign, test inventory, unsent CSA72 packet, diff, private-data
   exclusions and clean baseline. Export only the candidate's tracked Git tree
   into a new isolated Linux directory; retain source hashes and binary identity.
2. Compile the Windows host/desktop and run its complete default CTest suite in
   a separate build directory. Preserve the installed/paired desktop application.
   Run the imported heap-map and report-block offline decoder corruption tests.
3. Build normal Linux and run complete default native CTest, including OOM and
   lifecycle regressions and relocated consumer packaging. Run the full two-node
   three-phase scenario and all six native wire cases under Memcheck. Then build
   separately with ASan/UBSan/LSan and repeat those scenarios. Retain ordinary
   versus corrected-peer negative controls, real retries, ACK/completion order,
   per-fabric admission and orderly zero-live drain; do not accelerate timers.
4. Use the existing fixed loopback-only injector capability to repeat the 14
   Linux UDP/IPv6 cases under Memcheck and separately sanitizers. Change no
   privileges or VM interface configuration.
5. Run full signed simulated OTA against the existing unmodified CHIP provider
   under Memcheck and separately sanitizers. Check BDX bytes/EOF, token/version
   binding, Apply/Notify, simulated restart and fresh CASE readback. This is
   independent acceptance, not an original automatic CSA verdict.
6. Repeat every exact currently PASS automatic case/endpoint/collection: 98
   positions using the frozen CSA58 fixtures plus the distinct-DAC TC_DA_1_7
   fixture from CSA70. Preserve the approved simulation parameters, actual QR,
   PICS, original test/helper hashes and full resource-test observation periods.
   Use a fresh disposable native process/store per case and real reset actions.
7. Collect original TH verdicts and step states, source/binary/PICS fingerprints,
   zero-exit/empty-stderr cleanup and temporary-PAA removal. Compare all 99 exact
   identities with the baseline. Diagnose any new failure before declaring stable
   acceptance; keep its original attempt even if a corrected-fixture follow-up
   passes. Check helpers and source again after execution.
8. Review reports and commit locally. Advance main only to the accepted integration
   result and only if it still has the expected baseline; never absorb a moving
   memory-branch tip automatically. No push.

## Scope of the conclusion

This is a regression of the previous automatic PASS set and additional memory,
fault/recovery and OTA coverage. The existing 24 manual PASS outcomes are historical.
The 27 FAIL and 5 prerequisites retain their [CSA72 gates](csa72-questions.md);
preparing this merge does not resolve their test, provisioning or physical-lab
requirements. In particular it does not schedule the owner-deferred multi-hour
DGGEN run. Do not claim a fresh 155-position full-matrix PASS, endurance soak,
Apple/Google UI acceptance, 128 KiB RAM fit or product certification.
