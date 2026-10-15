# CSA16: PASE RevokeCommissioning response discrepancy

## Reproduction and normative decision

The unchanged **TC_CADMIN_1_10 fails in baseline run 333**, endpoint 0, on
the CSA14 binary. It records 12 passed, one failed and one pending TH records.
The failure is test step 9: TH2 awaits `SendCommand(RevokeCommissioning)` over
PASE and receives `CHIP Error 0x00000032: Timeout`. The exception occurs before
the step 10 assertion that a subsequent PASE read must fail. It reproduces
historical run 157 and the already documented CSA02 run 257 discrepancy.

Core 1.6.1 section **11.19.8.3** requires terminating open and in-progress
PASE sessions on RevokeCommissioning, deleting temporary ECM credentials and
expiring the relevant fail-safe. Its note explicitly says a PASE caller SHALL
NOT expect a response because the session is terminated during execution.
The official script instead awaits that response without accepting timeout
at step 9. This is a standard/test discrepancy, not evidence that successful
PASE alone should close a commissioning window. Section 5.5.1's twenty failed
attempts and its post-successful-commissioning admission rule do not require
a RevokeCommissioning response over a terminated PASE session.

Per the CSA16 stopping rule, **no implementation or test workaround is made**.
The official FAIL remains. Obtain CSA/test resolution before changing this
response behavior. This confirms, rather than supersedes, the normative
decision in [CSA02](csa02-validation.md). No waiver or certification is claimed.

## Verified implementation path

`matter_admin_commissioning.c:start` accepts command 2 through its asynchronous
path, clears the window and marks revocation pending. Its owner `process`
withdraws advertising and calls the runtime's `admin_revoke`. That callback
stops enhanced admission, calls `matter_dispatch_retire(..., false)` and
expires an active fail-safe. The commissioning-host cleanup also retires
sessions before credential/network rollback.

The dispatcher marks PASE transactions closing and retires their secure
channels; ordinary CASE sessions are retained by this selective operation.
An Invoke containing the PASE revocation is itself among the retired
transactions, so it cannot deliver an InvokeResponse on the terminated
session. The existing bounded ArmFailSafe-expiry response exemption is tied
to `expiry_reply`, not to every pending Invoke, and must not be expanded to
manufacture a response for this test. CSA12's one-shot `pase_failed` callback
and runtime epoch counter cover handshake failures; neither accounts for
successful-PASE RevokeCommissioning as a failed handshake.

This is source tracing plus official baseline evidence, not new acceptance
of every retirement/error/race path. No API, allocation, scheduler, fail-safe,
CASE or window policy changes were made.

## Evidence and checks

- TH reports v2.15.1+summer2026 with SDK image
  `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf-ipv6`. The fetched test hash is
  `a983dbfc42a8555f7923cec3adb9d99436c13717995fbf463329de433c8782cd`,
  matching CSA01. The execution PICS hash matches CSA15.
- Baseline `matter-node` SHA-256 is
  `e2eb58b373dca220bb98ee2033c3db7ec0ec97d71dc442c9b12e589afd71b371`,
  matching CSA14/CSA15. The six relevant C/header files match the VM baseline
  source byte-for-byte. No new binary was built or labeled final.
- The runner uses a new campaign directory and fresh DUT store. It uses
  project 10 without modifying its configuration, script, PICS or assertions.
  CSA15's connected-Wi-Fi startup override is absent. TH was idle before and
  after the run. Only campaign-owned DUT/capture processes were stopped;
  the DUT log ends with `STOPPED rx_packets=79 result=0`.
- Private evidence retains the historical log, current official JSON/log,
  DUT log, mDNS capture, source identities and cleanup checks. Hashes are in
  [the CSA16 delta](csa16-results.json); lab paths/state stay ignored.

Executed campaign commands: `python build/csa16/preflight.py`,
`python build/csa16/setup.py`, `python build/csa16/batch.py baseline.json`,
`python build/csa16/fetch_evidence.py`, `python build/csa16/make_results.py`,
`python tools/matter/check_test_map.py` and `git diff --check`.
Git HEAD remains `9d88156`; inherited uncommitted CSA15 work is retained.

No C changes means no new native regression, failing old-code control,
Linux build, compiler-warning assessment, Memcheck or ASan/UBSan/LSan run.
TC_CADMIN_1_9 was not rerun because shared window policy was unchanged.
Step 10 was not executed after the official failure. Later-stage failed
commissioning counts, duplicate/old-epoch races, physical hardware and
full-catalog acceptance were not assessed. The capture covers mDNS, not
decrypted IM traffic. No green tests were repeated.

Latest matrix stays **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**;
all other rows are inherited. **Next: review the Core 11.19.8.3/test step 9
discrepancy with CSA/test maintainers.** Do not extend PASE authority to obtain
a local PASS, and keep later-stage failure-budget assessment a separate task.
