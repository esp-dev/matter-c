# CSA64: OTA recovery through a new CASE session after backoff

CSA63 was committed as `8d251d2`; the starting tree was clean. This independent
fault/recovery scenario extends the existing OTA acceptance driver. No native
implementation, policy, public API, PICS or original CSA test changes were made.
Acceptance is incomplete: the normal run passes; the sanitizer run fails before
a new CASE reaches the provider and its cause remains open.
The original TC_SU_2_2 remains FAIL607; the prior deliberate-loss608 diagnostic
is separate. Full fingerprints and raw-result hashes are in [the receipt](csa64-results.json).

## Recovery path

The unmodified CHIP provider actually sends Busy with 60s delay. After the native
requestor enters DelayedOnQuery, the driver kills only its own provider child
and starts a new process with the same image and persistent KVS. The requestor
is neither restarted nor recommissioned to recover. The first retry uses the
old active session, which the replacement provider no longer knows. Actual peer
unknown-session drops, no decoded QueryImage response and native Idle/Failure
establish the failed operation. No BDX or install has started.

An explicit application query after another announcement preserves the existing
second-failure backoff. The driver waits the real 240s policy interval without
accelerating the native clock. It then requires a new CASE handshake on the
replacement provider boot and binds its responder SessionID to the encrypted
QueryImage. The actual response must offer version 2. The driver checks the
complete image transfer, authentication and update lifecycle after recovery.

### Full CASE versus resumption

The first Memcheck attempt retained raw FAIL: its oracle incorrectly required
only Sigma1/Sigma2/Sigma3. Actual traces show Sigma1/Sigma2Resume/Success, followed
by an authenticated QueryImage and UpdateAvailable. The test then stopped the
node before completing the update. This is a verifier-precondition failure,
not complete OTA acceptance or evidence that the requestor failed recovery.
The receipt records its 32110 allocations/frees, zero errors/live blocks and the
exact driver/log hashes, without claiming complete-update acceptance.

Core 1.6.1 section 4.14.2.6 permits resumption to establish a new secure session.
Restarting the provider loses active sessions but need not erase persistent
resumption records. The corrected oracle accepts either a complete full handshake
or Sigma1/Sigma2Resume/Success. In the latter case it checks the resume fields'
lengths, initiator Success and responderSessionID tag3; full Sigma2 uses tag2.
It retains the required secure QueryImage/session binding. A different numeric
SessionID alone is neither necessary nor sufficient proof of fresh CASE.

Actual native/CHIP peers authenticate the MIC and secure messages. The trace
oracle checks their observable handshake/session/query linkage; it does not
independently recompute the MIC or publish resumption material. The existing
explicitly selected CHIP-compatible key-derivation profile remains unchanged.
The earlier documented Core/CHIP derivation difference is not resolved here.

The corrected oracle is checked against actual full/resumed peer traces and
copies with a missing handshake message, mismatched SessionID, an unsecured
query or failed resumed StatusReport. All 13 controls must pass. No assertion
about backoff, image bytes, signature, version/token or restart was removed.

## Acceptance

| Scenario | Outcome | Actual coverage |
| --- | --- | --- |
| First Memcheck attempt, full-only oracle | Raw FAIL after 9 checks | Legal resumed CASE and positive response; stopped before complete OTA |
| Corrected oracle, normal host under Memcheck | PASS27/27 | Full recovery, signed update and two native boots |
| Corrected oracle, separate ASan/UBSan/LSan host | FAIL after 9 passing checks | Backoff retained, then 32ms failed attempt; no new CASE/QueryImage at peer |
| Offline oracle controls | PASS13/13 | Actual full/resumed traces and missing/mismatched/failed-status controls |

Both final variants use fresh disposable state and the same corrected driver.
Only the normal variant completes recovery. Its requestor stays alive through
provider restart; its sole restart is the later accepted simulated installation.
The sanitizer requestor remains alive through the failed attempt and is stopped
by test cleanup. The completed normal scenario verifies:

- Same persistent provider identity, no successful stale-session query and no
  premature download; explicit owner request cannot bypass backoff.
- New authenticated CASE and actual UpdateAvailable/version 2 after the wait.
- All16585 image bytes, seventeen ordered BDX blocks, EOF/AckEOF counter 16 and
  matching SHA-256; no offset resume is claimed.
- Latest offered token/version in ApplyUpdateRequest and NotifyUpdateApplied,
  signed simulated installation and live Applying before the first boot exits.
- Fresh CASE readback of version 2 and BootReason SoftwareUpdateCompleted, plus
  matching VersionApplied event after the simulated restart.

The normal observer measures 240.436s from the failure-log observation to the
recovery check; peer last-unknown-packet to decoded QueryImage is 242791ms. Both
the initial full CASE and the replacement resumed CASE are linked to their secure
QueryImage by the oracle. Memcheck's two boots report 36967/36967 and 19568/19568
allocations/frees, zero errors and zero live bytes/blocks. Both native stderr
files are empty.

The separate sanitizer run is a functional **FAIL**, despite empty sanitizer
stderr and clean process shutdown. Actual event uptime timestamps are 130548ms
for the first Idle/Failure, 370572ms for the next Querying and 370604ms for its
Idle/Failure: the retry waited 240024ms, then failed after 32ms. No new handshake
or decoded QueryImage reached the replacement peer. The driver's 315s recovery
observation expires without download/apply/reboot/Notify; those sanitizer checks
were not executed. Do not claim full sanitizer OTA acceptance or infer the cause
from a clean memory log.

This narrows the next investigation to preparation before a new CASE reaches the
peer. No internal return code or packet capture identifies whether resolver
admission, local preparation, session creation or another early failure caused it.
Do not change timeouts, policy or production code on that inference alone.

The backoff oracle uses both local failure-log observation with a 0.5s measurement
tolerance and a conservative peer last-unknown-packet-to-new-query bound of at
least 240s. This tolerance changes no native deadline. The 240s value is existing
policy, not a Matter-required delay; Core 11.20.3.2's 120s minimum/provider-delay
guards remain unchanged. Apply/Notify and StateTransition expectations follow
Core 11.20.3.6/11.20.7.7. There is no new production memory or scheduling mechanism.

## Reproduction and boundaries

```text
python tools/matter/tests/test_ota_chip_provider.py ... --mode query-restart --events --event-min-interval 5 --local-query --require-trace --apply-binding --bdx-profile --valgrind
# Supply private executable/provider/chip-tool/PAA/credentials/interface/output.
# Repeat with a separate ASan/UBSan/LSan node, without Valgrind, in fresh state.
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

The runner, test map and host acceptance guide document this path. All 362 tracked
C/H inputs retain their CSA63 byte identity; the normal/sanitizer native binaries
retain the CSA62 hashes. No new native compilation or CTest run is claimed.
Remote Python compilation and the offline verifier controls ran successfully;
CSA63's focused CTests are prior evidence only. Raw logs, state, image trust keys
and controller credentials remain private. Final cleanup verifies no stage
processes remain; TH is idle and no paired Windows node was changed.

No new original CSA execution, assertion/PICS workaround, Windows build,
physical-device/bootloader test, full applicable-suite rerun or certification is
claimed. This is signed host-simulation OTA, not production firmware installation.
Counts remain 122 PASS/28 FAIL/5 prerequisites, including manual outcomes.

Next: **CSA65**, attribute the 32ms pre-handshake sanitizer failure with scoped
resolver/outgoing preparation/CASE-creation result diagnostics and a bounded repro.
Reuse this actual FAIL; avoid blind multi-minute reruns or retry-policy changes.
Fix only an attributed native defect, then require complete memory acceptance.
