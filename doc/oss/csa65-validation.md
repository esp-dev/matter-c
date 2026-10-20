# CSA65: VM network outage during the early OTA failure

The starting commit is `c7454cf`; the tracked tree was clean. This investigation
retains the CSA64 sanitizer functional FAIL. The historical system journal now
confirms a VM link/address outage overlapping the estimated failed attempt.
There is no established native implementation defect and no production change.
Fingerprints and separate diagnostic outcomes are in [the receipt](csa65-results.json).
The original TC_SU_2_2 FAIL607 and separate injected-loss608 remain unchanged.

## Historical timing

All times below are UTC on 2026-10-20. The journal's original local timestamps
include `+02:00`; they have been converted explicitly.

| Observation | UTC |
| --- | --- |
| Kernel reports selected VM interface link down | 10:01:39 |
| Network manager removes addresses/multicast registration | 10:01:45--46 |
| Estimated OTA Querying / Idle-Failure generation | About 10:01:46 |
| Kernel reports link up | 10:01:49 |
| Address configuration and activation complete | About 10:01:51 |
| Controller receives Querying / Idle-Failure reports | 10:01:53.461 / 10:01:53.495 |

Receipt time is not event-generation time. OTA StateTransition stores the owner
loop's node-relative monotonic timestamp. The failed pair has uptime370572 and
370604ms. Anchoring to the first Busy send at09:55:39.369 and its later state
event at uptime3981ms estimates generation at10:01:45.960 /45.992. Those are
approximate anchors: packet handling and owner-loop sampling prevent an exact
millisecond wall-clock claim. A separate causal comparison uses the first
Querying event at uptime3701ms preceding its peer Sigma1 at09:55:39.248; it
places the later failure no later than about10:01:46.151, assuming no intervening
wall-clock step relative to monotonic time and allowing local sampling latency.
Both comparisons place the attempt within the observed outage, well before the
controller receives the retained events after connectivity returns.

The user reports switching the host computer's Wi-Fi connections around this
work. That is consistent with the VM link change; neither the journal nor the
protocol trace independently proves which host action caused it. The confirmed
fact is the guest's loss of carrier and addresses. The original run did not
capture a native failing branch or system-call errno. Do not relabel that missing
detail as a proven resolver, CASE, allocator or sanitizer defect. Equally, do not
claim every native network-recovery path is correct from this correlation alone.

## Four diagnostic executions

Each run uses fresh disposable state and the same unchanged public recovery
driver. Each observes the real Busy60, stale-session timeout, existing240s
second-failure backoff, then a new resumed CASE and full signed simulated OTA.
The requestor stays alive during provider replacement; its later restart is the
simulated accepted installation. These are independent laboratory outcomes,
not new original CSA executions.

| Variant | Result | Interpretation |
| --- | --- | --- |
| Private scalar result diagnostics | PASS27/27 | Resolver, outgoing preparation, CASE and query boundaries; ASan/UBSan/LSan |
| Original frozen sanitizer under GDB watch | PASS27/27 | No outgoing failure flag in third operation; LSan explicitly OFF under ptrace |
| Private first-failure diagnostics, silent on success | PASS27/27 | Only expected old-session timeout observed; ASan/UBSan/LSan |
| Original frozen sanitizer with error-only I/O hook | PASS27/27 | No recorded sendmsg/sendto/nonblocking-excluded recvmsg errors; ASan/UBSan/LSan |

All four complete16585 image bytes in17 blocks, EOF/AckEOF16, exact image hash,
signature validation, bound Apply/Notify token/version, live Applying, simulated
reboot and fresh CASE version2/SoftwareUpdateCompleted readback. All collected
driver stderr files are empty and no sanitizer diagnostics were found. GDB's
native stdout/stderr share a PTY; that combined log was scanned, so its empty
driver stderr is not independent native-stderr evidence. **GDB's raw
memory-clean check is not leak acceptance:** LSan cannot operate under ptrace
and was disabled for that execution. Its result is diagnostic only. The other
three executions retain leak detection. No new normal Memcheck run is claimed;
CSA64's clean two-boot normal result remains prior evidence.

Two private diagnostic builds and the I/O hook compile without warning/error
lines. Instrumentation changes execution timing/environment even when quiet;
none of these passes supersedes the earlier functional failure. In particular,
fresh-state runs do not prove that the same running instance recovers after a
physical VM interface outage and the subsequent480s third-failure backoff.

## Source and acceptance boundaries

All362 tracked C/H inputs remain byte-identical to the starting commit. Frozen
normal/sanitizer files also match their original build outputs. This does not
support a stale-binary explanation. No production C, public API, clock, retry
policy, test assertion or PICS change was made. Existing source distinguishes
a failed asynchronous operation from successful CASE establishment; the third
original OTA_QUERY means the invocation was accepted, not that resolution or
transmission succeeded.

The historical failure therefore has a demonstrated environmental disturbance,
and four instrumented full updates pass under later conditions. Exact internal
failure attribution and same-instance recovery across the actual outage were
not captured. Preserve that limitation rather than introduce speculative socket,
timeout or security workarounds. There is no certification or matrix reclassification:
counts remain122 combined PASS/28 FAIL/5 prerequisites.

The privileged journal was supplied by the user; raw machine/account/address
details stay in ignored local evidence. Only its hash and sanitized chronology
are public. No stage processes remain. Paired Windows nodes, their fabrics and
TH services were not modified.

Validation includes source/artifact hash checks, final raw-result and sanitizer
log inspection, journal/event correlation, campaign and test-map consistency,
public privacy checks and `git diff --check`. No new CTest, Windows build,
full applicable-suite rerun, physical firmware/bootloader test or original CSA
test result is claimed.

Next: **CSA66**, a controlled same-instance transient-network failure/recovery
check with first-error result capture. Isolate fault injection to the test
process instead of disconnecting the shared VM/SSH interface. Preserve real
retry/rate limits; fix only a reproduced native defect, if one is found.
