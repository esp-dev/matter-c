# CSA21: OTA transfer interruption and peer-session recovery

2026-10-15. CSA20 was committed first as **`14efb54`**. Scope: the existing
BDX-only x86 OTA Requestor and the unchanged TC-SU-2.3 manual procedure.
Public C APIs, persistent formats, device types, PICS and external CHIP sources
are unchanged. The user-paired Windows node and its fabrics were not used.

## Requirements and scope

Matter Core 1.6.1 **11.20.3.5** requires a BDX idle timeout of at least five
minutes. UDP OTA transfers use Receiver-Drive mode, with a proposed block size
at most 1024 bytes. ReceiveInit's optional STARTOFS field is described in
**11.22.5.1**. The current profile does not implement transfer resumption;
a new transfer must start at the beginning instead of treating a partial file
as authenticated or installed.

The installed **TC-SU-2.3**, SDK YAML Tests / FirstManualSuite, is a manual YAML
procedure, not an automatic Python test. Its source SHA-256 is
`3c8229d8371ab8f5856b5955bc7d7de41f42bc83f5a15a4e39f984dce7cc80fc`.
The local frozen catalog and actual TH source match. The applicable steps are
complete transfer (2) and interrupted transfer / retry from zero (4). Consent,
HTTPS and offset resumption (1/3/5) are outside the existing declared profile.
The QueryImage trace also reports RequestorCanConsent=false and synchronous BDX.

The five-minute idle limit is different from an MRP delivery error. If delivery
of an outstanding reliable message fails, the transfer can fail before its idle
timer. Both interruption runs retain the actual observed failure time and still
wait at least five real minutes before the required independent Idle readback.
This campaign does not infer early idle expiry from a failed MRP transaction.
Existing `test_bdx` independently checks the 299999/300000 ms idle boundary.

## Reproduced defect and correction

The preceding C binary fails the new full scenario. It receives a partial image,
discards it after MRP failure, remains at version 1 and returns Idle after the
301-second observation. However, after the same provider restarts, QueryImage
reuses the old secure session. The provider logs repeated **unknown session**
packet drops and no second QueryImage. The scenario times out. Its logs and
failed result remain separate from final acceptance; Memcheck finds no leaks
in that failed protocol run.

`matter_dispatch.c::finished` now marks only that peer's operational connection
for the existing retirement/drain lifecycle when an **outbound MRP sequence
times out**. The failed operation stays failed; no command is automatically
replayed. The next operation establishes CASE. ACK, explicit cancellation,
local transmission failure, inbound traffic and PASE do not trigger this policy.
No extra timer, thread, buffer, allocation, retry layer or public API was added.

The `test_dispatch` regression checks that policy and preservation of another
connection, including all five negative controls. With the preceding production
source it fails with exit 1 at
`dispatch:263: c->retiring==(mode==0) && !other->retiring`; with the fix it passes. Full normal
and separate sanitizer builds each pass **13/13** focused CTests (dispatch,
BDX, OTA query/apply/requestor/update, runtime and existing allocation variants).
Both compiler logs contain no warnings.

## Independent transfer evidence and manual TH result

An uninterrupted `update --require-trace --valgrind` control completes the full
BDX transfer. The provider receives AckEOF, the requestor authenticates the exact
signed test image and simulates install/restart, and a fresh CASE reads version
2 / SoftwareUpdateCompleted boot reason. NotifyUpdateApplied reaches the provider.

The new `interrupt-retry --valgrind` scenario verifies a **4096-byte visible
prefix** matching the offered image before killing the official provider process.
The image contains 16,585 bytes; EOF, authentication, publication and simulated
installation must still be absent. The visible prefix is a lower bound because
the file stream buffers writes. It waits **301.021 seconds** of real
monotonic time with the requestor alive. Transfer failure is first observed at
approximately **10.213 seconds** after the kill, separately from the
BDX idle timer. Independent chip-tool reads UpdateState=1 and SoftwareVersion=1;
neither a final image nor its partial file remains.

The same provider executable restarts with retained KVS, fabric and image. The
requestor process is not restarted or recommissioned for this recovery. A new
announcement leads to QueryImage / UpdateAvailable and ReceiveInit with
**Range Control=0 and Start Offset=0** in the second provider log. The subsequent
whole-image hash, final AckEOF, signature/authentication, simulated installation,
restart, NotifyUpdateApplied and fresh CASE version/boot readback all pass.

A separate **ASan/UBSan/LSan** `interrupt-retry` run repeats the actual failure,
**301.053-second** observation and complete retry/restart path; both
requestor boots exit cleanly with empty stderr. Memcheck covers the uninterrupted
control and the fixed interruption scenario: **four requestor boots,
111,042 allocations/frees, zero errors/leaks, no suppressions**. Independent
CHIP peers are not instrumented by those requestor memory tools; the provider's
first process is intentionally killed.

**TH run 444 PASSED** with three passed steps (two verification steps and
evidence upload) and three N/A steps. The coding agent reviewed the captured
provider traces, assertions and chip-tool readbacks, entered those manual
assessments and uploaded a compact evidence log with raw-artifact hashes.
Neither official YAML nor PICS nor TH result records were patched. This remains
**agent-operated manual acceptance**, not automatic CSA assertions, accredited
laboratory acceptance or certification.

Only TC-SU-2.3 changes from BLOCKED to MANUAL with manual result PASS. Latest
matrix: **97 PASS / 14 FAIL / 12 BLOCKED / 35 MANUAL / 704 NA**. The automatic
PASS count does not increase. All other official rows are inherited, not rerun.
The [JSON delta](csa21-results.json) records the source manifest, exact binary,
provider, controller, test, PICS and artifact hashes. Raw protocol logs, test
credentials, KVS, images and state stay in ignored laboratory directories.

## Changed files, commands and remaining limits

- `main/apps/matter/runtime/matter_dispatch.c`: retire a timed-out outbound peer session.
- `tools/matter/tests/test_dispatch.c`: failing-old-code regression and negative controls.
- `tools/matter/tests/test_ota_chip_provider.py`: interruption, actual wait/readback and retry oracle.
- `doc/runtime.md` and `doc/ota-host.md`: session recovery policy and fixture usage.
- `doc/oss/test-map.md`: register the additional coverage without new native test definitions.
- `doc/oss/csa21-validation.md` and `doc/oss/csa21-results.json`: evidence and classification delta.
- `README.md`, `doc/oss/status.md` and `doc/roadmap.md`: discoverability, status and next task.

Commands executed: normal and sanitized CMake builds; 13 focused CTests in each;
the expected failing old-code dispatcher control; `update --require-trace
--valgrind`; failed baseline and fixed `interrupt-retry --valgrind`; separate
sanitized `interrupt-retry`; unchanged manual TH TC-SU-2.3; Python syntax/CLI,
test-map inventory, source/hash checks and `git diff --check`. Generic laboratory
commands and prerequisites are in the [OTA host contract](../ota-host.md).

This host installs an application-specific signed **WWOTA001 test payload** and
restarts the same executable; it does not install executable firmware or test a
physical bootloader. Windows, hardware, radio, production credentials and Home UI
acceptance were not tested. The full unrelated native and CSA campaigns were
not repeated. Existing failures and other blocked/manual cases remain open.
Owned processes are stopped, laboratory ports are free and TH is idle after
acceptance; existing user fabrics remain unused.

**Next: CSA22 — TC-SU-2.4, ApplyUpdateRequest fields and token/version binding.**
