# CSA28: automatic QueryImageResponse scenarios

CSA27 was committed as **`12e484f`**. CSA28 runs the original automatic
**TC_SU_2_2**, checks its initial-query precondition against Core R1.6.1, and
adds an explicit default-provider route to the independent OTA laboratory.
No C/H implementation, public API, production schedule, PICS or official test
source changed. See the [result record](csa28-results.json).

## Official result and precondition

**TC_SU_2_2 FAIL, TH run457, step1.** Commissioning passes. The test announces
a new provider with reason1, UpdateAvailable, then waits 120 seconds for
DelayedOnQuery. The node accepts the announcement but remains Idle, so the
unchanged test times out. The TH records three passed entries including wrappers,
one failed entry and five pending entries. Steps2 through6 did not execute.

The installed helper's `announce_ota_provider()` defaults to UpdateAvailable.
The test does not set DefaultOTAProviders or arrange an application query
opportunity before this wait. For a newly selected provider with reason1, the
current requestor schedules its next normal query in one day. The node log
records `source=announcement reason=1` without starting an OTA query, and
actual subscription reports remain Idle throughout the official wait.
This is not evidence of a malformed Busy response or early retry: the first
QueryImageResponse was never reached.

Core **11.20.7.4**, AnnouncementReasonEnum / UpdateAvailable, recommends querying at the next upcoming
OTA-provider query, rather than mandating an immediate query. Core **11.20.3.2**
recommends a daily query and establishes the 120-second minimum. Core
**11.20.3.1** recommends configuring DefaultOTAProviders when a provider is known
at commissioning, specifically to reduce the delay before the first query.
The automatic fixture does not supply that precondition for this host policy.
The test/host fixture contract needs CSA/test-maintainer review; no correction
has been approved. The full one-day wall-clock interval was not tested here.

The original case SHA-256 remains
`d5e9fbf867982ba7b1c8c8305c70a6fc6b04f018b521562d2e7028b6e672b8e4`,
and its shared helper remains
`9e9b2af9fcca6b039da12273b89560bd55121ec11fdb72de0f4973499318615b`.
No official assertions, selection rules, PICS or sources were patched. A
temporary TH status-API timeout during execution was not used as the verdict;
the completed run and its official log establish the actual step1 failure.

Only the automatic TC_SU_2_2 row changes from BLOCKED to FAIL. Counts become
**97 PASS, 18 FAIL, 4 BLOCKED, 39 MANUAL, 704 NA**, across 862 rows. Other
results are inherited. The manual counterpart accepted in CSA20 remains
separate, as do the new local protocol scenarios.

## Independent fixture

`test_ota_chip_provider.py --default-provider` explicitly writes a provider on
the authenticated fabric and reads it back before UpdateAvailable announcements.
Event subscription is established first. This supplies the initial normal query
opportunity; further announcements retain the existing retry/daily schedule.
Without the flag, the previous SimpleAnnouncement route is unchanged.

This is a deliberate, documented laboratory setup, not an undisclosed change
to the original automatic test. It uses unmodified chip-tool and CHIP Provider,
actual decoded QueryImageResponse fields and real elapsed time. No clock,
120-second minimum, provider delay or requestor backoff was accelerated.

Seven independent scenarios cover:

- Busy/60: no early second query, then UpdateAvailable and full signed update.
- Busy/180: the response-to-next-query interval respects the full provider delay,
  then transfer, simulated install and restart complete.
- NotAvailable: no second query or BDX/install during a real 120-second observation.
- Invalid BDX URI and same-version offers: actual responses are decoded, the
  requestor returns to Idle without BDX/install, and fresh CASE retains version1.
- Two separate full updates, one under Memcheck and one with ASan/UBSan/LSan:
  token/version binding, authenticated image, final BlockAckEOF, simulated
  restart, NotifyUpdateApplied and fresh CASE version/BootReason readback.

Core **11.20.3.2** requires returning to the next query opportunity for
same/older versions or unusable URIs. Busy/NotAvailable respect the 120-second
floor and supplied provider delay; Core **11.20.6.5.2** measures the latter
from the response. The pinned provider omits DelayedActionTime for NotAvailable,
which is permitted. This does not prove behavior with that optional field present.
Invalid URI and same-version rejection use a short post-decision observation,
not a full-day polling acceptance or an exhaustive URI/version test.

The seven scenarios pass **134 checks**: 21 each for Memcheck/sanitizer updates,
24 each for Busy/60 and Busy/180, 14 for NotAvailable, and 15 each for invalid
URI and same-version rejection. Actual query intervals are **120203 ms** for
Busy/60 and **180200 ms** for Busy/180; the latter is **180198 ms after the
provider response**. Memcheck across both host boots reports **55235 matched
allocations/frees, zero errors/live bytes and no suppressions**. Separate
ASan/UBSan/LSan and all other host stderr files are empty. These memory counts
cover the C host, not independent CHIP processes.

The actual response predicate is rechecked against all seven captures. Six
negative controls are rejected: wrong status, shorter provider delay, wrong or
missing offered version, query before 120 s and query before the 180 s provider
delay. Two exact lower-bound positive controls also pass. Per-boot memory
results, trace hashes and checks are in the [JSON evidence](csa28-results.json).
Local acceptance is not a replacement automatic PASS or certification.

## Reproduction and scope

Use the existing [OTA host recipe](../ota-host.md) and fresh state/output
directories. Add `--events --default-provider` for `update`, `busy-60`,
`busy-180`, `not-available`, `invalid-uri` and `same-version`. The update runs
also use `--apply-binding`; run Memcheck first, then separately the sanitizer
binary without Valgrind. Actual keys, credentials, state and logs stay ignored.

The isolated TH host has a supervisor that restarts only after a clean exit
with the `OTA_SIM_REBOOT` marker, retaining its existing state. This was ready
for step5; run457 failed before any update or restart occurred. The supervisor
stopped the node cleanly after the original test completed.

```sh
python -m py_compile tools/matter/tests/test_ota_chip_provider.py
python tools/matter/tests/test_ota_chip_provider.py --help
python tools/matter/check_test_map.py
git diff --check
```

The optional runner requires Python cryptography; its CLI and network scenarios
are checked on Linux. Local Windows Python syntax compilation succeeds, but
its help invocation lacks cryptography; no Windows dependency installation or
Windows node run is claimed. Both host binaries are reused from CSA26 after
verifying the current 360-file C/H source manifest. No rebuild or new CTest
campaign is claimed for this Python/docs-only change. The inventory stays at
236 mapped files, 87 native definitions, 59 core sources and 75 public headers.

Changed files: the optional runner gains the explicit default-provider flag;
the host guide documents it; this report/result JSON, README, status and roadmap
record the actual outcome and next task. Production code and resource budgets
remain unchanged. User-paired Windows nodes were not modified.

## Remaining work

The initial-query precondition awaits CSA/test-maintainer clarification.
No physical firmware/bootloader, ecosystem UI, daily wall-clock query,
128 kB RAM fit or full campaign rerun was verified. The four remaining BLOCKED
rows are operator-dependent: General Diagnostics, Group Key Management,
Identify and Device Attestation.

The same-version control uses a fresh version1 host and version1 offer. It
validates numerical equality rejection, not the original test's version2 offer
after its multi-step update sequence. The seven fresh scenarios do not prove
all original sequential subscription/provider-restart interactions.

**Next: CSA29 — TC-I-2.2, Identify timing and the x86 observation fixture.**
The host currently declares IdentifyType0 and logs simulated callbacks; do not
claim a physical indicator was observed. Review the unchanged manual prompts
against that declared type before supplying any operator assessment.
