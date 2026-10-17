# CSA26: OTA Requestor events

CSA25 was committed as **`aad5772`**. This step fixes observable OTA event
behavior and tests both installed TC-SU-2.7 procedures against Matter Core
R1.6.1. [Results, individual events and evidence hashes](csa26-results.json)
retain every executed outcome, including failed attempts.

## Official results

- **TC-SU-2.7 manual PASS, TH run455.** Six verification steps pass, consent is
  NOT APPLICABLE under unchanged PICS, and evidence upload passes. The coding
  agent evaluated actual peer reports before answering each prompt. This is not
  automatic assertions, certification or accredited laboratory acceptance.
- **TC_SU_2_7 automatic FAIL, TH run454**, after the stack fixes. Baseline run453
  also fails. In step1, the script expects Idle -> Querying after subscribing,
  but it already configured the default provider during setup. This host starts
  querying before that subscription; the first live event is Querying ->
  Downloading. Later Python steps were not executed. No assertion, test source,
  PICS or valid polling behavior was changed to force PASS.

Only these two rows change. Counts become **97 PASS, 16 FAIL, 6 BLOCKED,
39 MANUAL, 704 NA** (862 rows). All other results are inherited. The original
TC_SU_2_5 FAIL and separate CSA24b LOCAL-PATCH PASS remain unchanged.

The YAML SHA-256 is
`903dd6166909d7255ac46d4560fdacd7b0747fd73f51009e22199be7f907d6f9`;
Python SHA-256 is
`9a8b0ffa278180cf3aaa772dae3d2d3a1650114c3260a035d784db11a4f8dd31`.
Execution PICS matches the preflight snapshot. Requestor consent remains false.
TH returns to idle; both official source files are unchanged.

## Stack corrections and normative basis

Core **11.20.7.4** defines Idle as not yet processing an update; Downloading and
Applying describe ongoing work. Query handoff previously published an extra
Idle before starting BDX, and successful download published another Idle before
Apply. Handoffs now publish the next owner state directly. Real query errors,
unsupported images, prepare/dispatch failure and failed Apply startup still
return to Idle. A supplied QueryImage delay still waits in Idle until handoff;
retry floors, Busy behavior and Apply timing are unchanged.

Core **11.20.7.7** requires StateTransition on state changes, target version only
for Downloading/Applying/RollingBack, VersionApplied values matching Basic
Information, and DownloadError with actual bytes and nearest integer percentage
when total length is known. Runtime previously always supplied null error
progress. It now reads the terminal progress snapshot before final cleanup.
The file adapter retains validated counters through cancellation and provides
nearest rounding without I/O; unknown length still yields null.

The existing `matter_ota_file_progress()` keeps its prior active/floor semantics.
The host callback uses the new `matter_ota_file_last_progress()` snapshot instead.
The optional runtime callback retains its signature/struct layout, but its
documented contract now requires terminal metadata to remain readable through
cancellation until the next prepare. Persistent schemas and wire types do not
change. No new allocations, global workspaces or task-stack buffers were added.

The new query regression fails against the previous Query module and passes
against the current code. File tests cover exact rounding during fragmented
input, retention after error/cancel/commit, unknown headers and reset at prepare.

## Executed coverage

All fixtures use disposable state, three subscriptions per fabric and transport
capacity 128. The current 360-file C/H manifest matches both builds and the final
repository. GCC normal and ASan/UBSan/LSan builds each pass **15 focused CTests**
with no compiler warnings.

| Independent scenario | Checks | Main event evidence |
| --- | ---: | --- |
| Full update to version 2, Memcheck | 20 PASS | Direct Querying -> Downloading -> Applying; VersionApplied after restart |
| Full update to version 3, separate sanitizers | 20 PASS | Same checks with different signed version; fresh CASE readback |
| Busy / 60 s response, real 120 s minimum | 23 PASS | DelayedOnQuery, reason DelayByProvider, null target |
| AwaitNextAction / 60 s, real 120 s minimum | 28 PASS | Applying -> DelayedOnApply, correct reason/target; retry and install |
| QueryImage ignored by live ordinary provider | 13 PASS | Querying -> Idle / Failure, no download or version change |
| Provider terminated during BDX | 25 PASS | DownloadError, correct byte count/nearest percentage, cleanup and recovery |
| Live-MRP BDX data stall, final repeat | 27 PASS | Actual five-minute Idle timeout, fields and eventual recovery/update |

This is **156 checks across seven accepted scenarios**. Memcheck over two host
boots reports **55192 allocations and frees, zero errors/live bytes and no
suppressions**. Separate sanitizer stderr is empty. Independent CHIP processes
are not included in these memory counts.

The final event-check/parser AST was re-executed over all seven saved captures.
Six controls are rejected: wrong target version, missing Downloading, missing
VersionApplied, wrong ProductID, wrong error percentage and wrong error bytes.
These are checker controls, not hostile packets injected into the C requestor.
Earlier captures retain their actual driver hashes; their final event review
does not require replaying already accepted real delays.

## BDX Idle versus transport failure

Core **11.20.3.5** requires at least five minutes for BDX idle timeout. Core
**11.22.2.6** separately recommends aborting BDX on transport delivery failure;
**11.22.4** requires reliable transport, including MRP over UDP. Provider death
therefore does not isolate an idle timeout.

The terminated-provider case reports failure after **10.651 s**, while its full
observation lasts 301.052 s. This is not five-minute idle acceptance. A separate
laboratory provider stops supplying blocks after 5120 bytes while retaining MRP.
With this fault, failure is observed after **300.327 s**, within a 301.093 s real
observation. DownloadError contains version 2, 5120 bytes, 31 percent and null
PlatformCode, agreeing with the actual file length and transfer. Partial files
are removed and version 1 remains until the subsequent valid update.

The [provider-only patch](../../tools/matter/patches/README.md) targets one copied
Project CHIP translation unit. Its notices/hashes are retained; exact patch
application and compilation were checked. The original SDK at
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7` stays clean and its ordinary provider
binary is unchanged. This is an explicit fault peer, not an unmodified provider
claim or a modification of the C requestor/official TH tests.

The first extra recovery attempt passed Idle assertions but failed with a 90 s
fixture wait after restarting the provider. The first query can use a stale CASE
session, fail, then wait the normal 120 s OTA backoff. Only that fixture bound
was increased to 240 s and the failed capture was retained. A fresh repeat passes
recovery, full transfer, authentication, restart and VersionApplied. No requestor
clock, retry floor or timeout was shortened.

## Reproduction and changed files

Use the existing [OTA host recipe](../ota-host.md), add `--events`, and run fresh
output/state directories for `update`, `busy-60`, `apply-await-60`,
`query-timeout` and `interrupt-retry`. The two update runs use `--apply-binding`,
version 2 with `--valgrind`, then version 3 with the sanitizer binary. The BDX
idle run additionally supplies `--stall-provider /path/to/chip-ota-provider-stall`.
Keep actual credentials, KVS, images and traces outside Git.

```sh
ctest --test-dir /path/to/normal-build --output-on-failure \
  -R '^test_(dispatch|root(_alloc)?|bdx(_alloc)?|ota_(query|apply|update|requestor)(_alloc)?|runtime(_alloc)?)$'
# Repeat separately with the sanitizer build.
python tools/matter/check_test_map.py
git diff --check
```

- `matter_ota_query.c/.h` and `matter_runtime.c/.h`: direct state handoff,
  error fallback and terminal percentage contract.
- Host `matter_ota_file.c/.h` and `matter_server.c`: retained rounded snapshot.
- `test_ota_query.c`, `test_bdx.c`, `test_ota_chip_provider.py`: regression,
  actual event capture/validation, query timeout and separate fault-provider mode.
- Provider patch, its README, NOTICE and provenance: reproducible isolated fault
  injection and third-party attribution.
- Acceptance JSON/report, README, status, roadmap and OTA host guide: results,
  commands, limitations and next task. Existing test inventory remains intact.

## Limits and next task

The automatic subscription-order assumption is a source observation and
reproduced compatibility problem; CSA has not confirmed a correction. The
Python provider-kill/minimum-idle assumption is a separate review item, not an
assertion reached in run454. No official test is silently patched or relabelled.
No physical firmware/bootloader, full campaign rerun, 128 kB target fit or
Apple/Google Home UI test was performed. Paired Windows nodes remain untouched.
On-demand allocation work remains a later stage.

Next: **CSA27 — TC_SU_4_1, OTA Requestor cluster attributes**, retaining the
TC_SU_2_7 observations and evidence for CSA review.
