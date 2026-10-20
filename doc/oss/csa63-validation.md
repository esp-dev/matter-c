# CSA63: QueryImage provider handoff and retry attribution

CSA62 was committed as `714781e`; the starting tree was clean. No production
implementation, policy, default, public API or PICS changes are justified by this
stage. The unchanged original TC_SU_2_2 retains FAIL. Two different observed
provider handoffs explain why observing Querying alone is insufficient to prove
which QueryImageResponse reached the requestor. Full fingerprints, outcomes and
cleanup are in [the receipt](csa63-results.json).

## Original procedure: valid response crosses the scenario boundary

Unforced run607 uses private scalar diagnostics and the existing explicit local
query fixture, with the original Python/support/PICS bytes unchanged. It receives
Busy with60s delay. After the120s floor, the automatic retry reaches the old
provider, which is still running and now returns UpdateAvailable/version2. The
native host accepts the image and starts BDX. The original procedure stops that
provider and enters its NotAvailable scenario without resetting this download.
Step2 fails at+0.4s: Downloading is forbidden while waiting for Querying. Later
response scenarios remain pending. This differs from run605's step3 failure.

The first scenario's guard permits Downloading after its120s observation. A
valid positive response is therefore possible before the provider handoff. The
two actual decoded responses are Busy60 and UpdateAvailable2, separated by
120158ms; that is a response-to-response interval, not measured request spacing.
No actual NotAvailable response is present in this run. Accepting an available
image is not evidence of a native defect.

## Controlled loss: transport error, then retained backoff

Separate diagnostic run608 deliberately kills only the first disposable provider
after Busy is decoded and before the120s retry. The helper verifies PID birth
and exact executable argv0 before SIGKILL; it does not restart shared TH services
or touch paired Windows nodes. The original Python/support/PICS bytes remain
unchanged. This injected-fault execution is excluded from campaign classification.

The restarted provider retains its persistent identity but has lost the volatile
CASE session. The requestor reuses its existing connection. Four received packets
are explicitly logged by the peer as belonging to an unknown session and dropped.
MRP times out after6232ms. Query completion is `MATTER_PORT_ERROR` (6), with no IM
error and zero response bytes. The native state becomes Idle/Failure, not the
Idle/Success produced by an actual NotAvailable response.

Busy was failure1; this transport failure is failure2. The query policy schedules
240s from failure completion. An explicit owner query and a provider announcement
do not bypass it. The original step2 nevertheless passes after seeing Querying;
it never proves receipt of NotAvailable. Step3 then fails its120s wait for
DelayedOnQuery before the next retry is due. Its raw FAIL is retained.

Runtime diagnostics place failure completion at140477ms, the global120s floor
at260477ms and next due at380477ms. These are component-relative monotonic
timestamps; dispatcher time can lag the runtime pump. They are not packet
timestamps. The connection token is an opaque local handle, not a wire SessionID.
The original teardown ends the observation before the next due query: no later
fresh CASE or successful recovery is claimed here.

This establishes a controlled mechanism consistent with the shape of run605.
It cannot retrospectively prove that uninstrumented run's exact cause. Run607's
different phase-boundary failure and run608's deliberate fault remain separate.

## Specification and clarification draft

Core1.6.1 section11.20.3.2, printed pages999-1003, requires at least120s between
queries, subject to the specified clock-reset exceptions and provider delay.
Retrying the same Busy provider at least once is a recommendation. With no
alternate provider, a NotAvailable retry must also respect the minimum interval
and any optional delay. Failure to receive an application-layer response SHOULD
be considered equivalent to NotAvailable. This availability-negative recommendation
does not make a transport timeout into a decoded NotAvailable response.

Without a verified image, error recovery may choose an alternate provider or
continue with the same one within the query timing constraints. The240s value is
current implementation policy, not a Matter-required timeout. A120s minimum is
not a requirement to query exactly then or produce a response inside a120s test
observation. Nothing here justifies fabricating a response, discarding a valid
UpdateAvailable or bypassing rate limits to obtain a green test.

Local clarification draft, **not sent to CSA**:

- How should independent QueryImageResponse scenarios synchronize provider
  shutdown/restart with automatic retries and an already accepted image?
- Should the NotAvailable step prove that response was sent/decoded rather than
  only observing Querying, which is also possible before a transport timeout?
- What observation bound accommodates a permitted retry policy after a provider
  restart, given that120s is a minimum rather than an exact retry deadline?

## Verification and limits

| Scenario | Outcome | Coverage |
| --- | --- | --- |
| Original TC_SU_2_2, run607 | FAIL step2 | Actual old-provider UpdateAvailable, then Downloading |
| Original procedure with deliberate provider loss, run608 | FAIL step3 | Unknown CASE session, MRP timeout, preserved240s backoff; diagnostic only |
| Independent actual NotAvailable, Memcheck | PASS13 | Decoded status2, Querying/Idle success events,120.28s observation, fresh CASE/version1 |
| Independent actual NotAvailable, separate ASan/UBSan/LSan | PASS13 | Same response/state/error distinction,120.30s observation, clean stop |
| Clean focused builds |2/2 each|Normal and allocation query targets, normal and sanitizer builds |

Memcheck reports37783 allocations and37783 frees, zero errors and zero live
bytes/blocks. Native stderr is empty in both independent variants. Neither
negative-response scenario downloads, installs or restarts an image. Full positive
signed-update/two-boot memory evidence is reused from CSA62 only after checking
all production C/H inputs and exact baseline-binary identity; it is not rerun here.

The new heap-owned query regression uses the public API: Busy60, transport error,
Idle/Failure, owner query preserving240s backoff, then an actual NotAvailable
resetting failure count, and the following Busy using120s again. It adds no
production memory, thread, timer or allocation. The test map records this chain.
All362 clean-build C/H files match the working tree byte for byte; only this test
differs from CSA62. Private diagnostics differ in three files solely for scalar
query/result/deadline and connection/MRP logging. No warning lines occur in the
final diagnostic or clean focused builds.

Provider responses are independently decoded with the existing public driver's
TLV/SDK JSON reader after stripping only the anchored provider-log prefix.
Cumulative snapshot copies are deduplicated; raw log hashes remain unchanged.
Missing standalone JSON trace files did not mean the SDK stdout trace was absent.
Earlier private bootstrap/escape/script errors and one SSH timeout are retained
as setup faults in the receipt. Original sources stayed unchanged; the preexisting
CSA58 `sdk_container.py` laboratory modification remains, so this is not a pristine
TH installation claim. Both VM stage process lists are empty; TH is idle and
temporary PAA files were removed. No Windows build, paired-node replacement,
physical-device test, full applicable-suite rerun or certification is claimed.

```text
cmake --build BUILD -j 3 --target test_ota_query test_ota_query_alloc
ctest --test-dir BUILD --output-on-failure -R '^(test_ota_query|test_ota_query_alloc)$'
# Original TH identities: TC_SU_2_2, endpoint0, SDK Python Tests, runs607/608.
# Private fixtures supply paths/interface/state;608 additionally injects provider loss.
python tools/matter/tests/test_ota_chip_provider.py ... --mode not-available --events --local-query --require-trace --valgrind
# Repeat with a separate sanitizer binary, without Valgrind.
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

Counts remain122 PASS/28 FAIL/5 prerequisites, including manual outcomes. Next:
**CSA64**, observe the next permitted retry after controlled provider restart,
requiring fresh CASE and complete signed OTA recovery. A scheduled deadline alone
is not proof of recovery; keep any original CSA verdict separate.
