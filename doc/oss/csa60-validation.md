# CSA60: application query trigger; original OTA FAIL retained

Added an explicit application-owned query opportunity for the selected live OTA
provider, forwarded through the runtime/server. The opt-in host `--ota-control`
accepts `ota-query` on its existing stdin pipe. No new thread, network endpoint,
allocation, default scheduling change or original CSA/PICS edit is introduced.
The call preserves the 120s minimum, provider delay, urgent jitter and growing
Busy/error backoff; active query/update/reboot cannot be preempted. API ownership
and errors are documented in [runtime](../runtime.md) and [host](../ota-host.md).

## Original QueryImageResponse test

Revisited CSA28 before changing code. Core1.6.1 sections11.20.3.2/11.20.7.4 allow
daily polling and schedule reason1 announcements at the next opportunity. The
original test assumes a prompt query. This run adds a recorded local application
query after authenticated announcements, keeping the original source/assertions
and default production policy unchanged. This extra fixture precondition is
essential when interpreting the results.

Original **TC_SU_2_2 run605 remains FAIL**, now at step3. The first Busy60 response
and required120s interval pass. Its retry overlaps the test's provider restart
for NotAvailable. Step2 passes after observing Querying, but native completion is
failure (reason2), not a decoded NotAvailable response (reason1). Step2 PASS is
therefore insufficient proof of that response scenario. At the next provider
restart, the explicit application query preserves growing error backoff, and
the original120s wait for DelayedOnQuery expires. Steps4/5/6 remain pending.
Transport/restart ordering is a lead; its exact failure is not fully attributed.
No backoff bypass or test-specific state transition was added.

Earlier run604 fails before protocol because host paths were supplied inside the
SDK container; corrected mount paths resolve that fixture fault. The earlier
missing-output-directory bootstrap failed before any original run. Raw attempts
remain private; hashes/results are in [the receipt](csa60-results.json). Shared
support and original test fingerprints are unchanged. The preexisting TH
sdk_container.py lab modification documented in CSA58 remains.

## Full memory and focused acceptance

All scenarios use the new frozen Linux hosts and actual CHIP provider/controller,
signed16585-byte image, simulated restart, NotifyUpdateApplied and fresh CASE.

| Scenario | Result | Checks | Scope |
| --- | --- | --- | --- |
| Busy180 + events, Memcheck | PASS |23|Actual retry after180199ms from response; two clean boots|
| Busy180 + events, separate sanitizers | FAIL |18|Applying missing from captured event sequence; no memory diagnostic|
| Proceed180 + events, separate sanitizers | PASS |26|Actual180005ms apply delay; complete event sequence|
| Immediate update + token/version binding, final driver, Memcheck | PASS |15|Two boots, no event-sequence claim|
| Same final-driver update, separate sanitizers | PASS |15|Two boots, empty native stderr|

The instant-reboot event failure remains open. The delayed-apply PASS is a
different provider scenario and does not supersede it. Applying generation versus
subscription delivery/capture needs attribution in CSA61.

Busy Memcheck boots have36430/36430 and19569/19569 allocations/frees;
final-driver boots35539/35539 and19554/19554. All have zero errors/live blocks.
ASan/UBSan/LSan run separately; native stderr is empty. Final focused CTests pass
8/8 per build: runtime/query/requestor/apply and allocation variants. Extended
query tests cover active jobs, stale providers, clock regression, stop, Busy180,
growing retry backoff, minimum spacing and urgent jitter. No compiler warning
lines were found in these build logs. CLI incompatible fixtures reject with2;
help, test inventory and campaign checks pass.

```text
python tools/matter/tests/test_ota_chip_provider.py --help
# Supply private node/provider/controller/credential/interface/output arguments:
python tools/matter/tests/test_ota_chip_provider.py ... --mode busy-180 --events --require-trace --local-query --valgrind
# Separate sanitizer binary, no --valgrind; retain instant-reboot event failure.
python tools/matter/tests/test_ota_chip_provider.py ... --mode apply-proceed-180 --events --require-trace --local-query
python tools/matter/tests/test_ota_chip_provider.py ... --mode update --require-trace --apply-binding --local-query
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
```

TH is idle, temporary PAA removed and stage hosts stopped. Existing paired Windows
nodes/stores are untouched. No Windows build, physical-device acceptance, full
matrix rerun or certification is claimed. Counts remain122 PASS/28 FAIL/5
prerequisites; original and independent outcomes remain separate.

Next: **CSA61**, original TC_SU_2_7 and attribution of fast-reboot OTA event capture.
