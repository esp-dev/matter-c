# CSA58: frozen automatic regression sweep

**The sweep is complete, but stable acceptance is FAIL.** After correcting two
test-input mismatches, 98/99 positions pass and
1/99 remains failing. Original TC_IDM_5_2 run 560 fails again
in unchanged confirmation run 595 (FAIL).
[All original receipts and hashes](csa58-results.json) preserve every outcome.

## Full sweep and bounded follow-ups

Original runs 496-594 execute all 99 previously passing automatic positions:
96 PASS and 3 FAIL.
Three separate follow-ups confirm Timed Write and correct two fixture inputs;
there are 102 original TH case executions, with no changed test/assertion.
The effective per-position outcomes below use the two corrected fixtures, while
preserving the first protocol FAIL. This is one full sweep, not an endurance
soak or certification.

| Lifecycle group | Positions | PASS | FAIL |
| --- | ---: | ---: | ---: |
| commissioning | 20 | 20 | 0 |
| composition | 13 | 13 | 0 |
| interaction-security | 34 | 33 | 1 |
| measurements | 18 | 18 | 0 |
| resource-long | 2 | 2 | 0 |
| setup-codes | 3 | 3 | 0 |
| yaml | 9 | 9 | 0 |

Collections: 9 YAML, 9 mandatory Python and 81 SDK Python positions. Endpoint-specific
positions remain separate even when they call the same shared implementation.
Primary step states: {"failed": 3, "not_applicable": 138, "passed": 1022, "pending": 24}. Not-applicable steps
remain not-applicable; they are not counted as successful checks.

The measurement group includes aggregate import/export energy, actual changes
from TestEventTrigger, aggregate and three-phase EPM, Identify, Meter
Identification change reports and Power Topology. TC_RR_1_1 and TC_SC_3_6 both
pass with their full resource fixture and observation rules. The existing optional
local-session-ID check is retained. TC_SC_7_1 uses two actual disposable instances
with different valid setup codes.

## Input mismatches corrected without changing the DUT

TC_CNET_4_9 run 583 fails before the first protocol step: its Wi-Fi accessors need
an explicit in-test Wi-Fi mode. Restore `in-test-commissioning-method=ble-wifi`,
the simulation parameter used by [CSA15](csa15-validation.md), while initial
commissioning remains on-network and the native host remains Wi-Fi-connected in
simulation. Follow-up run 596 is PASS.
This does not claim a physical BLE/Wi-Fi test or modify PICS/assertions.

TC_DD_1_16 run 590 uses a historical QR with a different full discriminator and
therefore cannot discover this instance. The unchanged test also checks actual
commissionable discovery, not just payload decoding. Encode the live host's
PIN, discriminator 3918, VID and PID with the existing verified C payload helper;
follow-up run 597 is PASS. Manual-code
TC_DD_1_17 already passes because its short discriminator 15 still matches.
These are simulated payload/discovery checks, not final physical-label approval.
Both first FAILs remain in the evidence rather than being deleted or relabelled.

## Repeatable Timed Write failure

TC_IDM_5_2 run 560 fails step 4 and unchanged confirmation run 595 fails the same
step. The test source hash matches the earlier PASS. TH receives an IM
WriteResponse for the delayed Timed Write and then fails because its call did
not raise the expected timeout. The preceding delayed Timed Invoke receives
StatusResponse/TIMEOUT (0x94). Core 1.6.1 section 8.7.2.3 requires a
StatusResponse/TIMEOUT when the Timed Write interval has actually expired.

This receipt does not by itself prove when the native interval began/expired,
the WriteResponse status or whether NodeLabel changed. Actual peer send/native
receive timestamps, status decoding and side-effect readback are the next
reproducer. Native deadline/lifecycle behavior and peer busy-wait scheduling
must be distinguished before selecting a fix. No native behavior was changed
in this sweep and the original test was not patched to obtain green.

## Frozen identity, lifecycle and cleanup

Native binary SHA-256:
`a86841888db781d2766a09bce78bd7d467831c88089057e44544026a0e860906`.
All 362 current C/H inputs match the CSA56/57 export. The evidence freezes
75 test/metadata files and three shared support files; their hashes and
the binary match again after all executions. Three effective current PICS
snapshots retain the root/aggregate/phase declarations and CSA35/36 discovery
corrections; no PICS flag changes during the run. The two new follow-up projects
change only the documented fixture parameters.

Preflight already showed an existing local `sdk_container.py` support change in
the TH installation, dated before this sweep. Its hash is recorded and checked
again. CSA58 does not edit it or claim a pristine TH checkout. The recorded
harness repository revision identifies TH, not a newly verified SDK Git commit.

Each position starts a fresh native process with empty durable state and uses
new commissioning rather than the controller's previous snapshot. Real in-test
factory-reset prompts affect only the disposable instance. The same binary is
retained across all 104 native process lifetimes, including follow-ups;
all stop with code 0 and empty native stderr. Paired desktop instances and their
stores are untouched. TH ends idle and both temporary-PAA lifetimes are cleaned
up. No case execution deadline expires or unexpected operator prompt occurs.

An auxiliary API status request times out during TC_IDM_4_3. Local SDK output
confirms ongoing subscription/heartbeat progress, so the original test continues
and ends PASS, run 559. It is not aborted/resubmitted for that observer timeout.
No second controller WebSocket is injected into an active test.

## Validation and remaining work

No native compilation or new sanitizer run is claimed here. The frozen host
reuses the separate full Memcheck and ASan/UBSan/LSan scenarios from
[CSA56](csa56-validation.md) and [CSA57](csa57-validation.md) after checking
source/binary identity. Python lifecycle, collector and report helpers pass
syntax compilation. TH receipt collection warns that its legacy `--log` option
is deprecated; that is not a native compiler warning.

Executed checks include `python tools/matter/check_test_map.py`,
`python tools/matter/csa_campaign.py --write`,
`python tools/matter/csa_campaign.py` and `git diff --check`. Original cases
are selected by exact case/endpoint/collection; receipts use separate
`th-cli test-run-execution --id <id> --json` and `--log` invocations. Local
credentials, controller stores, raw logs, VM addresses and helpers stay outside
the public export.

The 18 older automatic FAILs and 37 manual positions are not rerun, including the
owner's deferred DGGEN 2.1 case. Effective automatic counts: 98 PASS,
19 FAIL, 1 BLOCKED; manual outcomes remain 24 PASS, 9 FAIL, 4 BLOCKED.
Totals: 122 PASS/28 FAIL/5 prerequisites across 155
applicable positions, plus 707 NA. The newly failing position remains open.
No final physical labels, live-IP/timed-client fixture, production provisioning,
radio/firmware, embedded RAM-fit or Google/Apple UI acceptance. No push.

Next: CSA59, diagnose the repeatable Timed Write failure with actual packet-time
and side-effect evidence, apply only a confirmed standards-correct native fix,
then rerun the original case unchanged plus relevant timed/error paths under
full Memcheck and separate sanitizers. Return to older unresolved FAILs afterward.
