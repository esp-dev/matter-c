# CSA62: drain Applying reports before simulated OTA reboot

CSA61 was already committed as `d88d421`; the starting tree was clean. This
campaign attributes and repairs the fast-reboot event capture gap retained in
CSA60. The unchanged original TC_SU_2_7 is not rerun: its known step1
default-provider/callback ordering failure happens before this boundary. No
original test/PICS assertion or official outcome is changed.

## Attribution and change

The frozen CSA60 sanitizer host reproduces the problem with an immediate signed
update and a real5s minimum event-report interval. Native state publication
returns success for Applying, followed by accepted installation and immediate
`OTA_SIM_REBOOT`. The independent peer captures no StateTransition before that
boot ends. Its positive event check fails. This isolates the premature host
shutdown without requiring a Busy response or an artificial controller delay.

The previous host called stop as soon as `ota_reboot_requested` became true.
Stop closes subscriptions; it is not a final event flush. The event may be
waiting for its minimum interval, report construction, IM Success or reliable
MRP confirmation. Core1.6.1 section11.20.7.7 requires the StateTransition event;
this host lifecycle fix leaves subscription intervals, ApplyUpdateResponse
delays, signatures, provider authorization and query rate limits unchanged.
The selected30s host upper bound is an application policy, not a normative
Matter timeout.

The runtime records the event number when Applying is actually appended. A new
owner-only `matter_runtime_ota_reboot_ready` observes interested subscriptions'
confirmed event cursor through the shared IM/dispatcher layer. The cursor moves
only after the complete report, IM Success and MRP confirmation. Unrelated,
EventMin-excluded, failed/cancelled and closing subscriptions do not block.
There is no new allocation, buffer, thread or library-owned timer. Public
configuration structures and existing `reboot_requested` semantics are preserved.

The host continues its existing RX/TX/process loop until ready or30s have elapsed,
then logs readiness and the actual wait before restarting. Explicit stop, process
deadline and error paths still take precedence. Bounded/volatile retention is
unchanged: cursor readiness is not persistent event storage or a guarantee for
offline/future subscribers or overflowed payloads. See [runtime](../runtime.md)
and [host contract](../ota-host.md).

## Verification

The OTA peer now checks live Downloading -> Applying, target version and Success
before starting the next native boot. A later history read cannot supply this
pre-reboot check. `--event-min-interval` accepts the uint16 range and uses real
subscription timing; the requestor clock is not accelerated.

Final outcomes and fingerprints are in [the receipt](csa62-results.json).

| Scenario | Result | Checks | Report wait |
| --- | --- | --- | --- |
| Frozen CSA60 sanitizer baseline, min5s | FAIL |14|Old immediate shutdown; no StateTransition captured|
| Fixed min5s, Memcheck | PASS |21|Already confirmed before installation gate:0ms|
| Fixed min5s, separate sanitizers | PASS |21|2111ms, ready1|
| Fixed min60s, Memcheck negative control | Expected raw FAIL |10|30005ms, ready0|
| Prior Busy180, instant apply, separate sanitizers | PASS |24|93ms, ready1|

The Busy retry is180154ms after the actual response. Positive Memcheck boots
have35582/35582 and19552/19552 allocations/frees; timeout control has35585/35585.
All show zero errors and zero live bytes/blocks. Native stderr is empty in all
variants. Positive update checks include live Applying, target version, exact
image bytes, signed installation, Notify and fresh CASE version2 after restart.

Two positive5s scenarios exercise full signed transfer, token/version binding,
restart, NotifyUpdateApplied and fresh CASE. Memcheck and ASan/UBSan/LSan run
separately. A60s interval deliberately exceeds the host wait: the positive live
event assertion must fail, while the host logs `ready=0` after30s. That raw FAIL
is retained as a negative control, not converted to a CSA PASS. It proves bounded
shutdown without bypassing the negotiated report interval or claiming delivery.

The prior Busy180/instant-apply sanitizer scenario is rerun separately with its
original zero minimum interval. Its first launch was rejected by argparse because
an update-only token-binding flag was supplied with Busy mode. No native process
or protocol test started on that attempt; the corrected command is recorded
separately and no assertion was weakened.

Clean Linux builds pass11/11 focused CTests in each variant: runtime, Subscribe,
dispatcher, query, requestor and apply, including allocation variants. The new
cursor tests cover a pending minimum interval, unrelated paths, EventMin, IM
Success arriving before MRP confirmation, acknowledged cursor advancement and
cancellation. No compiler warning lines were found. Test inventory and campaign
consistency checks also pass; raw credentials, images and logs stay private.

```text
cmake --build BUILD -j 3 --target matter-node test_runtime test_runtime_alloc test_im_subscribe test_im_subscribe_alloc test_dispatch test_ota_query test_ota_query_alloc test_ota_requestor test_ota_requestor_alloc test_ota_apply test_ota_apply_alloc
ctest --test-dir BUILD --output-on-failure -R '^(test_runtime|test_runtime_alloc|test_im_subscribe|test_im_subscribe_alloc|test_dispatch|test_ota_query|test_ota_query_alloc|test_ota_requestor|test_ota_requestor_alloc|test_ota_apply|test_ota_apply_alloc)$'
python tools/matter/tests/test_ota_chip_provider.py --help
# Add private paths/interface/output and use a normal node:
python tools/matter/tests/test_ota_chip_provider.py ... --mode update --events --event-min-interval 5 --local-query --require-trace --apply-binding --valgrind
# Repeat with a sanitizer node, without Valgrind.
python tools/matter/tests/test_ota_chip_provider.py ... --mode busy-180 --events --local-query --require-trace
# Negative control: --mode update --events --event-min-interval 60; retain expected live-event FAIL.
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

No new original CSA execution, Windows build, paired-node replacement, physical
device test, full applicable-suite rerun or certification is claimed. Campaign
counts remain122 PASS/28 FAIL/5 prerequisites, including manual outcomes. Original
TC_SU_2_7 FAIL606 and the other external questions remain open.

Next: **CSA63**, attribute the provider-restart/query-failure boundary retained
by CSA60 TC_SU_2_2. Separate actual response reception and retry backoff from
original observation windows before deciding on a native correction.
