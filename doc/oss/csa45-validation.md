# CSA45: BDX receiver and real IM Invoke client

Original manual **TH run481**: **TC-BDX-1.2, TC-BDX-2.2 and TC-IDM-1.1 PASS**;
**TC-BDX-2.3 FAIL**. Sources, support and PICS unchanged. See [receipts](csa45-results.json)
and [continuing queue](csa-campaign-status.md). Counts of automatic outcomes do
not change when manual procedures finish.

## Actual complete transfers

Two fresh disposable node/provider setups complete the signed OTA simulation:
Memcheck first, ASan/UBSan/LSan separately. The existing provider recorder gains
`--bdx-profile`. Shared JSON trace reassembly retains the existing OTA decoding;
BDX payloads are binary octets, not TLV. Decode the actual peer ReceiveInit and
ReceiveAccept, selected synchronous receiver-drive0x20, range flags, proposed/
accepted1024-byte block bound and length-delimited nonempty file designator.
Optional offset/length/metadata are absent; effective offset is0. No nonzero
resume, sender-driven transfer or BlockQueryWithSkip is claimed.

Actual BlockQuery and Block/BlockEOF counters are sequential0..16, same exchange.
Each data length fits the negotiated bound. Reassembling all17 blocks produces
exactly the source16585-byte image; its hash matches, and final AckEOF counter16
matches BlockEOF16. Four in-memory oracle mutations (counter, missing AckEOF,
image byte and mode) are rejected using a retained actual peer trace. Core1.6.1
11.22.5/11.22.6 is the basis;11.22.6.2 says next BlockQuery implies acknowledgement
of the previous block. A transport MRP ACK is never substituted for BDX AckEOF.

Both runs also capture four genuine C DUT InvokeRequests at the reference OTA
provider: QueryImage0, ApplyUpdateRequest2, NotifyUpdateApplied4 and a new
QueryImage0 after simulated reboot with retained fabric. Every request has one
CommandDataIB targeting endpoint0/cluster0x29, suppressResponse=false,
timedRequest=false and IMrevision13. Thus the original IDM1.1 step1 request and
three further requests have separate actual evidence. The original permits any
supported commands, so its OnOff examples are not required. Wildcard Invoke and
the two BDX procedure steps explicitly described as out of scope are answered
NOT APPLICABLE. No timed/batched/arbitrary client support is inferred.

## Failed recovery remains failed

A separate Memcheck node uses the existing fault-only provider to stall BDX after
5120 bytes while keeping secure transport/MRP live. After at least300 real
seconds the node discards the partial image, reports Idle and retains version1.
Those observations pass. After stopping that peer and launching the unmodified
provider with its same persisted identity, a new announcement does not produce
a new QueryImage/ReceiveInit within the bounded240-second observation. The
restart procedure therefore FAILS. Its required restarted Block/EOF observations
are also missing. Do not count fresh positive nodes as recovery of this node.
Operator precondition shorthand referring to the interruption is not a claim
that recovery succeeded. Native versus fixture/session prerequisites have not
yet been attributed; investigation belongs in the repair/triage pass. This long
failure was not repeated under sanitizers.

## Validation and limits

Each successful transfer passes16 checks; the failed scenario has13 successful
preliminary observations, not an overall PASS. Memcheck allocations/frees:
35,599 and19,573 across the two positive boots,31,317 in the failed attempt;
all have zero errors/live bytes. Separate positive sanitizer run has two boots,
empty stderr and clean stop. Existing `test_bdx`/`test_ota_requestor` pass2/2 per
build with no observed incremental-build warnings. All362 native inputs and both
host binaries still match CSA35; no new host compilation/native/API/PICS change.
TH is idle and disposable processes stopped; desktop pairings are untouched.

Executed both recorder modes as recorded in JSON, focused CMake/CTest, trace
post-decoding and oracle controls, campaign/inventory/privacy/link checks and
`git diff --check`. This is original manual/operator acceptance, not automatic
certification. No full matrix, physical/radio/Home UI or embedded RAM test.

Counts remain97 PASS/18 FAIL/3 BLOCKED/39 MANUAL/705 NA. MANUAL now has
**17 PASS,8 FAIL,14 without outcome**. Continue **CSA46** with diagnostic events,
simulated Wi-Fi reorder and unsupported CacheAndSync policy rejection; retain
real BLE/physical boundaries.
