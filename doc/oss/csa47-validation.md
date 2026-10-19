# CSA47: applicability and concrete prerequisites

This is a **read-only review**, not a new Test Harness run or test PASS. The
original test predicates, current project PICS/API selection, prior payload
artifacts and actual host presentation/client scope were inspected. No PICS,
native code, desktop process, credential or original TH source was changed.
See [review receipts](csa47-results.json) and [continuing queue](csa-campaign-status.md).

Two old checkpoint positions were wrongly left MANUAL. Original custom
TC-DD-1.3 requires `MCORE.DD.NFC`, explicitly false; TC-DD-1.4 requires
`MCORE.DD.CONCATENATED_QR_CODE`, absent/not enabled. The current TH API excludes
both under the same PICS fingerprint. Correct these two to NA with explicit
source/API evidence, preserving the original CSA42 checkpoint and history.
No capability was disabled or failed case hidden. No forced NFC or synthetic
multi-device payload is submitted as a supported DUT feature.

Four positions remain **MANUAL/BLOCKED**, with concrete prerequisites:

| Case | Missing evidence or fixture | Next prerequisite |
| --- | --- | --- |
| TC-DD-1.6 | Final QR label/presentation and physical scan/module/ECC/version measurements | Provide final artifact and instrument/scan evidence; CSA31 headless bitmap scan is only partial software coverage |
| TC-DD-1.7 | Final manual setup material and measured typography/grouping | Provide approved printed/provided card; desktop currently shows QR only, and the prior CHIP-generated lab card is not a final product label |
| TC-IDM-5.1 | No host application trigger for DUT TimedRequest followed by timed Invoke | Clarify applicability to limited untimed OTA client; if required implement/expose its real timed-client trigger, not a chip-tool request pretending to originate at DUT |
| TC-SC-4.4 | No executed controlled peer IP-change flow; VendorID client is not declared | Clarify limited OTA controller role and supply peer address-change fixture with genuine supported DUT request; retain BINFO.C.A0002=false steps as NAs |

Read/codec/server timed support does not prove client TimedRequest execution.
Actual untimed OTA invokes in CSA45 remain accepted separately. Original
IDM5.1 gates timed Write on false WriteRequest PICS and describes its timeout
step as out of scope; neither supplies the missing timed Invoke evidence.
SC4.4 gates both VendorID reads on false BINFO.C.A0002; earlier rediscovery
regressions do not complete its original live address-change flow.

The tracker now keeps manual blockers visible and requires reason/prerequisite
fields. NA corrections require the unchanged PICS hash, original source hash
and observed TH exclusion. Validation rejects three deliberately bad metadata
controls: absent NA review, absent blocker prerequisite and inconsistent counts.
All four manual blockers remain visible. No native build, runtime/memory test,
physical label, live network-address change or official testcase was executed
in this metadata review. Earlier results are inherited, not rerun or upgraded.

Totals become **155 applicable +707 NA =862 positions**:97 PASS,18 FAIL,
3 BLOCKED and37 MANUAL. Manual outcomes: **20 PASS,9 FAIL,4 BLOCKED,4 not run**.
No test verdict is invented for the blocked positions. Continue **CSA48** with
IDM6.1/6.2/7.1/8.1, then reassess the three older BLOCKED rows before native repairs.
