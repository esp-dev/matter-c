# CSA72: consolidated questions and rerun gates

**DRAFT — NOT SENT. No CSA answer, approved correction or new test verdict is claimed.**

Experimental native x86 Matter1.6.1 profile, TH v2.15.1+summer2026. This consolidates existing results rather than rerunning or upgrading them. Original failures, manual/operator results, independent laboratory acceptance, setup errors and production qualification limits remain distinct. Linked receipts pin the relevant original source versions; this is not a fresh SDK-binary or test-source audit.

Coverage: 32 exact open positions: 27 FAIL and 5 prerequisites. 22 question groups and 4 owner/laboratory prerequisite groups. Campaign total remains123 PASS/27 FAIL/5 prerequisites; manual and automatic results remain separate.

## How to use this package

Review and prioritize the questions with the project owner before selecting any recipient or attachment. CSA/test-maintainer questions request a normative/applicability or accepted-procedure decision; owner/lab items require concrete inputs. Retain a ticket/release/guidance reference and approved scope for each resolved item. No message, submission, upload, account change or test execution is authorized by generating this packet.

The JSON is the source of this list. Each linked receipt retains original run IDs, source hashes, unexecuted portions and independent acceptance limits. Campaign run IDs below can be inherited checkpoint references; explicitly selected reference runs identify the later reviewed evidence. No raw credentials, certificate bytes, private traces or specification PDFs are attached.

| Topic | Cases | Decision owner |
| --- | --- | --- |
| [CSA72-Q01: PASE header flags, lengths and PBKDF parameter meaning](#csa72-q01) | TC-SC-2.1 | CSA / test maintainers |
| [CSA72-Q02: Bad MIC: discard message or destroy PASE session](#csa72-q02) | TC-SC-2.2 | CSA / test maintainers |
| [CSA72-Q03: MRP total sends versus retransmissions](#csa72-q03) | TC-SC-1.3 | CSA / test maintainers |
| [CSA72-Q04: Last-fabric reset and CM advertisement](#csa72-q04) | TC-OPCREDS-3.6 | CSA / test maintainers |
| [CSA72-Q05: Identical trusted root and fail-safe idempotence](#csa72-q05) | TC_CGEN_2_2 | CSA / test maintainers |
| [CSA72-Q06: RevokeCommissioning response on terminated PASE](#csa72-q06) | TC_CADMIN_1_10, TC_OPCREDS_3_4 | CSA / test maintainers |
| [CSA72-Q07: ProxyView in the current revision](#csa72-q07) | TC_ACL_2_4 | CSA / test maintainers |
| [CSA72-Q08: Per-operation statuses in list writes](#csa72-q08) | TC_ACL_2_6, TC_SU_4_1 | CSA / test maintainers |
| [CSA72-Q09: ScanNetworks and fail-safe prerequisite](#csa72-q09) | TC_CNET_4_4 | CSA / test maintainers |
| [CSA72-Q10: BLE precondition and full-network repeat arithmetic](#csa72-q10) | TC-CNET-4.13 | CSA / test maintainers |
| [CSA72-Q11: Positive GroupKeyMap writes with zero group capacity](#csa72-q11) | TC-GRPKEY-2.1 | CSA / test maintainers |
| [CSA72-Q12: Overwrite versus new KeySetID at capacity](#csa72-q12) | TC-GRPKEY-2.2 | CSA / test maintainers |
| [CSA72-Q13: Phased PartsList hierarchy and full-suite closure gate](#csa72-q13) | TC-DESC-2.1 | CSA / test maintainers |
| [CSA72-Q14: Subscribe after all event paths are denied](#csa72-q14) | TC-IDM-6.2 | CSA / test maintainers |
| [CSA72-Q15: Resource exhaustion result after concurrent subscription load](#csa72-q15) | TC-IDM-7.1 | CSA / test maintainers |
| [CSA72-Q16: Optional Leave event with false PICS](#csa72-q16) | TC_BINFO_2_2 | CSA / test maintainers |
| [CSA72-Q17: Timed Write delay measured after real Success](#csa72-q17) | TC_IDM_5_2 | CSA / test maintainers |
| [CSA72-Q18: Optional ordinary BlockAck in receiver-drive BDX](#csa72-q18) | TC-BDX-2.3 | CSA / test maintainers |
| [CSA72-Q19: Provider handoff race and QueryImage observation window](#csa72-q19) | TC_SU_2_2 | CSA / test maintainers |
| [CSA72-Q20: Historical progress replay and retained subscriptions](#csa72-q20) | TC_SU_2_5 | CSA / test maintainers |
| [CSA72-Q21: Default-provider query before event callback registration](#csa72-q21) | TC_SU_2_7 | CSA / test maintainers |
| [CSA72-Q22: Limited OTA client: timed interaction and peer IP-change procedures](#csa72-q22) | TC-IDM-5.1, TC-SC-4.4 | CSA / test maintainers |
| [CSA72-P01: Assigned identity, manufacturer extension and default-value warnings](#csa72-p01) | TC_DA_1_2, TC_IDM_10_1, TC_IDM_13_1 | Product / laboratory owner |
| [CSA72-P02: Controller Wi-Fi migration between two real APs](#csa72-p02) | TC_CNET_4_11 | Product / laboratory owner |
| [CSA72-P03: Final QR/manual-code presentation evidence](#csa72-p03) | TC-DD-1.6, TC-DD-1.7 | Product / laboratory owner |
| [CSA72-P04: Long diagnostics run and post-reset controller recovery](#csa72-p04) | TC-DGGEN-2.1 | Product / laboratory owner |

## CSA72-Q01

**PASE header flags, lengths and PBKDF parameter meaning**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-SC-2.1 | 0 | SDK YAML Tests | MANUAL/FAIL | 472 | 472 |

**Recorded observation:** Run472 literal procedure disagrees with observed Core-compliant S/DSIZ addressing, byte lengths and hasPBKDFParameters meaning; success/commissioning was observed.

**Requested decision / input:** Confirm corrected initiator/responder S/DSIZ expectations, byte units and true/known-PBKDF interpretation for Core1.6.1.

**Rerun only after:** Accepted procedure/interpretation with explicit corrected fields; replay retained captures first, then repeat original manual procedure with fresh transcript only if needed.

Evidence: [csa37-validation.md](csa37-validation.md), [csa37-results.json](csa37-results.json).

## CSA72-Q02

**Bad MIC: discard message or destroy PASE session**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-SC-2.2 | 0 | SDK YAML Tests | MANUAL/FAIL | 473 | 473 |

**Recorded observation:** Run473 fails the step requiring session termination/key clearing after corrupted MIC. The message is rejected, replay state is not committed and the same live session recovers.

**Requested decision / input:** Does Core4.8.3 require session destruction here, or only dropping the failed AEAD message as recorded? Identify the normative source for mandatory key erasure if intended.

**Rerun only after:** Accepted session/error policy; repeat corrupt-MIC and same-session recovery plus original procedure. Do not infer key erasure from absence of traffic.

Evidence: [csa38-validation.md](csa38-validation.md), [csa38-results.json](csa38-results.json).

## CSA72-Q03

**MRP total sends versus retransmissions**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-SC-1.3 | 0 | SDK YAML Tests | MANUAL/FAIL | 477 | 477 |

**Recorded observation:** Run477 literal step expects MRP_MAX_TRANSMISSIONS-1 total messages. Actual loss trace has one initial send plus four retransmissions, with correct backoff and exhaustion.

**Requested decision / input:** Confirm whether the step means four retransmissions rather than four total sends under Core1.6.1.

**Rerun only after:** Accepted counting wording; first compare retained five-message trace, then original loss/late-ACK/recovery procedure without reducing native retransmissions.

Evidence: [csa42-validation.md](csa42-validation.md), [csa42-results.json](csa42-results.json).

## CSA72-Q04

**Last-fabric reset and CM advertisement**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-OPCREDS-3.6 | 0 | SDK YAML Tests | MANUAL/FAIL | 466 | 466 |

**Recorded observation:** Run466 observes successful RemoveFabric, operational withdrawal, explicit process restart, CM1/_CM and successful recommissioning; literal Step4 asks CM0 without _CM despite a commissioning heading.

**Requested decision / input:** Confirm expected CM/subtype after last-fabric reset when an on-network product opens a basic commissioning window, versus closed or enhanced-window policies.

**Rerun only after:** Accepted product-window procedure; rerun response/withdrawal/restart/discovery/recommission flow with genuine advertisements, retaining explicit CLI restart scope.

Evidence: [csa32-validation.md](csa32-validation.md), [csa32-results.json](csa32-results.json).

## CSA72-Q05

**Identical trusted root and fail-safe idempotence**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_CGEN_2_2 | 0 | SDK Python Tests | FAIL | 128 | 255 |

**Recorded observation:** CSA02 retains failure when the procedure expects an extra trust entry after installing identical committed root material under a new fail-safe.

**Requested decision / input:** Confirm expected TrustedRootCertificates count and rollback behavior for an identical existing root; should the procedure supply a distinct root when it expects growth?

**Rerun only after:** Accepted identity/count expectation; rerun identical-root idempotence, distinct-root candidate, fail-safe expiry and committed-fabric preservation without duplicate entries.

Evidence: [csa02-validation.md](csa02-validation.md), [csa02-results.json](csa02-results.json).

## CSA72-Q06

**RevokeCommissioning response on terminated PASE**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_CADMIN_1_10 | 0 | SDK Python Tests | FAIL | 157 | 333 |
| TC_OPCREDS_3_4 | 0 | SDK Python Tests | FAIL | 129 | 256 |

**Recorded observation:** CSA02/16 retain response timeouts expected by scripts after successful PASE revocation; Core11.19.8.3 says the caller must not expect a response on that terminated session.

**Requested decision / input:** Confirm PASE revocation completion criteria and accepted observation replacing an InvokeResponse on a terminated channel.

**Rerun only after:** Accepted procedure; rerun real window withdrawal/PASE retirement/fail-safe rollback and independent CASE survival, without broadening the separate ArmFailSafe reply exemption.

Evidence: [csa16-validation.md](csa16-validation.md), [csa16-results.json](csa16-results.json), [csa02-validation.md](csa02-validation.md).

## CSA72-Q07

**ProxyView in the current revision**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_ACL_2_4 | 0 | SDK Python Tests | FAIL | 130 | 287 |

**Recorded observation:** CSA06 original287 fails step16 because the test expects ProxyView2 to succeed; supplied Core1.6.1 marks it D/disallowed. Later steps remain unexecuted.

**Requested decision / input:** Which Access Control revision/enum conformance should this installed test enforce, and what approved test excludes or negatively validates ProxyView for Core1.6.1?

**Rerun only after:** Accepted revision/profile expectation; rerun original case through all later scenarios, preserving rejection unless a legitimate different revision is selected.

Evidence: [csa06-validation.md](csa06-validation.md), [csa06-results.json](csa06-results.json).

## CSA72-Q08

**Per-operation statuses in list writes**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_ACL_2_6 | 0 | SDK Python Tests | FAIL | 131 | 288 |
| TC_SU_4_1 | 0 | SDK Python Tests | FAIL | Not recorded in checkpoint | 456 |

**Recorded observation:** ACL288 and OTA456 fail first-status assertions on clear/append/append responses[0,0,135]; the invalid append is rejected. Diagnostic290 and independent CSA27 readbacks distinguish partial state and fabric isolation.

**Requested decision / input:** Confirm accepted SDK aggregation or test handling of the complete status vector, preserving successful operations, constraint rejection and post-write state checks.

**Rerun only after:** Accepted correction/guidance or verified client aggregation change; check all operation statuses and actual list/fabric state, then complete previously unreached original assertions.

Evidence: [csa06-validation.md](csa06-validation.md), [csa27-validation.md](csa27-validation.md), [csa71-validation.md](csa71-validation.md), [csa71-csa-question.md](csa71-csa-question.md).

## CSA72-Q09

**ScanNetworks and fail-safe prerequisite**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_CNET_4_4 | 0 | SDK Python Tests | FAIL | 166 | 330 |

**Recorded observation:** Connected-state fixture fixes the original setup problem, but run330 still calls ScanNetworks without arming fail-safe and gets FailsafeRequired.

**Requested decision / input:** Confirm the required fail-safe setup for this procedure versus its current command sequence.

**Rerun only after:** Accepted precondition or normative exception; rerun general/directed scan with proper fail-safe and retain the unarmed negative control. Do not remove the server guard.

Evidence: [csa14-validation.md](csa14-validation.md), [csa14-results.json](csa14-results.json).

## CSA72-Q10

**BLE precondition and full-network repeat arithmetic**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-CNET-4.13 | 0 | SDK YAML Tests | MANUAL/FAIL | 482 | 482 |

**Recorded observation:** Run482 fails compound BLE/explicit BLE prompts on the IP-only simulation and a loop that asks three further additions after one of three free slots is already consumed.

**Requested decision / input:** Clarify applicability of BLE steps for this profile and whether the repeat count must subtract the intervening successful addition.

**Rerun only after:** Accepted role/radio applicability and capacity arithmetic; supply genuine BLE if required, then rerun reorder/Breadcrumb/fill/rollback/commit with the real remaining capacity.

Evidence: [csa46-validation.md](csa46-validation.md), [csa46-results.json](csa46-results.json).

## CSA72-Q11

**Positive GroupKeyMap writes with zero group capacity**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-GRPKEY-2.1 | 0 | SDK YAML Tests | FAIL | 493 | 493 |

**Recorded observation:** Native list-admission defect is repaired in CSA55; run493 now gets actual clear Success/add ResourceExhausted89 for the declared zero Groups/Groupcast profile.

**Requested decision / input:** Is the positive-capacity procedure applicable when advertised group-map capacity is zero, and which accepted branch should exercise that profile?

**Rerun only after:** Accepted applicability/capacity procedure, or intentionally supported positive group capacity with consistent PICS/implementation. Rerun clear/add/status/readback; do not invent mappings.

Evidence: [csa55-validation.md](csa55-validation.md), [csa55-results.json](csa55-results.json).

## CSA72-Q12

**Overwrite versus new KeySetID at capacity**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-GRPKEY-2.2 | 0 | SDK YAML Tests | FAIL | 487 | 487 |

**Recorded observation:** Run487 reaches every step; Step22 asks for an unused ID but hardcodes3 after capacity fill already created3. Valid overwrite returns Success, not ResourceExhausted.

**Requested decision / input:** Confirm use of a genuinely unused ID for overflow and the distinct expected result for replacing an existing KeySetID under Core11.2.7.1.

**Rerun only after:** Accepted unused-ID selection; rerun fill, changed-epoch overwrite, actual new-ID overflow, readback and reset without rejecting valid overwrites.

Evidence: [csa50-validation.md](csa50-validation.md), [csa50-results.json](csa50-results.json).

## CSA72-Q13

**Phased PartsList hierarchy and full-suite closure gate**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-DESC-2.1 | 0 | SDK YAML Tests | MANUAL/FAIL | 480 | 480 |

**Recorded observation:** Run480 literal step requires every nonroot PartsList empty, while aggregate endpoint1 has phase children3/4/5 as in the supplied Device Library. A separate final all-clusters gate also remains unsatisfied.

**Requested decision / input:** Confirm accepted Descriptor procedure for a phased meter hierarchy under Device Library2.1.7/14.9.6; retain the independent complete-cluster acceptance requirement.

**Rerun only after:** Accepted hierarchy wording plus completed applicable cluster acceptance; rerun full Descriptor procedure. Metadata-only reads cannot satisfy the final behavior gate.

Evidence: [csa44-validation.md](csa44-validation.md), [csa44-results.json](csa44-results.json).

## CSA72-Q14

**Subscribe after all event paths are denied**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-IDM-6.2 | 0 | SDK YAML Tests | MANUAL/FAIL | 484 | 484 |

**Recorded observation:** Run484 examples expect UnsupportedAccess or empty ReportData; Core8.4.3.2 empty error-free event selection causes global InvalidAction and no subscription prime.

**Requested decision / input:** Confirm the global Subscribe error and absence/presence of ReportData for only-denied concrete paths and all-denied wildcards.

**Rerun only after:** Accepted selector/error expectation; rerun concrete/wildcard event Subscribe and valid subscription recovery without exposing foreign events.

Evidence: [csa49-validation.md](csa49-validation.md), [csa49-results.json](csa49-results.json).

## CSA72-Q15

**Resource exhaustion result after concurrent subscription load**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-IDM-7.1 | 0 | SDK YAML Tests | MANUAL/FAIL | 494 | 494 |

**Recorded observation:** CSA56 repairs host RX starvation; independent five-fabric/15-subscription checks pass. Original494 retains the final overflow-status mismatch against ResourceExhausted89.

**Requested decision / input:** Confirm the accepted overflow status and admission scope for a request exceeding the advertised subscription budget, without requiring termination of existing valid subscriptions.

**Rerun only after:** Accepted overflow procedure/status; rerun complete original load case plus bounded per-fabric admission, continued reports and memory acceptance on the repaired host.

Evidence: [csa56-validation.md](csa56-validation.md), [csa56-results.json](csa56-results.json).

## CSA72-Q16

**Optional Leave event with false PICS**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_BINFO_2_2 | 0 | SDK Python Tests | FAIL | 491 | 491 |

**Recorded observation:** Original491 fails by dereferencing absent Data.fabricIndex; CSA55 concrete read gets UnsupportedEventC7 with BINFO.S.E02=false and Leave absent from the catalog.

**Requested decision / input:** Should the optional Leave procedure be excluded or follow an error-status branch when E02 is false? Confirm approved behavior rather than dereferencing absent event data.

**Rerun only after:** Accepted PICS/applicability or corrected error handling; rerun actual remove/event procedure or explicit supported negative branch, without fabricating a Leave event.

Evidence: [csa53-validation.md](csa53-validation.md), [csa55-validation.md](csa55-validation.md), [csa55-results.json](csa55-results.json).

## CSA72-Q17

**Timed Write delay measured after real Success**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_IDM_5_2 | 0 | SDK Python Tests | FAIL | 603 | 603 |

**Recorded observation:** Original603 fails; diagnostic601 shows an MRP-retried TimedRequest and Write arriving1.56ms after actual Success, inside the700ms window despite busyWaitMs1400.

**Requested decision / input:** Confirm that the expiry test delay must start after receipt of successful TimedRequest status, including retries, rather than an earlier SDK scheduling boundary.

**Rerun only after:** Accepted SDK timing/fixture guaranteeing Write beyond actual Success plus timeout; retain kernel/send timing and actual callback/readback evidence, plus genuinely late and valid recovery controls.

Evidence: [csa59-validation.md](csa59-validation.md), [csa59-results.json](csa59-results.json).

## CSA72-Q18

**Optional ordinary BlockAck in receiver-drive BDX**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-BDX-2.3 | 0 | SDK YAML Tests | MANUAL/FAIL | 495 | 495 |

**Recorded observation:** Run495 retains one literal failure because the procedure asks for ordinary BlockAck. Actual recovered receiver-drive flow acknowledges via the next BlockQuery and completes signed OTA.

**Requested decision / input:** Confirm whether next-BlockQuery acknowledgment is accepted under Core11.22.6.2/.6 and whether the ordinary BlockAck prompt is conditional on negotiated mode.

**Rerun only after:** Accepted negotiated-mode interpretation; rerun original interruption/recovery with captured ACK/Query/EOF and exact image verification, keeping optional messages optional.

Evidence: [csa57-validation.md](csa57-validation.md), [csa57-results.json](csa57-results.json).

## CSA72-Q19

**Provider handoff race and QueryImage observation window**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_SU_2_2 | 0 | SDK Python Tests | FAIL | 607 | 607 |

**Recorded observation:** Original607 accepts UpdateAvailable from the old provider before handoff and fails in Downloading. Separate diagnostic608 injects loss and backoff; CSA67 repairs an independently reproduced resolver RX latch without reclassifying607.

**Requested decision / input:** Confirm provider-response/announcement ordering for each QueryImageResponse scenario and the observation window when legitimate failure backoff outlives the test wait.

**Rerun only after:** Verified provider generation/handoff and unambiguous responses before triggering the DUT, with a window covering permitted backoff. Then rerun original scenario; diagnostic loss and recovery passes do not substitute.

Evidence: [csa63-validation.md](csa63-validation.md), [csa63-results.json](csa63-results.json), [csa67-validation.md](csa67-validation.md).

## CSA72-Q20

**Historical progress replay and retained subscriptions**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_SU_2_5 | 0 | SDK Python Tests | FAIL | Not recorded in checkpoint | 450 |

**Recorded observation:** Original450 falsely completes download from null/0/1 replay; earlier449 hits a fourth subscription. Local corrected451 passes with budget3, but is not an accepted original PASS.

**Requested decision / input:** Confirm chronological FIFO progress observation, one deadline and scenario subscription cleanup, or identify an approved corrected test release.

**Rerun only after:** CSA-accepted correction or verified approved test/helper whose temporal/lifecycle behavior changes the prerequisite; first use existing offline controls, then full original accepted procedure.

Evidence: [csa68-validation.md](csa68-validation.md), [csa24b-validation.md](csa24b-validation.md), [csa68-csa-question.md](csa68-csa-question.md).

## CSA72-Q21

**Default-provider query before event callback registration**

Category: `CSA_TEST_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_SU_2_7 | 0 | SDK Python Tests | FAIL | 606 | 606 |

**Recorded observation:** Original606 repeats startup ordering: Querying occurs before step1 callback, whose first event is already Downloading. A later independent subscription reads the retained Querying event.

**Requested decision / input:** Confirm callback/history priming or a deterministic startup/announcement ordering that observes the required first transition without disabling legitimate automatic provider queries.

**Rerun only after:** Accepted observation setup reaching actual first Querying event; then rerun original and later Applying/reboot boundaries. CSA62 event-drain repair alone does not fix the earlier callback prerequisite.

Evidence: [csa61-validation.md](csa61-validation.md), [csa61-results.json](csa61-results.json), [csa62-validation.md](csa62-validation.md).

## CSA72-Q22

**Limited OTA client: timed interaction and peer IP-change procedures**

Category: `CSA_APPLICABILITY_QUESTION`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-IDM-5.1 | 0 | SDK YAML Tests | MANUAL/BLOCKED | Not recorded in checkpoint | See linked receipt; no executed result for this prerequisite |
| TC-SC-4.4 | 0 | SDK YAML Tests | MANUAL/BLOCKED | Not recorded in checkpoint | See linked receipt; no executed result for this prerequisite |

**Recorded observation:** Both manual positions remain blocked: no genuine timed-client Invoke trigger, and no controlled peer-IP-change run with a supported DUT-originated request. VendorID-read client PICS is false.

**Requested decision / input:** Confirm applicability of these procedures to a limited untimed OTA Invoke client and accepted supported-operation substitutions or exclusions.

**Rerun only after:** Accepted role/PICS decision; if applicable provide a genuine DUT client trigger and isolated peer-IP-change fixture. No chip-tool request may masquerade as DUT-originated traffic.

Evidence: [csa47-validation.md](csa47-validation.md), [csa47-results.json](csa47-results.json).

## CSA72-P01

**Assigned identity, manufacturer extension and default-value warnings**

Category: `PROVISIONING_PREREQUISITE`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_DA_1_2 | 0 | SDK Python Tests | FAIL | 171 | 171 |
| TC_IDM_10_1 | 0 | SDK Python Tests | FAIL | 219 | 219 |
| TC_IDM_13_1 | 0 | SDK Python Tests | FAIL | 206 | 206 |

**Recorded observation:** DA171 stops on CD VID0xFFF1. IDM219 reports manufacturer cluster0xFFF10000 with bad prefix0xFFF1. IDM206 default warning reports BasicInformation VendorID65521. These are deliberate development inputs, not established signature failures.

**Requested decision / input:** Owner supplies an authorized identity plan or seeks explicit accepted development-profile guidance. Confirm VID/PID/CD/DAC relationships and manufacturer-specific cluster namespace; do not borrow another vendor identity or suppress warnings.

**Rerun only after:** Authorized consistent VID/PID and signed test/production CD as appropriate; configure host identity and manufacturer extension consistently, retain trust checks, then rerun all three original cases. Test CD type0 is allowed at certification testing; different DAC origin IDs need separate constructor review.

Evidence: [csa69-validation.md](csa69-validation.md), [csa69-results.json](csa69-results.json), [csa53-validation.md](csa53-validation.md).

## CSA72-P02

**Controller Wi-Fi migration between two real APs**

Category: `PHYSICAL_LAB_PREREQUISITE`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC_CNET_4_11 | 0 | SDK Python Tests | FAIL | 168 | 168 |

**Recorded observation:** Earlier168 FAIL remains. CSA15 preflight found no TH wireless interface/wpa_supplicant; the procedure changes controller routes, AP association and IP. DUT AP records are simulation only.

**Requested decision / input:** Lab owner supplies a dedicated Wi-Fi-capable controller with two controlled APs and recovery access independent of the tested route.

**Rerun only after:** Real interface, supplicant and AP credentials ready in a separate bench; confirm route/recovery plan, then run original migration/rediscovery. Do not alter shared VM/SSH networking or apply an in-test BLE flag blindly.

Evidence: [csa15-validation.md](csa15-validation.md), [csa15-results.json](csa15-results.json).

## CSA72-P03

**Final QR/manual-code presentation evidence**

Category: `PHYSICAL_PRESENTATION_PREREQUISITE`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-DD-1.6 | 0 | SDK YAML Tests | MANUAL/BLOCKED | Not recorded in checkpoint | See linked receipt; no executed result for this prerequisite |
| TC-DD-1.7 | 0 | SDK YAML Tests | MANUAL/BLOCKED | Not recorded in checkpoint | See linked receipt; no executed result for this prerequisite |

**Recorded observation:** Software payload scans exist, but final QR label/presentation measurements and manual-code typography/grouping artifacts are absent.

**Requested decision / input:** Product owner supplies final approved label/card or permitted final presentation and measurement/scan evidence; clarify presentation alternative with CSA if needed.

**Rerun only after:** Final artifact, payload binding, measured modules/ECC/version/scan and font/grouping evidence available; then original manual acceptance. Generated digits/bitmap alone are not physical presentation PASS.

Evidence: [csa47-validation.md](csa47-validation.md), [csa47-results.json](csa47-results.json), [csa31-validation.md](csa31-validation.md).

## CSA72-P04

**Long diagnostics run and post-reset controller recovery**

Category: `DEFERRED_INFRASTRUCTURE_PREREQUISITE`. Decision state: **pending**.

| Exact case | Endpoint | Collection | Retained state | Campaign run | Selected reference runs |
| --- | --- | --- | --- | --- | --- |
| TC-DGGEN-2.1 | 0 | SDK YAML Tests | BLOCKED | 135 | 463, 464 |

**Recorded observation:** CSA30 original463/464 ended ERROR on controller WebSocket keepalive. Run464 completed the first2h05 wait and hours0-to2 assertion, then failed commissioning after factory reset; the later1h05 part remains unexecuted.

**Requested decision / input:** Lab owner schedules a stable controller/reset path and a full-duration window. Exact controller stall remains unproven; preserve both errors and partial observations.

**Rerun only after:** Resolve the post-reset controller prerequisite with bounded relevant evidence, then obtain explicit owner scheduling before the unshortened multi-hour original run. Owner-deferred long run is not started by this package.

Evidence: [csa30-validation.md](csa30-validation.md), [csa30-results.json](csa30-results.json).

## Common acceptance and rerun rules

1. Keep every current original FAIL/ERROR and unexecuted portion until an actual superseding accepted execution exists. Manual review and local-corrected results are not automatic PASS or certification.
2. For a CSA question, record the accepted interpretation, corrected official test/helper version or verified relevant SDK aggregation behavior before repeating. Unchanged prerequisites, an unrelated rebuild or old independent PASS alone do not justify a long repeat.
3. For an owner/laboratory prerequisite, supply the actual authorized identity, physical artifact, radio/network bench or DUT-originated trigger. Do not substitute simulated physical work, a borrowed VID, SDK-only flag or a controller request pretending to originate at DUT.
4. Freeze exact case/endpoint/collection, binary/source/test/helper/PICS fingerprints and isolated stores. If capabilities genuinely change, review a new coherent profile; do not hide a failure through ad-hoc PICS edits.
5. On an attributed native change, reproduce the real defect, make the smallest shared repair, rerun the original accepted procedure and complete relevant full Linux Memcheck followed by separate ASan/UBSan/LSan and error/recovery checks. Reuse proven binaries only with verified identity and explicit coverage limits for tester-only work.
6. Use a bounded first-error/packet/state capture and retain run/process identity. Do not submit duplicates while RUNNING, accelerate required timeouts, discard setup attempts or interrupt shared VM/SSH interfaces.
7. Keep the owner-deferred multi-hour TC-DGGEN-2.1 unscheduled until its controller/reset prerequisite and explicit owner execution window are supplied. Short diagnostic evidence cannot become its original full PASS.
8. After the changed prerequisite is verified, run the complete selected original procedure including previously unreached steps and real state readback. Then update one explicit classification delta, retain prior evidence and commit locally. Schedule the final stable applicable-matrix rerun after relevant repairs/gates are resolved.

## Next action

Owner reviews/prioritizes this unsent package. Send or upload only after explicit authorization and selection of recipient/material. Until a gate changes, continue only independent work that adds coverage; do not restart already-attributed original failures. No automatic sending or long-run scheduling is configured.

Generated from [csa72-questions.json](csa72-questions.json) by `python tools/matter/csa_review_packet.py --write`. Local rendering does not submit anything.
