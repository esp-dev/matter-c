# CSA48: five-fabric subscription resources

Original manual **TC-IDM-7.1 FAIL, TH run483**, nine exact prompts and one evidence upload. Source, support code and frozen PICS are unchanged. [Machine-readable evidence](csa48-results.json) retains the complete original outcome and all independent attempts.

Five real commissioned fabrics each retain three distinct subscriptions, each primed with three requested paths. All15 receive both updates in the baseline; one four-path request also succeeds. Excess requests return ResourceExhausted89, sometimes Busy9c while an earlier overflow drains; neither is counted as admitted. Three subscriptions share one CASE session per fabric. No native budget was enlarged.

Under Memcheck, burst-after-overflow misses the second IdentifyTime change while new NodeLabel and Location reach all15. This persists with actual InvokeResponse/ACK completion checks. The separate faster ASan/UBSan/LSan run passes all four phases (399 checks). Memcheck's second actor times out in CASE; sanitizer authenticates node2 in RD1's fabric, proved by ACL event AdminNodeID2, rejects its extra subscription89 and preserves existing15. These differences remain open for load/timing attribution. No speculative native fix was made.

The original final example expects INVALID_ACTION80 for RD1A, whereas the actual bounded-capacity response is RESOURCE_EXHAUSTED89. That literal discrepancy and the load-dependent failures are retained in the original FAIL. Compare Core2.11.2.2 admission guarantees before changing a status solely to match an example.

Seven Memcheck process lifetimes have equal allocations/frees and zero live bytes/errors, including failed attempts. Sanitizer stderr is empty in all four final phases. Existing test_im_subscribe/test_runtime pass2/2 per variant; no incremental warnings. All362 native source inputs and reused CSA35 host binaries remain unchanged. No new host compilation or public API/PICS change.

Tester setup failures are explicit: Status capitalization, valid Busy during overflow drain and overly broad Status00 command matching. Raw prime paths of all15 baseline subscriptions were rechecked. Private controller state/logs remain ignored; paired Windows nodes untouched. This is manual/operator acceptance, not automatic CSA, physical-device, embedded-RAM or certification evidence.

Campaign:97 PASS/18 FAIL/3 BLOCKED/37 MANUAL/707 NA. Manual:20 PASS,10 FAIL,4 BLOCKED,3 not run. Next:CSA49, remaining event and fabric-sensitive Read/Subscribe coverage; then earlier blocked cases and the attributed native-repair pass.
