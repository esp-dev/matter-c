# CSA55: GroupKeyMap status and optional Leave attribution

A further **native defect is repaired**, while original **TC-GRPKEY-2.1 remains FAIL, run493:6 PASS/2 FAIL**. It now reports ResourceExhausted89 instead of InvalidAction80. [Evidence, baseline and commands](csa55-results.json).

Generic IM Write only allowed nonempty full/fabric-list operations for ACL and OTA Providers. A valid GroupKeyMap write was rejected before the cluster validator, which knows the actual zero-group capacity. The minimal extension admits GroupKeyManagement.attribute0 to the existing bounded path. Its provider accepts clear and rejects add with ResourceExhausted; no group capacity or functionality is added. Fabric, permissions, schema, version, response preflight and ordinary-list restrictions remain.

Independent full actual-controller baseline on CSA52 has one intended failure after the keyset restart/reset flow. Raw WriteResponse contains two AttributeStatusIBs[80,80]. Final normal/sanitizer responses contain[00,89] and a subsequent read confirms empty map. This corrects CSA53's earlier word global: the status was per-attribute, not global StatusResponse. Historical receipt remains unchanged.

A concrete optional Leave read returns EventStatusIB UnsupportedEventc7 in all variants. With BINFO.S.E02=false and Leave absent from the catalog, this is a supported error response rather than Leave data. The original BINFO script's NoneType.fabricIndex exception is therefore a result-handling/applicability question; run491's FAIL remains. No additional original BINFO acceptance is claimed.

Existing real CASE/IPv6 regression now checks nonempty REPLACE capacity denial and unauthorized REPLACE, plus existing clear/ADD and literal encrypted response lifecycle. Full independent fixture still checks keyset fill, epoch overwrite at capacity, genuine overflow, redacted keys, persistent restart and fresh-controller reset. It adds actual per-attribute map status and optional-event status assertions:53 checks PASS in each final variant.

Three final Memcheck boots:59,040 allocations/frees, zero errors/live bytes. Three separate ASan/UBSan/LSan boots exit0 with empty stderr. Baseline's three boots also exit0 with clean Memcheck despite its expected conformance failure. Five CTests per build pass, including IM Write allocation failures and ACL; no compiler warnings observed. New Linux hosts compiled; source hashes and original test/support/PICS verified.

Changed files: IM Write admission, existing CASE GroupKey regression, existing independent lifecycle fixture, its inventory entry and campaign reports. No API/quota/timer changes. Original positive-capacity GroupKey test still expects success for a profile declaring zero Groups/Groupcast capacity; seek CSA clarification, do not fabricate capacity. No Windows/Home UI, physical/production provisioning, embedded RAM fit or full matrix rerun. Disposable nodes stopped, temporary PAA removed, TH idle and paired Windows nodes untouched. No push.

Counts unchanged:99 automatic PASS/18 FAIL/1 BLOCKED; manual24 PASS/9 FAIL/4 BLOCKED;707 NA. Applicable total:123 PASS/27 FAIL/5 prerequisites. Next:CSA56, review remaining BDX recovery and load-dependent subscription state before further bounded reproduction.
