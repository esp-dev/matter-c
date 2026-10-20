# CSA71: reuse the TC_SU_4_1 status-vector attribution

**Original TC_SU_4_1 remains FAIL456, step5.** The installed script/helper and
archived result/log are byte-identical to CSA27. This step adds a precise triage
entry and [CSA question draft](csa71-csa-question.md), without another full test,
network scenario or offline regression. [Receipt](csa71-results.json) records
fresh checks, historical evidence and the rerun gate.

## Confirmed evidence

| Item | SHA-256 |
| --- | --- |
| Installed TC_SU_4_1.py | 644dde23f969393db842b84190978144a9279b02fa17e3d1e5ba4e0514811061 |
| Installed TC_SUTestBase.py | 9e9b2af9fcca6b039da12273b89560bd55121ec11fdb72de0f4973499318615b |
| Original456 result | 859247522b2cd69d977be698ed06d8a2aa86191bedf7c41a4b0d9bc8933ef6b3 |
| Original456 log | 2d4dc41481e87c0e43658777629513a96fbc4e137fdb145d02341d8a62c34f24 |

These hashes were read again from TH and compared with the CSA27 receipt and
local archive. Windows source copies have CRLF; their LF-normalized bytes match
the exact fresh Linux source hashes. Result/log comparisons use exact bytes.

In the archived step5 response, the three operations for endpoint0,
cluster0x002A, attribute0x0000 return:

| Operation | Status |
| --- | --- |
| Clear list | Success0 |
| Append provider4 | Success0 |
| Append provider1 on the same fabric | ConstraintError135 |

The original line310 checks `resp[0].Status` against ConstraintError, so it
fails on the successful clear. It never reaches its subsequent readback requiring
provider4 to remain, nor steps6..8. Run456 records7 passed entries including
harness bookkeeping,1 failed and3 pending. No current-host wire execution or
downstream original acceptance is inferred from that history.

## Why no native workaround or repeat

The supplied Core R1.6.1 clauses already reviewed in CSA27 remain decisive:

- 11.20.7.5 limits DefaultOTAProviders to one entry per fabric.
- 10.6.4.3.1 describes the list-clear/ordered-add encoding for this write and
  warns that a failed list write need not leave its old contents unchanged.
- 8.7.3.3 processes conveyed fields in order and generates their statuses;
  8.7.3.4 includes each generated AttributeStatusIB in the response.

Returning only the error, moving it before successful operations or changing a
successful clear to ConstraintError would misrepresent the executed operations.
The appropriate tester/client handling needs CSA agreement. Merely changing to
an arbitrary last status or accepting any error would also weaken checks if it
ignored unexpected earlier failures or the resulting list state.

Current `matter_ota_requestor.c` is unchanged from the CSA27 source base. The
shared `matter_im_write.c` has since changed its list-admission guard to add
GroupKeyMap0x3F; comparison shows existing OTA0x2A admission and the ordered
result/response loops unchanged. Static review does not substitute for a new
end-to-end run; it supplies no new native regression that would justify one.

The existing CSA27 independent two-fabric/readback/restart scenario already
checks the full[0,0,135] vector, partial list state and fabric isolation. Its
29 Memcheck/27 sanitizer checks,34 capture rechecks and8 rejected parser controls
are historical results only. The public driver still has the same bytes; neither
it nor the memory scenarios were executed again here.

The SDK source directory is not an independent Git checkout. `git rev-parse`
there finds the parent TH backend repository, so its HEAD is not reported as
the SDK revision. Matching the two script hashes does not establish identity
of a compiled Python controller binding. No such binding identity claim is made.

## Rerun gate and disposition

The draft asks CSA/test maintainers to confirm how the case or SDK should handle
per-operation statuses while preserving complete status, partial-state and
cross-fabric checks. It has not been sent or approved. A full rerun is justified
when an accepted correction/guidance changes that prerequisite, a verified SDK
aggregation change can affect it, or a relevant native regression is demonstrated.
Then verify the previously unreached readbacks and steps6..8 as well.

The campaign now links this attribution instead of generic fixture review.
Original FAIL456 remains; counts stay **123 PASS/27 FAIL/5 prerequisites**.
No local-corrected PASS, new build/CTest, Memcheck/sanitizer, physical firmware
or certification is claimed. TH was observed idle; no test/helper/PICS, service,
paired-node state or runtime resource was changed.

Executed public evidence checks:

```sh
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
python tools/matter/check_test_map.py
git diff --check
```

Next: **CSA72**, consolidate the existing clarification package locally, grouping
test/spec questions, provisioning and physical/manual prerequisites, with one
requested decision and exact rerun gate for every remaining FAIL. Do not send
messages or repeat unchanged long failures as part of preparing the package.
