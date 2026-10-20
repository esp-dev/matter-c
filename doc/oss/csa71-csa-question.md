# Draft: TC_SU_4_1 handling of per-operation list-write statuses

Prepared for review only; not sent. No CSA acceptance or approved test correction
is claimed. The original automatic result remains FAIL456.

## Question

In Matter Core R1.6.1 and TH v2.15.1+summer2026, the original Python TC_SU_4_1
step5 writes two DefaultOTAProviders entries on the same fabric. The observed
SDK return contains ordered per-operation statuses:

```text
clear list        Success
append provider4  Success
append provider1  ConstraintError (0x87)
```

All three statuses refer to endpoint0, cluster0x002A, attribute0x0000. Original
line310 checks `resp[0].Status == Status.ConstraintError`, so it fails on the
clear's Success before checking the expected partial-state readback. The later
assertions expect provider4 to remain and the other fabric to remain unaffected.

Please confirm whether the accepted correction should be in the case's handling
of the complete operation vector or in a defined SDK logical-list-write status
aggregation API. Which approved test/helper version or guidance should be used?
The on-wire per-operation statuses and original state/fabric checks must remain
intact; checking an arbitrary last status or any error is insufficient by itself.

## Normative basis and interpretation to confirm

Core11.20.7.5 requires ConstraintError when adding a second provider on one fabric.
Core10.6.4.3.1 describes this list-write encoding and permits partial changes on
failure. Core8.7.3.3 and8.7.3.4 process fields in order and include each generated
AttributeStatusIB in WriteResponses. Our interpretation is that the successful
clear and first append must not be replaced by errors or discarded simply to
put ConstraintError in the first Python result.

## Evidence

Original456 failed step5; steps6..8 and subsequent step5 readbacks were not reached.
The exact original log retains the complete[0,0,135] response. Independent CSA27
laboratory checks verified the partial state, other-fabric isolation, clear,
announcement behavior and restart. Their memory and parser results are historical
local evidence, not original automatic PASS or current-build acceptance.

| Evidence | SHA-256 |
| --- | --- |
| TC_SU_4_1.py | 644dde23f969393db842b84190978144a9279b02fa17e3d1e5ba4e0514811061 |
| TC_SUTestBase.py | 9e9b2af9fcca6b039da12273b89560bd55121ec11fdb72de0f4973499318615b |
| Original456 log | 2d4dc41481e87c0e43658777629513a96fbc4e137fdb145d02341d8a62c34f24 |
| Original456 result | 859247522b2cd69d977be698ed06d8a2aa86191bedf7c41a4b0d9bc8933ef6b3 |

CSA71 read-only checks reconfirm these installed source and archived result/log
hashes. No full repeat, installed patch, local-corrected test run or native
protocol workaround was performed. No credentials, certificates, private network
identifiers or paired-node stores are attached.

See [CSA27 evidence](csa27-validation.md), [CSA71 review](csa71-validation.md) and
[receipt](csa71-results.json). On accepted guidance/correction, the complete
original procedure and previously unreached assertions still need execution.
