# CSA44: Descriptor profile and endpoint hierarchy

Original manual **TC-DESC-2.1 FAIL**, TH **run480**: seven steps PASS,
two FAIL and root TagList NOT APPLICABLE. Sources, support and PICS unchanged.
See [receipts](csa44-results.json) and [continuing queue](csa-campaign-status.md).

The two failures have separate causes. Step1b literally requires every nonroot
PartsList to be empty. Our aggregate endpoint1 contains phases3/4/5; this is the
phased meter hierarchy allowed by Device Library1.6.1 sections2.1.7/14.9.6, and
leaf lists are empty. Preserve the original failure for CSA clarification.
The last step requires all applicable cluster behavior tests to be complete.
The campaign still has failures, unexecuted and blocked procedures, so that
closure gate cannot honestly pass from Descriptor metadata alone.

Independent CASE reads pass **117 checks per variant**. The actual five-endpoint
inventory verifies DeviceTypeList/revisions, recursive PartsList, ServerList,
ClientList, FeatureMap, child AC/phase tags and AttributeLists from all 28 listed
server instances. Root types are RootNode rev5 and OTARequestor rev1; aggregate
measurement types are ElectricalSensor/ElectricalUtilityMeter/MeterReferencePoint
rev1. Root advertises the OTAProvider client; measurement clients are empty.
Root TagList is absent with feature0 and frozen PICS false; child TagLists are
actually read. Core9.5.4.1/9.5.6 and supplied Device Library1.6.1 are the basis.
Cluster presence/catalogs do not prove all commands/attributes behave correctly.

The external recorder adds `--descriptor-profile`. Wait for the report ACK flush
before parsing complete chip-tool TOO output; enum display suffixes are allowed.
For the vendor cluster, chip-tool lacks a named schema, so parse its actual DMG
TLV unsigned array, requiring a single complete array and unique bounded IDs.
No expected-value substitution is used. Earlier parser attempts are retained in
the JSON. Manual run479 was cancelled when the converter presented a PICS-false
TagList step; completed run480 explicitly answers NOT APPLICABLE using the
original supported option. It does not treat that step as a native failure.

Memcheck: **44,053 allocations and frees**, zero errors/live bytes. Separate
ASan/UBSan/LSan run exits0 with empty stderr. Existing `test_root`/`test_runtime`
pass 2/2 per build; incremental target builds report no warnings. All 362 native
inputs and both host binaries match CSA35; no new host compilation or native,
API or PICS change. Disposable nodes stopped, TH idle, paired desktop untouched.

Executed the recorder with `--descriptor-profile --valgrind`, separately the
sanitizer binary, focused CMake/CTest, campaign validation, test-map check and
`git diff --check`. No full-matrix, physical/radio/Home UI or embedded RAM test.
This is original manual/operator acceptance evidence, not certification.

Counts stay97 PASS/18 FAIL/3 BLOCKED/39 MANUAL/705 NA. MANUAL: **14 PASS,
7 FAIL,18 without outcome**. Next: **CSA45**, related BDX receiver procedures
using actual OTA provider traces and explicit negotiated-mode limits.
