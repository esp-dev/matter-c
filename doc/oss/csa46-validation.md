# CSA46: diagnostic events, network reorder and group-key policy

Original manual **TH run482**: **TC-DGGEN-2.2, TC-DGWIFI-2.2 and TC-GRPKEY-5.4 PASS**;
**TC-CNET-4.13 FAIL**. The 39 procedure prompts and four evidence uploads complete
with unchanged sources/support/PICS. See [receipts](csa46-results.json) and the
[continuing queue](csa-campaign-status.md).

The existing diagnostics driver gains opt-in `--csa-profile`; its default mode
remains available. Real CASE reads on the simulated Node observe BootReason 1
matching the attribute, with event numbers 1 initially, 33 after process restart
with retained commissioning, and 1 after deliberate factory reset/recommission.
The process lifetime is the simulated Node lifetime; no hardware reboot is claimed.
DGGEN hardware/radio/network fault events are NOT APPLICABLE from false PICS.
All three optional DGWIFI event PICS are also false: that case's PASS means a
verified commissioning precondition and three NOT APPLICABLE steps, not Wi-Fi
radio/event payload coverage. These PICS values were reread from the TH project.

KeySetWrite supplies valid fixed public test epoch keys and CacheAndSync policy1.
FeatureMap 0 advertises no CacheAndSync; the actual command returns InvalidCommand
0x85. KeySetRead of the rejected ID returns NotFound0x8b. Positive CacheAndSync
steps are NOT APPLICABLE. This verifies rejection and no created key set, without
exposing production keys or adding unsupported group-message capability.

Functional Wi-Fi checks read root Descriptor/FeatureMap 1 and MaxNetworks 4, commit
a primary simulated network, arm/rearm the fail-safe, fill the actual free slots,
and test out-of-range index1-status and absent-ID3-status without changing
Breadcrumb1 or list order. Moving the primary to midpoint2 succeeds and changes
Breadcrumb to2. ArmFailSafe0 restores the one-entry baseline. A second full-list
transaction survives CommissioningComplete followed by ArmFailSafe0 with the
committed primary at index2. Transport is real IPv6/CASE; Wi-Fi association is
simulated and does not alter the host OS network.

The original CNET procedure retains three failed prompts: compound BLE
precondition, explicit BLE commissioning, and inconsistent repeat arithmetic.
After counting3 initially free slots it separately adds one network, then asks
for3 further unique additions although only2 slots remain. The fixture fills the
actual remaining2 and verifies capacity4; it does not claim the literal3-addition
loop was performed. Remaining functional observations pass. Clarify these
procedure/prerequisite issues before attributing a native defect or claiming a
full radio commissioning acceptance.

Two early tester attempts are retained as setup errors, not DUT failures. Actual
command fields use `errorCode` and `networkingStatus`. A fresh CASE handshake can
flush an ACK before the subsequent Read report: completion now requires a real
ReportData/InvokeResponse followed by its ACK flush, so parsing cannot stop at
Sigma traffic. The previously missing BootReason33 was present on the wire.

Final runs pass **50 Memcheck checks and 47 separate sanitizer checks**, each over
three boots. Three Memcheck allocations/frees:24,507;11,216;23,939. Every boot
has zero live bytes/errors; all sanitizer stderr is empty. Existing
`test_diagnostics`/`test_groupkey` pass 2/2 per build; no incremental-build warnings
observed. All 362 native inputs and both host binaries match CSA35. No new host
compilation, native/API/PICS change, full matrix, physical/Home UI or embedded RAM
acceptance. TH idle, disposable nodes stopped and desktop pairings untouched.

Executed the driver with `--csa-profile --valgrind`, separately the sanitizer
binary, focused CMake/CTest, source/PICS identity, campaign/inventory/link/privacy
checks and `git diff --check`. This is original manual/operator acceptance,
not fully automatic CSA or certification.

Counts stay 97 PASS/18 FAIL/3 BLOCKED/39 MANUAL/705 NA. MANUAL: **20 PASS,
9 FAIL,10 without outcome**. Next: **CSA47**, payload/label and limited-client
applicability/prerequisite review, then remaining IM server and BLOCKED cases.
