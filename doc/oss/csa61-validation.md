# CSA61: OTA event startup order; original FAIL retained

Original **TC_SU_2_7 run606 FAIL**, step1, with unchanged Python test, shared
support and PICS. This reproduces the default-provider/subscription ordering
already described in [CSA26](csa26-validation.md), rather than a new native defect.
The new [CSA60](csa60-validation.md) local query trigger cannot undo an update
that the test's setup has already started. No further original rerun is useful
until this fixture precondition is resolved.

## What the original actually observes

The setup writes DefaultOTAProviders before the step1 event subscription. Native
logs show selection `source=default reason=0`, Querying and an actual QueryImage
before the later reason1 announcement. The local query action returns BUSY while
that job is active. The first event returned by the test's live callback is
**Querying -> Downloading**, with target version2. Its assertion expects previous
Idle and fails immediately (`2 != 1`). Original steps2 through6 do not execute.
Teardown stops the provider; a subsequent1024-byte download failure is therefore
cleanup fallout, not the cause of this original assertion failure.

Inspected the SDK checkout source of `EventSubscriptionHandler.start`: it awaits ReadEvent's
initial subscription report, then installs SetEventUpdateCallback. It does not
enqueue initial cached events into its later wait queue. This explains how an
earlier Querying event can be present on the node yet absent from this callback's
queue. That is distinct from proving that a generated event was lost on the wire.
The helper fingerprint and original receipt are in [results](csa61-results.json).
Neither helper nor original assertions were patched. The installed container package
was not independently byte-compared with this checkout; callback attribution is
therefore a source-based explanation, supported by the independent wire control.

Core1.6.1 sections11.20.3.1/11.20.3.2 describe default-provider configuration and
normal query opportunities; section11.20.7.7 requires state-change events. No
normative rule was identified requiring a requestor to wait for a future test
subscription before its first legitimate query. Seek a fixture/test clarification
that establishes observation before starting the query, or evaluates initial
events. No report has yet been sent to CSA. Existing TH sdk_container.py lab
modification from CSA58 remains; this is not a pristine-harness claim.

## Independent late-subscription control

A private diagnostic permutation of the existing independent OTA runner moves
its event subscription after DefaultOTAProviders and waits for the actual native
QueryImage start. The unmodified CHIP provider ignores the response. An urgent
subscription must receive the earlier Idle -> Querying event; after the actual
query failure, Querying -> Idle must carry Failure and null target version. A
fresh CASE peer reads retained history and verifies version1/PowerOn, without
download, install or reboot. This diagnostic permutation changes only observer
order; it does not modify the native runtime or original CSA test.

Both variants **PASS14 checks**. The late subscription's own decoded client
log contains Idle -> Querying and Querying -> Idle/Failure; the separate fresh
reader also sees both. Memcheck has37906 allocations/frees, zero errors and zero
live blocks. Separate ASan/UBSan/LSan has empty native stderr and normal exit.
Full results and log fingerprints are recorded in the receipt. The raw diagnostic
driver, original receipts and captures stay ignored/private, with fingerprints
for audit. Its sequence remains separate from original CSA acceptance. CSA60's
full two-boot signed-update checks and eight focused CTests per variant are
reused only after source/binary identity verification; no new build is claimed.

The earlier **instant-reboot Applying capture gap remains open**. This original
run fails before Applying, and the late-query control does not cover that gap.
The different delayed-apply scenario that passed in CSA60 is not a replacement.
Also, the prepared optional reboot/restore operator branches were not reached by
this original run and have not been accepted as tested lifecycle behavior.

## Scope and resumption

Only receipts, the campaign queue and this analysis change. Public C/H inputs,
wire behavior and policies remain identical to CSA60. Counts stay122 PASS/28
FAIL/5 prerequisites. No original test/PICS weakening, physical-device run,
Windows rebuild, full applicable rerun or certification is claimed. Existing
paired Windows nodes/stores remain unchanged. TH and stage-process cleanup are
recorded in the receipt.

```text
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

Next: **CSA62**, attribute Applying generation versus reliable report delivery
at the simulated reboot boundary, using the already observed instant-apply
failure. Preserve original startup-order FAIL; do not repeat it without a changed
prerequisite or change correct polling policy solely to satisfy test order.
