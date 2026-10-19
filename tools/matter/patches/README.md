# Local Test Harness corrections

These are explicit laboratory corrections, not CSA-approved test releases.
Never substitute their results for the unmodified campaign's FAIL/PASS records.
The full Harness distribution, specification PDFs, credentials and live state
remain outside this repository.

## TC_SU_2_5-progress-order.patch

Target: installed SDK Python `TC_SU_2_5.py`, original SHA-256
`91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`.
The source retains `Copyright (c) 2025 Project CHIP Authors`, licensed under
Apache-2.0; see the root LICENSE and NOTICE. This patch modifies that source.
Expected reporting helper SHA-256:
`038e99c144a66640375d483ae9e5a8fc5fbf6421d3b44129f6b1a5f7551be322`.
The helper itself is unchanged. Patched test SHA-256:
`cb0e16c451093f51e153bd9d56c8d780bc8f1b7ceeaf06b94bad9136b929b588`.

The original stateful progress predicate is evaluated against the entire report
history repeatedly. For `null, 0, 1` it sees the positive value, then accepts the
earlier null on its next scan. The patch calls the existing `wait_next_report()`
FIFO helper, so the predicate sees every received report exactly once. A single
monotonic deadline bounds the whole wait, including repeated reports.

The patch also cancels the old state subscription after scenarios 3 and 4. The
first subscription of each scenario uses KeepSubscriptions=false to replace any
remaining publisher-side subscriptions from that controller. Its second
subscription retains the first. In scenario 3 SoftwareVersion starts first;
in scenarios 4 and 5 UpdateState starts first. This order matters: cancelling
the first subscription when opening the second would weaken the version check.
The intended simultaneous subscription set is two, within the Core minimum.

All original assertions and the original progress predicate are retained. In
particular, the provider must report Discontinue and exactly one Apply request;
the image must be removed, state Idle, progress null and software version unchanged.
No provider IPC response, timing result, device report or PASS is fabricated.

Apply only to the pinned source in an idle, isolated TH environment. Preserve
an exact backup and restore it after the local test. From the SDK script directory:

```sh
sha256sum TC_SU_2_5.py
cp -p TC_SU_2_5.py /path/to/local-backup/TC_SU_2_5.original.py
patch --dry-run --fuzz=0 -p1 -i /path/to/matter-c/tools/matter/patches/TC_SU_2_5-progress-order.patch
patch --fuzz=0 -p1 -i /path/to/matter-c/tools/matter/patches/TC_SU_2_5-progress-order.patch
```

Do not loosen directory permissions or grant permanent passwordless sudo for this
test. If administrator rights are needed, an operator can apply the reviewed
patch to that one file. The laboratory launcher records original/patched hashes
and arms automatic restoration before running the case.

Offline regression (no SDK imports, devices, network or credentials):

```sh
python tools/matter/tests/test_csa24_progress.py \
  --test-source /path/to/TC_SU_2_5.py \
  --helper-source /path/to/event_attribute_reporting.py \
  --original-source /path/to/local-backup/TC_SU_2_5.original.py
```

It executes the actual test block and helper methods via AST with deterministic
queue/clock adapters. Negative sequences must time out; valid positive-progress
then null sequences must complete. Checks also preserve every original assertion
and the original predicate, and verify that each scenario retains its second
subscription. The original source fails the two replay controls and the scenario
subscription-lifecycle control; the patched source passes all eleven checks.
These source regressions are not official CSA acceptance.

## BdxOtaSender-idle-stall.patch

This is a **fault-injection provider**, not a Test Harness correction. It changes
only a separately built laboratory peer. The C requestor, its timers and the
official TC-SU-2.7/TC_SU_2_7 sources are not patched by it.

Target: Project CHIP SDK commit `3bcdd56ba54fb88b2afb4bfef575014671df7aa7`,
`examples/ota-provider-app/ota-provider-common/BdxOtaSender.cpp`, original SHA-256
`aba5601bcbbde23db6e136742f44e3d749a63bc736dfdee090028ebe9e1b363f`.
Copyright (c) 2021 Project CHIP Authors, Apache-2.0. The upstream notice is retained
in the target source; see root LICENSE and NOTICE. Patched-copy SHA-256:
`f7a859bee28bd95d5d551944f0423ffff71cc87406cf0e8f33edad80ea117e49`.

The patched peer accepts a BlockQuery normally but stops supplying data after
5120 sent bytes. Secure exchange processing, automatic MRP ACKs and BDX polling
continue. It does not forge a reply, skip a DUT assertion, accelerate time or
change the requestor. This permits observing an actual BDX idle timeout;
terminating the provider instead can cause earlier MRP delivery failure.

Apply only to a separate disposable SDK checkout or compile a copied translation
unit into a differently named provider. Keep the ordinary provider and SDK source
unchanged. From the disposable SDK root:

```sh
patch --dry-run --fuzz=0 -p1 -i /path/to/matter-c/tools/matter/patches/BdxOtaSender-idle-stall.patch
patch --fuzz=0 -p1 -i /path/to/matter-c/tools/matter/patches/BdxOtaSender-idle-stall.patch
# Build the provider with the existing SDK recipe/tracing settings into a new output.
```

Use the separate executable with the laboratory runner's `--stall-provider`
option and `--mode interrupt-retry --events`. It is used for the first transfer
only; recovery uses the ordinary provider with the same disposable KVS/image.
The result records both binary hashes and distinguishes live-MRP stall from
provider termination. It must not be presented as an unmodified provider run.

The runner accepts `--recovery-announcement-reason 0` to select
SimpleAnnouncement explicitly after the provider restart. With `--default-provider`,
the initial announcement remains UpdateAvailable (reason1). Omitting the override
preserves the existing behavior: recovery inherits the initial reason, and
UpdateAvailable waits for the next scheduled query. The override does not shorten
the requestor's BDX idle timeout or 120-second query floor.
