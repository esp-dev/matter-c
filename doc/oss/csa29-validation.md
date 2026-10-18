# CSA29: Identify and laboratory recovery

CSA28 was committed as **`f59af1f`**. CSA29 restores the TH laboratory after
network/container disruption and completes the original **TC-I-2.2** on the
existing x86 profile. No C/H implementation or public API changed.

## Laboratory recovery

Both Linux VMs remained reachable over SSH, their source/binary artifacts were
intact and the DUT's fixture ports were free. However, all Docker-published TH
HTTP services timed out. Docker bridges lacked their IPv4 addresses and routes
to the container subnets. This was an environment failure, not a Matter result.

The operator executed `sudo systemctl restart docker`, then started the existing
TH Compose services. The SSH account could not perform these operations without
a sudo password. The service start recreated the bridge addresses/routes; TH's
frontend returns HTTP 200, the API is responsive and the final test state is idle.
No images were rebuilt or downloaded by the recovery procedure. The report does
not claim a persistent change to service auto-start policy.

The recreated SDK container used its normal mounted PAA directory. The custom
development PAA used by this node was present in the Python fixture but absent
from that YAML runner trust store. Run458 correctly rejected commissioning with
PAA-not-found and was cancelled before test assertions. The missing public PAA
was explicitly installed as a temporary laboratory trust anchor. Its SHA-256 is
`7b1a773695da4da446189d19fede0219f0d8d0fe78c22583cbcc065346ffc559`.
Signature/chain verification stayed enabled; no keys were copied and no existing
root was replaced. The temporary certificate was removed after the test.

Run459 reached the first operator prompt and was cancelled because the runner
expected the literal YAML text input rather than TH's ManualVerification prompt.
The runner was then matched to the actual prompt format and evidence upload.
These attempts remain recorded separately; they are not relabelled as passes.

## Official result

**TC-I-2.2 PASS, TH run460: 15/15 step entries passed.** The installed YAML source
remains unchanged, SHA-256
`819e24eeda8cb353aa7de759aeffee28b1496b7d38e9739971a5641670d6ca03`.
The existing endpoint1 PICS is reused without disabling its four Identify bits
or PICS_USER_PROMPT. Its digest is in the [result record](csa29-results.json).

Actual TH readback is IdentifyType0 and IdentifyTime **60, 50, 0, 0** at the
immediate, ten-second, explicit-stop and post-expiry checks. The live host
presentation callbacks are **60, 0, 15, 0**. Before accepting each operator
verification, the runner checks the actual live callback prefix on the isolated
node. Both assessments and their timestamps are retained and uploaded as evidence.

This is the original **semi-automated** case with agent-evaluated operator
steps, not a fully automatic test or physical indicator validation. The matrix
row moves **BLOCKED -> MANUAL, manual result PASS**. Counts become
**97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA** (862 rows). Other results
are inherited. No CSA certification is claimed.

## Specification and observation boundary

Application Cluster R1.6.1 **1.2.4.1** defines IdentifyType0 as None, with no
presentation. **1.2.5.2** prohibits None when the device can present one of the
other defined methods. This headless x86 fixture declares no physical indication;
the callback log observes application state, not a flashing LED or display.
The operator assessment is explicitly limited to that declared simulation profile.
A downstream device with a physical presentation method must declare and test it.

Sections **1.2.5.1** and **1.2.6.1** require setting/decrementing IdentifyTime,
starting identification for nonzero values and stopping at zero. Countdown ticks
are not reportable by themselves; command/write changes and transitions to/from
zero are reportable. The existing C implementation already follows these rules.

## Independent acceptance

The new [chip-tool scenario](../../tools/matter/tests/test_identify_chip.py)
checks verified development attestation, Type0 and initial zero, command60,
immediate read, a real ten-second countdown, command0, write15, natural expiry,
quiet reporting and a fresh CASE read after a clean host restart.

- **18 checks pass under Memcheck**, across two host boots.
- **16 checks pass separately with ASan/UBSan/LSan**, also across two boots.
- Memcheck totals **35219 matched allocations/frees, zero errors and zero live
  bytes**, without suppressions. All host stderr files are empty. These counts
  cover the C host, not the external CHIP controller.
- Ten-second samples read 50 after 10.075/10.065 s; natural expiry is observed
  after 15.096/15.065 s. The callback sequence is 60/0/15/0 in both runs.
- Four actual callback/report conditions are replayed through the final test
  predicates. Six negative controls reject early/late expiry, a missing stop,
  countdown-tick reports, a missing final zero and a stale zero before 15.

The first independent fixture failed because it expected a different chip-tool
status-line format, although the C command succeeded. Its result is retained.
An intermediate runner was interrupted during that same mismatch; an attempted
reuse of its output directory was rejected before launching a node. Fresh final
directories use the exact endpoint/cluster/command Success pattern. No production
correction was required and these setup attempts are not additional passing runs.

## Reproduction and changed files

Run original TC-I-2.2 from SDK YAML Tests / FirstChipToolSuite on endpoint1,
with PICS_USER_PROMPT and the Identify server/attributes/command enabled.
Configure the development PAA explicitly for the YAML chip-tool trust store,
keep verification enabled and restore the store after the isolated test.
Evaluate its two operator prompts against the declared IdentifyType and live
callback evidence; upload the compact evidence log.

```sh
python tools/matter/tests/test_identify_chip.py \
  --exe /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/paa --credentials /path/to/credentials --interface 2 \
  --output /path/to/fresh-memcheck-directory --valgrind
# Repeat separately with the sanitizer binary and another directory, without Valgrind.
python -m py_compile tools/matter/tests/test_identify_chip.py
python tools/matter/tests/test_identify_chip.py --help
python tools/matter/check_test_map.py
git diff --check
```

The new optional runner and inventory entries make the acceptance reproducible.
README, status, roadmap and this report/result JSON record the outcome and
limits. The inventory contains 237 mapped files; 87 native definitions,
59 core sources and 75 public headers remain unchanged. Both host binaries are
reused after matching the 360-file C/H manifest; no rebuild or new CTest campaign
is claimed. State, development certificates, logs and local VM paths remain
outside Git. User-paired Windows nodes were not restarted or modified.

## Limits and next task

This step does not validate physical indication, Windows GUI painting, consumer
ecosystems, firmware installation, 128 kB RAM fit or the whole CSA campaign.
The TH node is stopped, its port released, the temporary PAA removed and TH idle.
The original test, inherited PICS bits, other trusted roots and paired user
devices were not changed to force a pass.

**Next: CSA30 — TC-DGGEN-2.1, General Diagnostics and its x86 operator fixture.**
The remaining BLOCKED cases are General Diagnostics, Group Key Management and
Device Attestation. Review each original prompt before automating an assessment.
