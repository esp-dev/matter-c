# CSA33: commission, remove and recommission

CSA32 was committed as **`d1d8a47`**. Original **TC-DD-3.19**, selected from
FirstManualSuite without source or PICS changes, finishes **PASS in TH run467**.
All seven entries pass: preconditions, five protocol steps and evidence upload.
This is an operator-reviewed manual result, based on retained real x86/controller
and DNS-SD observations. TH records the review; it does not itself execute the
standalone controller commands. No runtime C/H fix was required.

## Accepted workflow

The existing last-fabric fixture now accepts `--same-controller` and an optional
`--qr-image`. The CSA33 run uses both, with the full frozen three-phase profile:

1. Start a disposable uncommissioned node. Observe its actual discriminator and
   CM=1 through IPv6 multicast discovery. Supply a QR bitmap generated with the
   existing C payload utility and C QR encoder/settings used in CSA31.
2. Independently scan that bitmap with zxing-cpp and commission through the
   unmodified chip-tool's QR/on-network path. Attestation and SendComplete pass;
   CommissionedFabrics is one and the actual advertisement changes to CM=0.
3. Keep an EPM subscription active during RemoveFabric. The same controller
   receives NOCResponse status0/index1. The node reports one last-fabric reset
   and exits cleanly. Observe operational TTL0 goodbye, no positive answers for
   the old operational identity and no advertisements from the stopped host.
4. Explicitly restart the host with the **same state file**, without deleting
   or editing it. The supported manufacturer restart path opens CM=1 with _CM;
   the old operational identity is absent. No destructive reference-app cleanup
   command from the YAML example is executed.
5. Scan the **same supplied QR** again and recommission using the **same live
   chip-tool process, controller storage and fabric credentials**. Attestation
   and SendComplete pass again, CommissionedFabrics remains one and CM returns
   to zero. The same fabric/node operational identity reappears and responds.
   Trusted roots, ACL and GroupKeyMap reads show expected fresh defaults.

Operational identity reuse after recommissioning is expected here: the
controller CA/fabric and assigned node ID are unchanged. Its absence between
removal and recommissioning is checked separately. CSA32's default fixture mode
still uses a new independent controller and expects a different identity.

The final independent runs pass **37 checks under Memcheck** and **35 separately
under ASan/UBSan/LSan**. The two Memcheck boots total **47,881 allocations and
47,881 frees**, zero errors and zero live bytes. All four host stderr files are
empty, and disposable node/controller processes are stopped. Accepted native
binaries are unchanged CSA30 builds; no new C build or broad CTest rerun was
needed for this controller-fixture change.

## Fixture corrections and original procedure

Two exploratory fixture failures remain recorded. The first incorrectly
required VP from the YAML's example discovery log; the actual responder supplies
D and CM. The final predicate checks the real discriminator and basic-window
mode; identity/attestation verification remains part of commissioning.

The second attempt's old EPM subscription timed out while the same interactive
controller was recommissioning. Its asynchronous `Run command failure` caused
the shared command helper to report failure, even though the subsequent log
contains successful attestation and SendComplete. The final fixture explicitly
issues controller `subscriptions shutdown-all` **after confirmed removal**.
It preserves the live process and credentials; no failure matching is weakened,
timeout ignored or controller store replaced. Both final full runs use that fix.

The original procedure's Step4 explicitly expects **CM=1** when re-entering
commissioning. It agrees with the observed manufacturer restart path. This does
**not** waive the contradictory CM=0 instruction in CSA32/TC-OPCREDS-3.6: that
separate manual FAIL remains open. Original YAML and profile PICS hashes, raw
result/log hashes, operator inputs and accepted driver identities are retained
in the [result record](csa33-results.json). The TH runner has a 180-second external
deadline and is idle after completion; protocol requirements are unchanged.

## Coverage, reproduction and limits

TC-DD-3.19 stays category MANUAL with manual_result=PASS. Category totals remain
**97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA**. The manual category now contains
**11 PASS, 1 FAIL and 28 without an outcome**. Other results are inherited.

```sh
python tools/matter/tests/test_last_fabric_discovery_chip.py \
  --same-controller --qr-image /private/supplied-setup-card.png \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --payload-exe /path/to/C-payload-utility --paa /path/to/development-paa \
  --credentials /path/to/development-credentials --interface 2 \
  --output /path/to/fresh-private-memcheck --valgrind
# Repeat separately with the sanitizer node, without --valgrind.
# Bitmap scanning requires Pillow and zxing-cpp 2.3.0.
python -m py_compile tools/matter/tests/test_last_fabric_discovery_chip.py
python tools/matter/check_test_map.py
git diff --check
```

The CLI exits on last-fabric removal and needs an explicit restart; this run does
not add automatic restart behavior. QR scanning is programmatic, not a physical
label or phone-camera test. Non-default ACL/group-key datasets were not seeded;
their full erasure is not proven by reading expected defaults. Existing paired
Windows instances and stores are untouched. No physical Wi-Fi, Apple/Google Home
UI, embedded RAM-fit or certification acceptance is claimed. Raw logs, state,
keys and captures remain outside Git.

Next: **CSA34, TC-DD-2.1 Announcement by Device Verification**: review original
conditional branches and accept the declared IP announcement/discovery path with
bounded operator evidence. CSA30 remains unsuccessful/deferred, and CSA32's
discrepancy remains unresolved.
