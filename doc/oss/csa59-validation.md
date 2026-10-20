# CSA59: Timed Write interval and MRP retry attribution

Original **TC_IDM_5_2 remains FAIL**, final unchanged-node run 603. No native
Timed Write deadline defect was confirmed. The observed write is inside the
actual interval; changing it to TIMEOUT would reject a valid transaction.
Campaign remains 122 PASS/28 FAIL/5 prerequisites. This is experimental x86
acceptance, not certification.

## Actual receive/send evidence

The original script requests a 700 ms interval and passes `busyWaitMs=1400` to
WriteAttribute, expecting a global timeout. Its test text says to wait after
Success, but the call does not prove when the responder actually sent Success.
Core 1.6.1 sections 8.7.1.2 and 8.7.2.3 start the interval at the successful Status
Response and require global TIMEOUT for a genuinely expired WriteRequest.

In diagnostic original run 601:

1. The initial TimedRequest reaches the kernel, but authenticated admission
   returns `MATTER_WOULD_BLOCK` because the preceding RX is still pending.
   Replay state is committed only on successful admission; the peer may retry.
2. The same counter is retried 1,414.41 ms later and is admitted. Only now does the
   native handler send Success and start its 700 ms window.
3. Write reaches the DUT kernel **1.56ms after the Success send**. Separately,
   native logical send15934/deadline16634/receive15965ms gives31ms elapsed.
   These are separate measurements on the DUT, not controller TX log estimates.
4. The reply is WriteResponse 0x07 with per-path Success 0x00. The Root callback
   confirms NodeLabel changed to the original step4 value. This is expected
   for an in-window write, rather than evidence of accepting an expired write.

Instrumentation is confined to ignored diagnostic exports: RX kernel timestamps,
actual sendmsg timestamps, RX admission/dispatch and callback status/effects.
No key/plaintext dump is added to the public runtime. Earlier diagnostic label
markers were corrected before the decisive run 601; conclusions use that trace.

The bounded RX queue can drop a datagram under backpressure. MRP recovery is
working here, but a busy wait started before the successful response cannot
reliably force expiry across that recovery. Request CSA clarification/a test
delay after the real Success response, including loss/retry coverage. **No report
has been sent to CSA.** Queue efficiency remains a separate engineering question;
this receipt is not full ingress-load acceptance.

## Unchanged original results

| Run | Fixture | Result |
| --- | --- | --- |
|598| Private diagnostic node on the controller VM | FAIL, step4 |
|599| Diagnostic node on a separate VM | FAIL, step4 |
|600| Separate VM, socket timestamps | FAIL, step4 |
|601| Separate VM, socket/RX/callback attribution | FAIL, step4 |
|602| Replacement host did not publish | ABORTED, invalid fixture |
|603| Supervised original frozen node, separate VM | FAIL, step4 |

Run 602 started without waiting for the previous listener to drain; a bind/start
race is inferred, not a measured socket errno. It provides no protocol verdict.
Run 603 verifies the port is free and waits for publication before starting TH.
Both the original source and PICS remain unchanged. All valid runs retain the
same 6 passed/1 failed step counts. Raw receipts and hashes are preserved in
[the public results](csa59-results.json), with private logs retained locally.

## Independent acceptance and memory

Extended the existing `test_pase_exchange_chip.py` with `--timed-writes`:

- Establish independent authenticated PASE using the existing affine fixture and
  cryptography AES-CCM; no native DUT codecs/crypto are reused by this peer.
- Perform a valid timed NodeLabel write and verify readback.
- Receive Success, then actually delay at least 1.4 s before a WriteRequest.
  Require global StatusResponse/TIMEOUT 0x94 and unchanged NodeLabel.
- Repeat after an expired duplicate TimedRequest. Require the matching MRP ACK,
  no new IM response for the exchange, and issue Write within a hypothetical
  restarted 700 ms interval. This detects an incorrectly restarted deadline.
  Legitimate unrelated ACKs/original-response retransmissions are allowed.
- Write a different recovery label and verify its new value. Close the probe's
  PASE session, then commission two independent chip-tool fabrics and verify
  normal CASE/operational reads and a commissioning-window transition.

**41 checks plus 2 existing conformance controls pass per variant**. Final
Memcheck: 48,407 allocations/frees, 0 errors and 0 live bytes/blocks. Separately,
ASan/UBSan/LSan passes with empty native stderr and normal exit. No sanitizer
combination with Valgrind is used. Binary/source fingerprints are in the receipt.

The first relay prototype failed its own guard because operational discovery
bypassed the relay; it was excluded and is not exported. An earlier overly strict
duplicate check rejected unrelated ACK traffic. The final probe scopes the ACK
and status checks to the relevant exchange and enforces the hypothetical-window
bound, so it cannot pass merely by letting a restarted interval expire again.

Clean builds compile and pass `test_im_write`, `test_im_write_alloc`,
`test_im_invoke` and `test_dispatch`: 4/4 normal and 4/4 sanitizer, without compiler
warning lines. The initial attempt against a partial cached build lacked three
executables per variant; these launch failures are not native assertion failures.
The fresh clean builds resolve that setup problem. Test-map validation and
campaign regeneration also pass.

## Scope and reproduction

Native C/H inputs remain byte-identical across all 362 checkpoint inputs and the
clean unit-test export. The runtime, timing policy, public API, test assertions
and PICS are unchanged. Memory scenarios reuse the frozen CSA57 normal/sanitizer
host binaries after identity verification; focused tests use fresh clean builds.
The preexisting TH sdk_container.py modification documented in CSA58 remains;
no pristine-harness claim is made. Shared support fingerprints remain unchanged.

```text
python tools/matter/tests/test_pase_exchange_chip.py --help
python tools/matter/tests/test_pase_exchange_chip.py --node NORMAL_NODE --chip-tool CHIP_TOOL --paa PRIVATE_PAA --credentials PRIVATE_CREDENTIALS --interface INTERFACE --ipv6 IPV6 --output FRESH_PRIVATE_OUTPUT --timed-writes --valgrind
# Repeat with the sanitizer node, without --valgrind.
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
```

No original test patch, physical-device test, delayed CASE Write peer injection,
full 99-position rerun or certification is claimed. Late-write wire probes use
PASE; the original CASE timing/callback trace and focused shared-handler tests
are separate evidence. Stage processes are stopped, TH is idle, the temporary
PAA is removed, and existing paired Windows nodes/stores were not modified.

Next: **CSA60**, revisit CSA28's existing QueryImageResponse investigation before
preparing a deterministic provider fixture for unchanged TC_SU_2_2. Keep original
FAIL outcomes separate from independent acceptance and external clarification.
