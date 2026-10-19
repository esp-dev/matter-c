# CSA38: bidirectional PASE and decryption errors

CSA37 is committed as **`c0ac3f0`**. Original **TC-SC-2.2**, unchanged source and
PICS, is executed in **TH v2.15.1+summer2026 run473** as operator-reviewed manual
evidence: **FAIL**. Four communication steps and log upload pass; Step5's required
session termination/key clearing does not occur after a corrupt MIC. See
[identities, observations and receipts](csa38-results.json).

## Requirement and implementation review

Core1.6.1 **4.14.1.2, Session Encryption Keys** derives
`I2RKey || R2IKey || AttestationChallenge`. The initiator sends with I2R and
receives with R2I; the responder does the reverse. The existing PASE handoff
(`matter_pase.c`) copies the appropriate halves by role, and `matter_secure.c`
uses send_key for CCM encryption and receive_key for CCM decryption. No keys were
extracted from the running host or controller to obtain this evidence.

Core **4.8.3, Step4a** requires failed AEAD verification to stop further processing
of **that message**; an error should be raised to the upper layer. It does not
mandate destroying the session on each bad MIC. **3.6.2** defines verification
failure. The runtime's `matter_secure_receive` returns the crypto error before
decoding the protocol header, admitting work or committing replay state, and
clears scratch plaintext on exit. The dispatcher drops that datagram without
retiring the otherwise live connection. Keys are cleared through the existing
close/drain/delete lifecycle, rather than on this unauthenticated input.

The original YAML Step5 instead expects the session to terminate and keys to
be cleared after an initiator or responder decryption error. That is a stronger
expectation than the cited Core message-processing rule. A corrected datagram
with the same counter/session is accepted and commissioning continues in the
same PASE session; immediate termination therefore demonstrably did not occur.
**No wire-based key-erasure claim is made.** The original FAIL remains pending
CSA/test clarification, not relabeled as PASS or NA. No clarification was sent
and no CSA response is claimed. No native workaround, PICS change or official
test/support patch was introduced.

## Actual fault-injection scenario

`test_pase_exchange_chip.py --tamper-pase` extends the existing private IPv6 UDP
recorder. Its default commissioning scenario is retained. The selected mode:

1. Establishes real PASE with the unmodified chip-tool. Before forwarding its
   first encrypted request, changes **one bit in the final MIC byte** and sends
   that damaged copy to the DUT. Header, ciphertext body and counter are unchanged.
2. Holds the original and its retransmissions for at least **0.6 real seconds**.
   No encrypted response/progression from the responder is observed during the
   hold. Then forwards the original packet unchanged.
3. Repeats MIC corruption and the hold for the first encrypted responder message.
   Encrypted responder retransmissions are also held. The initiator does not
   advance with a new encrypted counter before the valid original is released.
4. Observes successful encrypted commissioning in the **same** PASE session
   after both failures: attestation and CommissioningComplete, followed by CASE
   reads. It opens an enhanced window over that live CASE, commissions a second
   independent fabric, and confirms the first controller still reads successfully.

Both directions use the same original message counters and destination session
IDs when the held valid packets are released. There are exactly two complete PASE
handshakes per scenario, one per fabric; recovery is not a fresh hidden PASE.
The first responder session is ID1; its first controller's destination ID is
recorded separately. Later CASE ID2 coexists with the second PASE ID3. Captures
record incoming original datagrams; injection metadata retains original/damaged
hashes, identifiers and elapsed holds. The damaged copies are reproducible by the
documented one-bit operation; raw data and lab setup remain private.

| Original TC-SC-2.2 step | Operator result / basis |
| --- | --- |
| 1: Initiator sends with I2RKey | PASS: actual encrypted PASE requests reach the responder |
| 2: Responder decrypts with I2RKey | PASS: valid original after corrupt MIC is accepted; commissioning commands execute |
| 3: Responder sends with R2IKey | PASS: actual encrypted responses are recorded/forwarded |
| 4: Initiator decrypts with R2IKey | PASS: unmodified controller accepts valid response and completes authenticated commissioning |
| 5: Decryption error terminates session and clears keys | FAIL: session continues after bad MIC; no immediate termination; key memory not inspected |
| Evidence upload | PASS |

## Validation

The complete fault-injection scenario passes **25 independent checks under
Memcheck** and **25 separately under ASan/UBSan/LSan**. This includes four actual
bad-MIC deliveries in total, four complete PASE exchanges/full commissions, valid
encrypted communication after both-direction errors and CASE continuity. The
observed holds range from about **0.60 to 0.71 seconds**, without changing DUT or
controller clocks/timeouts. Existing four in-memory oracle mutation controls per
scenario remain separate from the actual wire injections.

Accepted Memcheck: **43,536 allocations / 43,536 frees**, zero errors, zero live
bytes. Both host stderr files are empty; both hosts exit0. Disposable processes
are stopped, TH is idle and paired Windows instances are untouched.

The first focused CTest invocation could not execute because `test_pase` and
`test_secure` had not been built in the reused CSA35 trees. Those two existing
targets were then compiled, and **2/2 tests pass per normal and sanitizer build**.
The recorded build logs contain no compiler warnings. `test_secure` checks
authentication rejection before admission/replay mutation, scratch clearing and
normal close/drain cleanup. This is separate white-box evidence, not live key
inspection or a CSA acceptance result. No allocation-variant execution is claimed.

No native C/H or public API/persistence changes. All **362 native source/header
manifest entries** and both host binary hashes still match the accepted CSA35
inputs/binaries. Native host recompilation was not performed; the two focused
test executables were built. `--help`, `python tools/matter/check_test_map.py`
(242 mapped files) and `git diff --check` pass. The existing fixture's new mode
and scope are recorded in the test map; no duplicate recorder was added.

```sh
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --tamper-pase --valgrind
# Repeat separately with a sanitizer node, without --valgrind.
cmake --build /path/to/build --target test_pase test_secure -j 2
ctest --test-dir /path/to/build --output-on-failure -R '^(test_pase|test_secure)$'
python tools/matter/check_test_map.py
git diff --check
```

## Limits and accounting

This is original **manual TH operator review**, not an automatic protocol test or
certification. No full CSA campaign, physical radio/firmware, Home UI, embedded
RAM-fit or live key-memory erasure audit was performed. Fault coverage is one
MIC bit per direction, not all malformed encrypted messages. A finite silent
interval establishes the recorded observation, not proof of every possible
internal side effect. Successful originals/full commissioning and existing secure
tests provide the complementary evidence. Legacy TC-SC-2.1 discrepancy fields
retained by the shared private fixture are not the TC-SC-2.2 verdict; its dedicated
`TC_SC_2_2` result and original TH receipt are authoritative for this step.

TC-SC-2.2 stays category MANUAL and gains `manual_result=FAIL`. Totals remain
**97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA** (862 positions). MANUAL now has
**12 PASS, 3 FAIL, 24 without an outcome**. The initial coverage pass therefore
has **24 manual procedures without an outcome plus 3 BLOCKED positions**; the
18 automatic and 3 manual failures remain deferred as requested. Earlier results
are inherited; CSA30 remains deferred and CSA32/37 discrepancies remain open.

**Next: CSA39 — TC-SC-2.3, PASE error handling: invalid passcodeID and invalid
Pake3.cA**, including actual failure statuses, bounded cleanup and subsequent
valid-session recovery. No result for that next case is claimed here.
