# CSA39: invalid passcodeID and Pake3.cA

CSA38 is committed as **`b8fd2e4`**. Original **TC-SC-2.3**, unchanged source and
PICS, is executed in **TH v2.15.1+summer2026 run474**: **manual FAIL**, seven
passed entries and two failed entries. Steps2/8 fail because the required error
StatusReports are not sent. This is a **confirmed implementation defect**, not a
test/specification discrepancy. See [record and receipts](csa39-results.json).

## Normative expectations and confirmed cause

Core1.6.1 **4.14.1.2** requires both invalid passcodeID and invalid Pake3.cA to
produce `StatusReport(FAILURE=1, SECURE_CHANNEL=0, INVALID_PARAMETER=2)` and stop
processing the failed exchange. The original procedure agrees with these rules.
The device receives/ACKs both modified messages but emits no corresponding
StatusReport. Wire observations and source inspection identify this path:

1. `matter_pase_process` rejects the input and returns `MATTER_PORT_ERROR`.
2. Its `failure` helper clears handshake secrets/keys, marks FAILED and prepares
   the correct eight-byte error StatusReport. `matter_pase_output` exposes it.
3. `runtime/matter_dispatch.c`, `process_transaction`, obtains that output but
   handles the non-OK process result by setting `t->closing` and returning before
   the message is packaged/submitted through UDP/MRP.

The existing `test_pase` checks the correct error output and unavailable keys in
the isolated PASE machine; it passes. The full runtime path drops that output,
which the wire test now detects. A local unit PASS does not supersede this FAIL.
Native C/H, PICS and original test/support sources were not changed. Repair is
deferred as requested while completing the first coverage pass.

The future repair must drain the terminal PASE StatusReport through the actual
UDP/MRP lifecycle before transaction disposal. Check response delivery, retry/
lost ACK behavior, bounded teardown and failure notification exactly once; do
not simply hide fatal results or leave a failed exchange reusable. It belongs
to the existing failure backlog and has not been implemented here.

## Actual scenario

The existing recorder gains `--pase-errors`, mutually exclusive with the MIC test
mode. Each error uses an isolated unmodified chip-tool controller and UDP lane:

- **Invalid passcodeID:** change only value0 to1 in an otherwise valid actual
  PBKDFParamRequest. The DUT sends a matching ACK. No PBKDFParamResponse or error
  StatusReport follows; the controller reaches its own PBKDF timeout.
- **Invalid cA:** a fresh valid passcodeID0 request, PBKDFParamResponse, Pake1 and
  Pake2 are exchanged. Change one bit in the 32-byte Pake3.cA, preserving the TLV
  and headers. The DUT ACKs it but does not send the required error StatusReport.
  The fixture ends the still-pending controller after its observation limit.
- Observe for **up to 12 seconds per negative command**, without changing the
  controller or DUT clocks. The cA command is explicitly aborted by closing its
  controller; that local abort is not presented as a received protocol response.
- Send a valid-shaped Pake1 into the failed passcodeID exchange and the original
  correct cA into the other failed exchange, using **fresh message counters** and
  their original exchange/ephemeral identities. During the subsequent 0.6-second
  observation, no PBKDFParamResponse/Pake2/success or encrypted-session activation
  is seen. Failed exchanges do not revive in this observation.
- Without restarting the DUT, commission a fresh fabric, verify attestation and
  CommissioningComplete, read over CASE, open an enhanced window, commission a
  second independent fabric and confirm both controllers remain usable.

The raw recorder preserves original/forwarded modified packets and late probes.
Independent receipt checks confirm exactly one changed bit per negative input,
valid field types/lengths, a matching DUT ACK and a fresh counter in each late
probe. Private datagrams and controller state are not exported.

| Original step | Operator result |
| --- | --- |
| 1: Send invalid passcodeID | PASS: modified request delivered and ACKed |
| 2: Reject with required StatusReport; no further processing | FAIL: StatusReport absent |
| 3: Send valid passcodeID | PASS |
| 4: Receive PBKDFParamResponse | PASS |
| 5: Send Pake1 | PASS |
| 6: Receive Pake2 | PASS |
| 7: Send invalid cA | PASS: modified confirmation delivered and ACKed |
| 8: Reject cA with required StatusReport; no further processing | FAIL: StatusReport absent |
| Evidence upload | PASS |

## Validation and limits

The complete scenario runs first under **Memcheck**, then separately under
**ASan/UBSan/LSan**. Each run has **26 passing functional checks and 2 failed
required-status assertions**. Both overall/Core outcomes remain **FAIL**; 52
functional PASS observations do not make the protocol test pass. Together the
runs cover four negative exchanges, four late probes and four subsequent full
commissions/PASE exchanges, with CASE reads and no DUT restart.

Memcheck: **48,294 allocations / 48,294 frees**, zero errors and zero live bytes.
Both node stderr files are empty and both nodes exit0. Existing `test_pase` and
`test_secure` pass **2/2 per normal/sanitizer build**. No host or test compilation
was required this step; compiler warnings were not checked anew. All **362 native
source/header manifest entries** and both host binary hashes still match CSA35.
The external Python fixture's `--help`, test-map check (242 files), result/hash/
scope checks and `git diff --check` pass. TH is idle; disposable processes are
stopped and paired Windows nodes untouched.

Earlier attempts remain private: the first stopped at the missing passcodeID
response; the next stopped when the reused controller did not finish the cA
command within the fixture timeout. The final mode uses isolated controllers
and an explicit bounded observation/abort, records both status failures, and
continues functional recovery. It does not scale protocol time or turn a timeout
into PASS. Final normal/sanitizer runs use one fixture hash.

This is original **manual operator review** of real controller/wire observations,
not an automatic CSA test or certification. The finite late-probe window is not
proof of all future/internal processing, and no live key-memory audit was made.
The source failure path and existing unit tests provide complementary evidence
of terminal state/secret cleanup. Other malformed fields, counter exhaustion,
all retry-loss patterns, physical firmware/radio, Home UI, embedded RAM-fit and
the full matrix were not rechecked. Private logs, codes, state and keys stay
outside Git. Earlier results are inherited.

```sh
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --pase-errors --valgrind
# Repeat separately with a sanitizer node, without --valgrind.
# Expected current exit1: the required status assertions fail; DUT itself exits0.
ctest --test-dir /path/to/build --output-on-failure -R '^(test_pase|test_secure)$'
python tools/matter/check_test_map.py
git diff --check
```

Only TC-SC-2.3 gains `manual_result=FAIL`; category totals stay **97 PASS, 18 FAIL,
3 BLOCKED, 39 MANUAL, 705 NA** (862 positions). MANUAL contains **12 PASS, 4 FAIL,
23 without an outcome**. Continue first-pass coverage of **23 manual plus 3
BLOCKED positions**; the 18 automatic and 4 manual failures remain deferred.
CSA30 stays deferred and earlier clarification items stay open.

**Next: CSA40 — TC-SC-1.1, MRP Max Message Size.** First resolve which protocol/
network headers are included in the procedure's 1280-byte boundary, then exercise
actual boundary datagrams and acknowledgements. No result is claimed yet.
