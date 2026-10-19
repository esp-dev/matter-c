# CSA41: TC-SC-1.2 MRP Message Flows

CSA40 is committed as **`da09494`**. Original **TC-SC-1.2** is executed in
**TH v2.15.1+summer2026 run476**: **manual FAIL**, six passed entries and one
failed entry. Steps1..5 and evidence upload pass; Step6 fails because five
authenticated R=0 requests receive no data response. The original test/support
sources and PICS are unchanged. See [record and receipts](csa41-results.json).

## Normative basis and cause

Core1.6.1 **4.12.1** permits clearing R when an acknowledgement is not requested.
Under **4.12.5.2.2**, R controls ACK generation; processing then continues to the
next message-reception step. **4.12.2.2 / 4.12.5.1.1** cover standalone and
piggyback ACKs. Exact reliable duplicates must be ACKed again and dropped before
application processing. PASE and CASE themselves require reliable delivery, so
clearing R in a handshake would be an invalid way to test generic R=0 traffic.
All handshake messages in this campaign remain reliable.

The full host's `runtime/matter_dispatch.c`, `dispatch`, rejects a new transaction
when `MATTER_PROTOCOL_RELIABLE` is absent, before constructing its handler. This
also rejects an authenticated, otherwise supported IM ReadRequest. The lower
`matter_rx_policy_receive` correctly records ACK work only for R=1 while still
delivering registered R=0 messages; `matter_im_read_receive` has no R requirement.
The blanket restriction is in runtime admission, not AES-CCM or the read payload.

The same authenticated VendorID read with R=1 succeeds immediately before and
after the five R=0 attempts, using the same session, path, keys and payload with
fresh increasing counters/exchanges. Source inspection identifies the explicit
R=0 rejection branch. This is a **confirmed native integration defect**. Silence
is not accepted as a successful reply merely because it contains no ACK.

No C/H repair is included, following the requested initial coverage pass. A
future fix must retain PASE/CASE reliability rules, authentication, replay and
resource admission, while accepting valid IM R=0 requests without recording or
attaching request ACKs. The response may independently request reliable delivery;
do not blindly force every outgoing response to R=0. Recheck the original case
and mixed R=0/R=1 traffic afterward.

## Actual scenario

The existing recorder gains mutually exclusive **`--mrp-flows`**. Its independent
test peer uses the existing `fixtures/pase-vector.py` affine SPAKE2+ primitives
and Python **cryptography AESCCM**, with fresh ephemeral scalars/randoms. It
validates the responder point, key confirmation and PASE success. The vector
script's fixed test output is suppressed in memory; session keys are never
exported to files or reports. This Python arithmetic is test-only, not production
or constant-time crypto.

| Original step | Actual observation | Verdict |
| --- | --- | --- |
| 1: Reliable message needing data | Valid PBKDFParamRequest; matching response/random | PASS |
| 2: Data reply piggybacks ACK | PBKDFParamResponse A=1, correct request counter/exchange | PASS |
| 3: Reliable message needing no data | Exact PBKDF request duplicate after ACKing original response | PASS |
| 4: Standalone ACK only | Empty R=0/A=1 ACK; no repeated PBKDF response | PASS |
| 5: Send five unreliable messages needing data | Five authenticated VendorID ReadRequests, R=0, fresh counters/exchanges | PASS |
| 6: Data replies without request ACK | No replies to all five; R=1 controls still work | FAIL |
| Evidence upload | Actual receipts and operator explanations retained | PASS |

Observe each duplicate/read for **0.7 seconds**; allow up to **10 seconds** for
costly handshake replies under Memcheck. After ACKing final PASE success, wait
0.25 seconds for the owner loop to activate its secure context before the first
control read. R=1 controls return authenticated ReportData with the expected
VendorID65521 marker. The R=0 messages have the same read payload and packet
length, independent exchanges and increasing authenticated message counters.
Reliable responder messages are ACKed by the peer.

An authenticated **CloseSession**, Core4.11.1.4, releases only this uncommissioned
PASE context. Without restarting the DUT, unmodified chip-tool then commissions
two independent fabrics, verifies attestation/CommissioningComplete, performs
CASE reads, opens the second window over first-fabric CASE and confirms the
first fabric still works. This separates missing R=0 support from resource or
session failure.

## Validation and limits

Both complete scenarios retain **overall/Core FAIL**. Per run, **26 functional
checks and two conformance checks pass**, while **five required-data assertions
fail**. The runs cover ten R=0 inputs, four successful R=1 encrypted controls,
two independent peer PASE sessions and four subsequent full commissions/CASE.
First run: **Memcheck**; second: separate **ASan/UBSan/LSan**. Both DUTs exit0 with
empty stderr. Memcheck records **48,333 allocations / 48,333 frees**, zero errors
and zero live bytes. These checks instrument the native node, not Python peer
key erasure or its memory lifecycle.

Focused `test_ack`, `test_ack_sender`, `test_rx`, `test_rx_policy` and
`test_im_read` targets build and pass **5/5 per build**, without observed compiler
warnings. The existing host binaries and all362 native source/header manifest
entries match the CSA35 build, verified locally and on the VM. There is no new
host compilation or API/ABI/native memory-footprint change. Inventory, report/
hash/count/link checks and `git diff --check` pass. TH is idle and disposable
nodes are stopped; paired Windows nodes are untouched.

Two earlier tester attempts remain private, not accepted as completed CSA
evidence: the first awaited expensive Pake2 for only0.7 seconds; the second sent
the first encrypted control immediately after the final PASE ACK, before owner
handoff. Both stopped at setup/control checks. The final tester uses a bounded
handshake wait, a28-bit initial secure counter, explicit handoff pacing and
CloseSession cleanup. Both final variants use one driver hash. No DUT protocol
clock, timeout, native code or test/PICS source was changed to obtain a result.

Private raw receipts independently verify the identical request/duplicate,
matching ACKs, seven equal-length encrypted read inputs with increasing counters,
encrypted positive replies and no replies for the five R=0 inputs. Session keys
are not retained, so encrypted flags and payloads are supported by the independent
peer source and paired controls, not later offline decryption of the capture.
Finite observation is not proof about every future/internal state. Physical
firmware/radio, Windows transport, Home UI, embedded RAM-fit, all loss patterns
and the full matrix were not rerun. Earlier failures stay deferred.

```sh
# Python cryptography is required only for the --mrp-flows external test peer.
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --mrp-flows --valgrind
# Repeat with sanitizer node, without --valgrind; current expected fixture exit1.
cmake --build BUILD --target test_ack test_ack_sender test_rx test_rx_policy test_im_read -j2
ctest --test-dir BUILD --output-on-failure \
  -R '^(test_ack|test_ack_sender|test_rx|test_rx_policy|test_im_read)$'
python tools/matter/check_test_map.py
git diff --check
```

This is the original **manual operator procedure**, not fully automatic CSA
acceptance or certification. Functional/memory/unit success does not override
its FAIL. Legacy TC-SC-2.1 discrepancy fields in shared private reports are not
this case verdict and are excluded from the public projection. Raw packets,
logs, credentials and controller state remain outside Git.

Only TC-SC-1.2 gains `manual_result=FAIL`. Category totals remain **97 PASS,
18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**,862 positions. MANUAL now has **13 PASS,
5 FAIL and21 without an outcome**. Initial coverage remaining: **21 manual plus
3 BLOCKED**. The18 automatic and5 manual failures remain deferred as requested.

**Next: CSA42 — TC-SC-1.3, MRP Retransmissions.** Review full outbound loss,
retry intervals/counts and final eviction against Core before executing the
original procedure. No CSA42 result is claimed.
