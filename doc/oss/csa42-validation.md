# CSA42: TC-SC-1.3 MRP Retransmissions

CSA41 is committed as **`6a8692f`**. Original **TC-SC-1.3** is executed in
**TH v2.15.1+summer2026 run477**: **literal manual FAIL**, four passed entries
and one failed entry. Steps1..3 and evidence upload pass. Step4 is retained as
FAIL for clarification of total transmissions versus retransmissions. The
independent **Core1.6.1 acceptance passes**. No native defect is established and
no C/H, PICS or original test/support source is changed. See [receipts and
classification](csa42-results.json).

## Count and timing requirements

Core **4.12.2.1**, **4.12.6** and **Table22** distinguish total transmissions from
retries. At the host's configured `MRP_MAX_TRANSMISSIONS=5`, there are **five
total sends: initial transmission plus four retransmissions**. The original
Step4 verification instead says:

> Verify that the DUT stops sending messages after a total of MRP_MAX_TRANSMISSIONS - 1 messages have been sent.

Under a literal **total-message** reading, this expects four total sends, which
the DUT does not produce. If the intended meaning is **four retransmissions**,
the observed behavior meets it. This is an open wording/interpretation issue;
no CSA clarification has been received. The original FAIL is retained rather
than rewriting the source or reducing the native count to four to obtain PASS.

Core backoff includes margin1.1, base1.6 after threshold1 and jitter0..25%.
The peer explicitly advertises **idle=active=500ms** in PBKDF SessionParameters.
This makes the procedure's idle interval base unambiguous without changing DUT
timers. It does **not** prove independent idle/active-state selection. With this
peer, the expected intervals between the five data transmissions are:

| Gap | Core minimum | Core maximum | Memcheck observation | Sanitizer observation |
| --- | --- | --- | --- | --- |
| Initial to retry1 | 550ms | 688ms | 579.35ms | 613.39ms |
| Retry1 to retry2 | 550ms | 688ms | 632.37ms | 651.10ms |
| Retry2 to retry3 | 880ms | 1100ms | 1066.21ms | 983.45ms |
| Retry3 to retry4 | 1408ms | 1760ms | 1734.40ms | 1533.75ms |

The external oracle uses exact rational arithmetic from the Core formula,
independent of native timer functions. It declares a receive-scheduling tolerance
of-25/+125ms, but **all eight observations also pass without that tolerance**.
Receive timestamps include OS/VM scheduling; no protocol clocks are scaled.

## Actual loss and termination scenario

The existing recorder gains mutually exclusive **`--mrp-retries`**:

1. Send one valid reliable PBKDFParamRequest with a fresh ephemeral peer identity.
2. For **12 real seconds**, record and discard every DUT datagram. Send no ACK,
   continuation or other reply. This is complete response/ACK loss after the
   initial trigger, not a failed local send or a replay-driven retry.
3. Observe exactly five byte-identical reliable PBKDFParamResponses with the
   same counter/exchange, correct destination, echoed request random and piggyback
   ACK counter. Standalone request ACKs are not counted as data retransmissions.
4. Verify the four gaps and continued silence beyond the final maximum wait
   of **2816ms plus a1000ms guard**. Actual tail silence is about7.95/8.22 seconds.
   The native PASE attempt deadline is30 seconds, so that deadline is not being
   substituted for MRP exhaustion.
5. Send a valid late standalone ACK with a fresh peer counter. No response or
   restarted retry train appears during the next0.7 seconds.
6. Without restarting the DUT, complete two fresh chip-tool fabrics, attestation/
   CommissioningComplete, CASE reads and enhanced-window reopening through the
   first fabric. Confirm the first fabric still works.

Independent receipt checks recompute packet identities, message counts, peer
silence, raw timing gaps/bounds and the late ACK. The original TH answers are
PASS/PASS/PASS/FAIL for the reasons above; the log upload passes.

## Validation and limitations

Full scenarios pass **32 independent Core checks each**, first under **Memcheck**,
separately under **ASan/UBSan/LSan**. Both nodes exit0 with empty stderr. Memcheck
reports **43,530 allocations / 43,530 frees**, zero errors and zero live bytes.
Together the scenarios observe ten data transmissions, eight retransmissions,
eight timed gaps, two late-ACK probes and four subsequent full commissions/CASE.

Incremental CMake target checks and existing `test_retransmission` /
`test_retransmission_sender` CTests pass **2/2 per build**. No warnings appear in
those build logs; no fresh compiler validation is claimed for the unchanged host.
All362 native source/header manifest entries match locally and on the VM, and
host binary hashes still match CSA35. Inventory, report/hash/count/link checks
and `git diff --check` pass. TH is idle and disposable nodes are stopped; paired
Windows nodes are untouched.

```sh
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --mrp-retries --valgrind
# Repeat separately with sanitizer node, without --valgrind.
cmake --build BUILD --target test_retransmission test_retransmission_sender -j2
ctest --test-dir BUILD --output-on-failure \
  -R '^(test_retransmission|test_retransmission_sender)$'
python tools/matter/check_test_map.py
git diff --check
```

Wire cessation and recovery are not live instrumentation of the host's internal
timeout callback or exact table-slot eviction. Existing table/sender unit tests
provide complementary timeout/drain evidence. Finite silence does not prove all
future states. Equal peer intervals do not cover state selection, every parameter
range, RNG distribution or partial-loss pattern. There is no physical firmware/
radio, Windows/Home UI, embedded RAM-fit or full-matrix rerun. This is original
**manual operator review**, not fully automatic CSA acceptance or certification.
The literal TH FAIL remains distinct from independent Core PASS. Raw packets,
logs, keys and controller state stay outside Git; legacy TC-SC-2.1 discrepancy
fields in shared private reports are excluded from this case's public projection.

Only TC-SC-1.3 gains `manual_result=FAIL`. Category totals remain **97 PASS,
18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**,862 positions. MANUAL now has **13 PASS,
6 FAIL and20 without an outcome**. Initial coverage remaining: **20 manual plus
3 BLOCKED**. Earlier native failures remain deferred; this count issue belongs
to the clarification backlog, not an identified native repair.

**Next: CSA43 — TC-SC-1.4, MRP counters and duplicate handling.** Check matching
ACK counters and absence of repeated application side effects. No result for
CSA43 is claimed.
