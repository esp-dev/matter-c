# CSA37: original manual PASE exchange procedure

CSA36 is committed as **`d4811e6`**. The original **TC-SC-2.1** is executed as an
operator-reviewed manual case in **TH v2.15.1+summer2026, run472**: **FAIL**,
five failed entries and two passed entries (final success verification and log
upload). Independent Core1.6.1 observations pass; they do not replace the TH FAIL.
See [identities, receipts and observations](csa37-results.json).

## Original procedure versus Core1.6.1

The installed YAML's top-level `MCORE.ROLE.COMMISSIONEE` guard remains true. Its
source hash matches the CSA01 catalog. No original test, framework/support source,
PICS, native C/H, application API or persisted format was changed.

| Original manual step | Literal procedure expectation | Core1.6.1 / actual wire | Outcome |
| --- | --- | --- | --- |
| 1, PBKDFParamRequest | S=0, DSIZ=0; reversed meaning of hasPBKDFParameters; random described in bits | S=1, DSIZ=0; false requests parameters; 32-byte random | FAIL |
| 2, PBKDFParamResponse | S=0, DSIZ=0; random/salt sizes described in bits | S=0, DSIZ=1; request random echoed, fresh 32-byte responder random, salt16/32 bytes | FAIL |
| 3, Pake1 | S=0, DSIZ=0; 65-bit octet string | S=1, DSIZ=0; 65-byte uncompressed point | FAIL |
| 4, Pake2 | S=0, DSIZ=0; point/confirmation sizes described in bits | S=0, DSIZ=1; 65-byte point, 32-byte confirmation | FAIL |
| 5, Pake3 | S=0, DSIZ=0; 32-bit octet string | S=1, DSIZ=0; 32-byte confirmation | FAIL |
| 6, PakeFinished | Success StatusReport; no earlier encrypted application data | Actual unsecured status (0,0,0), controller PASE success, then encrypted commissioning messages | PASS |

Core **4.14.1.2** requires initiator S=1/DSIZ=0 and responder S=0/DSIZ=1; these
rules also apply to the correctly addressed unsecured success report. Its schemas
specify byte lengths for octet strings. `hasPBKDFParameters=true` means parameters
are known; false requests their return. **3.9 / Crypto_PBKDFParameterSet** specifies
salt16..32 bytes and iteration count1000..100000. **4.4** defines message/exchange
headers. **Appendix A.11.1 / B.5.7 (numeric range qualifier)** permit integer
encoding widths different from the schema's range width; the controller's
passcodeId0 may use a one-byte unsigned TLV value.

This is a retained test/specification discrepancy, not evidence that the observed
PASE exchange violates Core1.6.1. No preprocessor workaround, weakened assertion,
test patch or PICS exclusion was introduced. These differences require CSA/test
clarification; no clarification request was sent and no CSA response is claimed.

## Real exchanges and memory validation

The new `test_pase_exchange_chip.py` runs an unmodified pinned chip-tool through
two isolated IPv6 UDP forwarding lanes. Packets are recorded and forwarded
unchanged, without raw-socket privileges or firewall changes. Each full scenario:

1. Commissions the first fabric through PASE, verifies development attestation
   and CommissioningComplete, then reads VendorID through fresh CASE.
2. Uses that CASE to open an enhanced commissioning window. The unchanged CHIP
   payload parser supplies the generated setup code to the second controller.
3. Commissions the independent second fabric and reads through CASE; the first
   controller remains alive and still reads successfully afterward.
4. Decodes both complete PASE exchanges, including typed/tag-ordered PBKDF TLV,
   request/response random matching, parameter bounds, optional session parameter
   types/ranges, Pake point/confirmation sizes, message/exchange flags, reliable
   delivery flags, shared exchange ID and final success status.

The second PASE responder session ID3 differs from the first fabric's live CASE
ID2 in each accepted run. Initial commissioning uses PASE responder ID1. Request
randoms differ in the two samples. Encrypted PASE application messages are
actually observed after the forwarded PakeFinished; the controller logs confirm
activation/success before commissioning completes. This is not merely an absence
of encrypted traffic. Duplicate MRP datagrams are deduplicated by lane/direction/
counter for transcript inspection. Four altered **in-memory captures** (addressing,
session ID, opcode and truncated TLV) are rejected by the oracle; invalid packets
are not injected into the DUT by these controls.

The full scenario passes **20 checks under Memcheck** and **20 checks separately
under ASan/UBSan/LSan**: four complete PASE exchanges/full commissions in total.
The accepted Memcheck process has **43,510 allocations and 43,510 frees**, zero
errors and zero live bytes. Both accepted node stderr files are empty and both
processes exit0. All disposable processes are stopped and TH is idle. Existing
paired Windows nodes were not restarted or replaced.

The unchanged normal/sanitizer binaries match the CSA35 accepted hashes. All
**362 native source/header manifest entries** still match their CSA35 build
inputs. No new native compilation or compiler-warning check was needed/claimed;
this change adds an external evidence fixture and documentation only. The new
fixture's `--help`, `python tools/matter/check_test_map.py` (242 files) and
`git diff --check` pass. The test map includes its external dependencies/scope.

Four earlier fixture attempts are retained privately: an incorrect PASE-success
log pattern; an overextended concurrent-PASE scenario receiving Busy; an incorrect
payload-parser field name; and an overly strict exact TLV integer-width check.
The accepted scenario uses commissioning/CASE/new-window commissioning, not a
requirement for multiple concurrent PASE contexts. The final Memcheck and sanitizer
runs use the same corrected fixture hash and unchanged native binaries. A final
comment-only correction points to Appendix B.5.7 instead of B.3.5; the AST is
identical, and executed/current source hashes are recorded separately. No repeat
runtime run is claimed for that citation edit. Earlier attempts are not counted
as accepted runs or silently erased.

## Limits, remaining work and reproduction

This is original **manual TH operator review of retained real observations**,
not automatic protocol acceptance or certification. True/known-PBKDF suppression,
session-ID exhaustion/wraparound, cryptographic entropy and all negative PASE
paths were not established by these two samples. The unmodified controller's
successful cryptographic exchange/full commissioning provides interoperability
evidence, not a complete cryptographic audit. No physical radio/firmware, Home UI,
embedded RAM-fit or full CSA matrix rerun is claimed. Raw datagrams, logs,
ephemeral setup codes, controller keys/state and lab configuration stay outside Git.

```sh
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --valgrind
# Repeat separately with a sanitizer node and without --valgrind.
python tools/matter/check_test_map.py
git diff --check
```

Only TC-SC-2.1 gains `manual_result=FAIL`; its category stays MANUAL. Category
totals remain **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA** (862 positions).
MANUAL now contains **12 PASS, 2 FAIL and 25 without an outcome**. Thus the initial
coverage pass still has **25 unreviewed manual procedures plus 3 BLOCKED positions**;
the 18 automatic and 2 manual failures remain a separate later repair/clarification
backlog. Counts are positions/procedures, not a promise of one development stage
per case. CSA30 remains deferred; CSA32 remains open.

**Next: CSA38 — TC-SC-2.2, bidirectional encrypted PASE and decryption-error
handling.** Review its original assertions against Core before choosing the
negative-packet scenario. No result for that next procedure is claimed here.
