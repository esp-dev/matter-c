# CSA43: TC-SC-1.4 counters and duplicates

CSA42 is committed as `c223287`; the continuing campaign plan/checkpoint is
committed as `8b195ba`. Original **TC-SC-1.4 PASS**, TH **run478**: both manual
steps and evidence upload pass, with unchanged source/support/PICS. No native
code or profile change was needed. See [receipts](csa43-results.json) and the
[continuing queue](csa-campaign-status.md).

The existing recorder gains `--mrp-duplicates`. Send a valid reliable PBKDF
request and require a response with the matching exchange, destination, A flag
and acknowledged counter, plus echoed request random. ACK the reliable original
response, then send **three byte-identical copies** of the request, retaining
its original counter/exchange/path. Each repeat receives only empty standalone
ACKs with A=1/R=0 and the same original counter. There is **one application data
response for the original, zero for each duplicate**. Observe0.7 seconds per
input. Core1.6.1 4.12.5.2.2 and the reviewed RX duplicate path require the duplicate
to be dropped before application delivery; no live callback/allocation audit is
claimed from this wire observation alone.

Terminate only this incomplete handshake with malformed Pake1, without asserting
or waiving CSA39's missing error report. Without DUT restart, unmodified chip-tool
then commissions two fabrics, verifies attestation/CommissioningComplete and CASE
reads, opens an enhanced window through the first CASE and confirms its continued
use. Raw packets, state and credentials remain private.

Both full scenarios pass **32 checks each**: Memcheck first, separate
ASan/UBSan/LSan second. Across both: two originals, six exact duplicate probes and
four subsequent full commissions. Memcheck: **43,506 allocations/frees**, zero
errors/live bytes. Both nodes exit0 with empty stderr. The existing replay/RX
targets `test_reception`, `test_rx`, `test_rx_policy` pass **3/3 per variant**;
CMake target checks succeed without observed warnings. No new host compilation
is claimed. All362 native inputs and host binary identities remain at CSA35.
TH is idle, disposable nodes stopped and paired desktop nodes untouched.

Commands executed include the full recorder with `--mrp-duplicates --valgrind`,
the same scenario with sanitizer node without Valgrind, incremental CMake target
checks, focused CTest, `python tools/matter/check_test_map.py`, campaign refresh/
validation and `git diff --check`. This is original manual/operator acceptance,
not fully automatic CSA or certification. No physical/radio/Home UI, embedded
RAM-fit or full-matrix rerun. Finite observations and the selected PBKDF operation
do not cover all counters/protocols or prove every future/internal side effect.
Earlier failures remain deferred.

Counts stay97 PASS/18 FAIL/3 BLOCKED/39 MANUAL/705 NA,862 positions. MANUAL now
contains **14 PASS,6 FAIL,19 without an outcome**. **Next: CSA44, TC-DESC-2.1**,
current profile Descriptor/device-type/server/client lists and hierarchy. Continue
the campaign; do not stop after this case or start repairs before coverage review.
