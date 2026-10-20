# CSA66: same-instance OTA recovery after a resolver send failure

The starting commit is `693ec82`; the tracked tree was clean. A new optional
laboratory mode injects exactly one `sendto()` ENETUNREACH into the native
requestor's operational resolver. The same requestor then preserves its retry
guard, establishes CASE and completes signed simulated OTA. Both memory variants
pass25 checks. [Receipt](csa66-results.json) retains fingerprints and limits.
No native implementation, public API, retry policy or original CSA test changes.

## Fault and recovery

The Linux shared-library fixture is loaded only into the test requestor. Its
bounded outgoing-packet filter selects the initial two-question SRV resolver
query on IPv6 mDNS; ordinary publication/probe traffic passes through. The first
matching send returns ENETUNREACH and writes only scalar fault metadata. Later
calls use the real system function. The fixture is not enabled again on the
later simulated OTA boot. No administrator privilege, link manipulation, shared
service restart, clock acceleration or provider modification is involved.

The driver requires Idle/Failure before any peer QueryImage or download. It
repeats the provider announcement and explicit owner query, challenging the
unchanged first-failure guard. Actual node-relative StateTransition timestamps
must show at least120000ms from failure to the next Querying; the observer also
rejects recovery before119.5s, allowing its existing0.5s log-observation tolerance.
The120s backoff is existing implementation policy here; it is not claimed as a
universal Matter network-recovery deadline.

| Variant | Checks | Event failure-to-retry | Observer failure-to-peer-query |
| --- | --- | --- | --- |
| Normal native executable under Memcheck | PASS25/25 | 120020ms | 121.825s |
| Separate ASan/UBSan/LSan executable | PASS25/25 | 120027ms | 120.294s |

The requestor PID and commissioned state remain unchanged during recovery.
The provider also stays alive. The actual peer trace must bind a complete
authenticated CASE handshake to the encrypted QueryImage; both executions use
full CASE. This is stronger than inferring recovery from a scheduled retry or
changing SessionID alone. The first actual response offers version2.

Both runs then verify all16585 image bytes in17 blocks, EOF/AckEOF16, exact hash,
signature authentication, Apply/Notify token/version binding, live Applying
delivery, accepted simulated reboot and fresh CASE version2/BootReason
SoftwareUpdateCompleted readback. The only requestor restart is the accepted
simulated installation after network recovery; no recommissioning is used.

## Memory and verifier acceptance

Memcheck reports zero errors and zero live bytes/blocks across both native boots:
35914/35914 and19568/19568 allocations/frees. Its recorded command is the native
executable directly, not a Python launcher that could lose tracing across exec.
The separate sanitizer execution retains ASan/UBSan/LSan, including
`detect_leaks=1`, with empty native stderr and no sanitizer diagnostics. No GDB
or sanitizer-under-Valgrind combination is used.

The optional hook compiles with `-Wall -Wextra -Werror` and empty compiler output.
Its small control program passes36 checks per memory variant: packet-filter
boundaries, nonmatching traffic, marker isolation, exactly one injected failure
and a later real send. The control Memcheck has4 allocations/frees, zero errors
and zero live blocks; separate instrumented controls are clean.

Offline checks execute the actual public backoff-oracle body on the real
decoded trace and reject three mutated copies: early retry, missing failure
reason and missing Querying transition. The first helper attempt supplied raw
ANSI output; it was corrected to use the same normalization as `Client.text()`.
No public assertion was relaxed. Five invalid CLI combinations return2 before
creating a fixture, and Linux help succeeds. Local Windows help could not import
the optional Python cryptography dependency; no Windows execution claim follows.

## Scope and reproduction

The public changes are limited to the optional independent OTA driver, its
laboratory interposition fixture, the test map, host guide and campaign evidence.
All362 pre-existing tracked C/H inputs retain byte identity. Existing native
binaries retain their prior hashes; no new host build or CTest run is claimed.
The fixture C file is not a library/host build input. Instructions are in
[the host guide](../ota-host.md).

```text
gcc -shared -fPIC -Wall -Wextra -Werror -O0 -o build/network-fault.so tools/matter/tests/test_ota_network_fault.c -ldl
python tools/matter/tests/test_ota_chip_provider.py ... --mode query-network-recovery --network-fault-library <absolute-fault.so> --events --event-min-interval 5 --local-query --require-trace --apply-binding --bdx-profile --valgrind
# Separate sanitizer executable: omit --valgrind, add --asan-runtime <absolute-libasan.so>.
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

This proves recovery from the selected one-shot send failure, not replacement of
interface addresses, restored multicast membership or a fatal receive error.
The fixture's errno is deliberate; it does not retroactively identify CSA64's
uncaptured native error. CSA65's confirmed VM outage and historical functional
FAIL remain intact. Original TC_SU_2_2 FAIL607 and separate diagnostic608 are not
rerun or reclassified. Counts stay122 combined PASS/28 FAIL/5 prerequisites.

No stage processes remain. Paired Windows nodes and their fabrics, shared VM
interfaces and TH services remain untouched. Private logs/state/credentials stay
ignored. No full applicable-suite rerun, physical firmware installation or
certification is claimed.

Next: **CSA67**, a bounded resolver receive-error recovery check with first-result
capture, before changing production code. Use the existing public resolver API
and a process-local fault; do not disconnect the shared VM or repeat an already
attributed original test failure.
