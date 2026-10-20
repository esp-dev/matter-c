# CSA67: host resolver recovery after a fatal receive error

Starting commit `7d016ea`, clean tracked tree. This step reproduces a native host
backend defect and repairs it: a fatal receive error permanently latched the
resolver offline, even after the original error was gone. Full independent OTA
and memory acceptance now pass. [Receipt](csa67-results.json) retains old-library
failures, source fingerprints, positive outcomes and limits. No original CSA
test/helper/PICS or campaign verdict is changed.

## Reproduction and minimal repair

The process-local fixture lets the initial operational DNS query be sent, then
returns ENETDOWN exactly once from `recvmsg()` on that resolver socket. It does
not fail publication sockets, stop a provider, modify the physical interface or
change the application clock.

The public-API probe queues four jobs. The receive error completes all four as
FAILED, preserving answer output bytes. After collecting them, the old resolver's
next valid start returns OFFLINE8 with unchanged caller ID. There is no path to
clear its offline flag. Both the initial reproduction and the final probe linked
against the old archives retain functional FAIL; their Memcheck reports zero
errors/live blocks. The old backend source matches the starting commit. The
final probe source is the same one used against the repaired archives.

The shared Windows/Linux host adapter now attempts to reopen its two sockets
when the owner submits a new valid query with available capacity. Existing
`open_sockets()` already handles partial failure by closing created sockets.
Only a successful reopen clears offline. Failed reopen claims no job/ID and can
be tried again by a later owner request. Old terminal results remain available;
their slots must still be collected before capacity can be reused.

No thread, background retry, timer, large buffer, new application heap allocation
or core-library dependency was added. Query deadlines, cancellation, serial IDs,
caller-owned polling and the OTA retry policy stay unchanged. The backend still
uses its configured interface/address snapshot; local address rediscovery is
outside this repair. Host API symbols and layouts are unchanged.

## Focused and full acceptance

| Scenario | Normal / Memcheck | Separate ASan/UBSan/LSan |
| --- | --- | --- |
| Receive failure, four terminal jobs, same-object reopen | PASS33 checks | PASS33 checks |
| IPv4 reopen EMFILE after IPv6 creation, then successful retry | PASS35 checks | PASS35 checks |
| Full same-instance CASE and signed simulated OTA | PASS25/25 | PASS25/25 |
| Discovery/mDNS/runtime/query CTests including allocation variants | PASS8/8 | PASS8/8 |
| Existing send-fault fixture controls | PASS36, plain control process | PASS36 checks |

The API probe checks capacity rejection, failed-result/answer preservation,
wrong-interface rejection, fresh IDs after recovery, busy deletion, cancellation
and stale-ID rejection. The partial-open fixture actually records both recvmsg
ENETDOWN100 and socket EMFILE24; it then permits a successful reopen. Each normal
probe reports15 allocations/frees, zero errors and zero live blocks. Sanitized
probes finish without diagnostics.

An extra `--track-fds=yes` partial-open run finds no resolver sockets or fault
marker descriptor left at exit. Its raw total is **four open descriptors**:
three standard streams and one diagnostic log explicitly reported as inherited
from Valgrind's launcher. That inherited logging FD is retained in the evidence,
not described as zero open descriptors. Heap and error summaries are clean.

Full OTA injects only the receive failure, challenges backoff with a repeated
announcement/local request, then requires authenticated full CASE bound to the
encrypted QueryImage. The same requestor and provider stay alive during recovery.
Actual event failure-to-retry intervals are120022ms normal and120031ms sanitized;
observer failure-to-peer-query times are122.044s and120.230s. The existing120s
first-failure guard remains real; no timing is accelerated.

Both executions verify16585 image bytes in17 BDX blocks, EOF/AckEOF16, exact hash,
signature authentication, bound Apply/Notify token/version, live Applying before
stop, accepted simulated reboot, fresh CASE version2 and SoftwareUpdateCompleted.
The only requestor restart is the later accepted simulated installation.
Two normal OTA boots have35874/35874 and19565/19565 allocations/frees, zero
Memcheck errors and zero live bytes/blocks. The separate sanitized OTA retains
ASan/UBSan/LSan with `detect_leaks=1`, empty native stderr and no diagnostics.

Both complete Linux targets were built from an isolated clean source export,
using the existing pinned official mbedTLS. Configure/build/probe logs contain
no warning/error lines; the hook/probes also compile with `-Werror`. Six focused
CTests plus the two directly affected discovery/parser tests ran per build.
The core library C/H inputs are unchanged. Native host changes are confined to
the resolver's start path and its header contract; other C changes are fixtures.

## Commands and boundaries

Use the optional public-API probe and fault environment documented in
[the host guide](../ota-host.md). Full acceptance adds
`--network-fault-kind receive` to the existing query-network-recovery scenario:

```text
python tools/matter/tests/test_ota_chip_provider.py ... --mode query-network-recovery --network-fault-kind receive --network-fault-library <absolute-fault.so> --events --event-min-interval 5 --local-query --require-trace --apply-binding --bdx-profile --valgrind
# Separate sanitizer executable: omit --valgrind, add --asan-runtime <absolute-libasan.so>.
ctest --test-dir <build> -R '^(test_discovery|test_discovery_alloc|test_mdns|test_mdns_alloc|test_runtime|test_runtime_alloc|test_ota_query|test_ota_query_alloc)$' --output-on-failure
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
git diff --check
```

This confirms a receive-error recovery defect independently; it does not identify
the native errno of CSA64's historical VM outage. Original TC_SU_2_2 FAIL607,
separate injected-loss608 and the earlier functional sanitizer FAIL remain
preserved. Counts stay122 combined PASS/28 FAIL/5 prerequisites. There is no new
original CSA result, Windows compilation/execution, actual interface/address
replacement, full applicable-suite rerun or physical firmware/bootloader claim.
This remains signed host-simulation OTA, not certification.

All stage processes have stopped. Paired Windows nodes/fabrics, shared interfaces
and TH services were not changed. Raw logs, credentials and host-specific paths
remain ignored; public receipts include sanitized summaries and fingerprints.

Next: **CSA68**, review the remaining automatic TC_SU_2_5 failure using existing
CSA20/23/53 evidence and the unchanged installed test. Check prior attribution
before proposing a fixture or native change; rerun only after a verified
prerequisite changes, rather than repeating a known long failure blindly.
