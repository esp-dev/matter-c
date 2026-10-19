# CSA56: host UDP receive starvation repaired

A real native defect is repaired: continuous outgoing traffic could prevent the host from receiving peer ACKs. All four five-fabric scenarios now pass under Memcheck and separately ASan/UBSan/LSan: **399 checks per variant**, four fresh-store lifetimes each, 15 simultaneous subscriptions. [Evidence](csa56-results.json). Original **TC-IDM-7.1 remains FAIL, run494**, for its final overflow-status example; source, support and PICS remain unchanged.

## Cause and smallest change

Both Linux and Windows pollers used `if pending TX completion ... else receive`. Under a continuous MRP report/retry backlog every call only completed TX. Instrumented reproduction records 15 MRP timeouts and matching live-subscription disposals. Two earlier receive errors and disposals concern different exchanges; there are no process errors. Thus this failure is not evidence that the attribute version cache lost a dirty update. Temporary diagnostics remain outside Git and the previous baseline binary is restored.

A poll now handles at most one completion **and** one datagram, preserving application-owned, bounded nonblocking scheduling. Completion errors still defer RX; empty RX retains completion success. Shutdown, callback reentry, exclusive sockets and packet validation remain unchanged. No portable-core API, quota, timer or buffer size changes. The host header documents the corrected contract.

The existing real IPv6 test adds 32 consecutive bidirectional rounds with pending TX on both endpoints: old Linux backend fails its first same-poll RX assertion; fixed Linux and Windows pass. Initial Windows tester setup incorrectly tried a wildcard-source send without the known interface; corrected to the existing received reply path before acceptance. Allocation-failure/lifecycle/reentry regressions remain included.

The actual-controller fixture additionally requires a changed Identify DataVersion. An old queued positive countdown no longer satisfies a new action. Baseline current host still fails under Memcheck; corrected host delivers NodeLabel, Location and genuine Identify changes to all 15 subscriptions in both rounds of all four scenarios, including overflow and a separately authenticated node2 in the same fabric.

## OTA recovery attribution

CSA45's no-new-QueryImage observation is explained by its trigger: after image handoff the query policy retains a daily due time, while same-provider `UpdateAvailable` reason1 uses the next scheduled query. Its 240-second wait therefore ends before a new CASE attempt. Core1.6.1 11.20.7.4,11.20.3.2 and11.20.3.5 support retaining the schedule and 120-second query floor. Do not shorten them to satisfy that observer.

Existing query unit/allocation tests gain explicit image-handoff controls: reason1 remains quiet through the earlier cutoff and starts at the daily boundary; SimpleAnnouncement can trigger this implementation earlier while retaining 120s. These are virtual-clock policy tests, not proof of recovered BDX. Original run481 FAIL remains. CSA57 will use an explicitly selected recovery trigger and verify the real stalled-transfer/restart sequence.

## Validation and remaining boundary

Seven focused Linux CTests per build pass, including UDP, Subscribe and Query allocation variants; two Windows UDP CTests pass. No observed compiler warnings. Full final Memcheck lifetimes have equal allocations/frees, zero errors/live bytes; separate final ASan/UBSan/LSan lifetimes exit 0 with empty stderr. An earlier sanitizer attempt passed functionally but was superseded because a rebuild refreshed host build-floor identity between boots; the final full run uses a frozen binary copy. Executed binary digests are recorded per receipt rather than substituted with later relinked artifacts.

The original manual TH rerun accepts the repaired load scenario. Its final example still expects InvalidAction80 for an excess subscription, whereas the full-quota node returns ResourceExhausted89 and retains the original15. This literal discrepancy remains open for CSA clarification; functional acceptance is not relabeled an original PASS.

Changed files: both host UDP adapters and their header, existing bidirectional UDP test, subscription fixture/oracle, query policy regression, inventory descriptions and campaign reports. Inventory, campaign consistency, links/privacy and diff checks executed. No full-matrix, physical/radio, Home UI, embedded RAM-fit or deferred multi-hour DGGEN test. No push.

Counts unchanged:99 automatic PASS/18 FAIL/1 BLOCKED; manual24 PASS/9 FAIL/4 BLOCKED;707 NA. Total123 PASS/27 FAIL/5 prerequisites. Next:CSA57, actual BDX recovery with a suitable explicit trigger.
