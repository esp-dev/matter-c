# Runtime ownership and application callbacks

## Callback and lifetime contract

Allocate the configuration in application-owned storage; large configurations
and persistent images should not be placed on an embedded task stack.

1. Prepare one mutable backend set per node: crypto/credential ports, atomic
   TLV blob, Wi-Fi port and its initialize/process/observe callbacks. Supply
   identity, attestation DER spans, DAC scalar, UTC, Matter-epoch timestamp,
   regulatory check, diagnostics interface and optional logging/update journal.
2. `matter_runtime_new(config,pin,now)` copies descriptors and identity; the
   operational credentials backend copies the DAC scalar. DER spans and all
   callback users remain borrowed. The caller may erase its scalar after new.
   Wi-Fi initialize stages restored settings synchronously and retains no
   pointers/work on failure. It must not start an untracked radio operation.
3. Attach application endpoints/clusters to `matter_runtime_root()`. Create
   caller-owned lifecycle/UDP/events, using the runtime store for persistent
   event allocation and EEM checkpoints. Optional resolver, outbound route,
   test-trigger and OTA sink are explicit. mDNS remains application-driven via
   the existing discovery ports and runtime fabric/window accessors.
4. Start once. Pump UDP/resolver/radio and call `matter_runtime_process(now)`
   from the same application thread. All instances may share that thread.
   Completion callbacks only enqueue/copy into their own instance. There is no
   implicit scheduler. Callbacks must not reenter the same runtime.
5. On shutdown or failed start, stop and drain while keeping borrowed adapters
   alive. `PENDING` does not authorize freeing. Successful stop is terminal;
   delete runtime before freeing its callback users, crypto, blob or journal.
   External clusters/events remain caller-owned. Recreate a fresh instance to
   restart; it reloads only its own persisted blob.

Strict operational certificate validation reads the supplied UTC callback at
verification, not a cached construction time. The explicit CHIP validity
profile still waives only validity dates, preserving signatures/root/identity.
The host retains its DAC-derived UniqueID behavior; generic runtime preserves
the caller's UniqueID. Event time uses the latest supplied monotonic time.

General Diagnostics uses the runtime's live dispatcher statistics. Successfully
completed local IM sends and admitted incoming IM messages are counted once;
MRP retries, standalone ACKs and CASE/BDX traffic do not inflate these counters.
An exhausted MRP retry sequence on an outbound operation retires only that
peer's operational session, through the existing drain lifecycle. A later
operation establishes CASE instead of reusing keys forgotten by a restarted
peer. The failed operation is still reported as failed; it is not silently
replayed. ACKs, explicit cancellation, local send errors, inbound transactions
and unsecured handshakes do not trigger this retirement policy.
Subscription reservations are not active subscriptions: successful local delivery
of SubscribeResponse establishes one, and cancellation/removal excludes it from
the current count while preserving the lifetime total. Counts are per runtime,
with separate current totals for the accessing fabric, and saturate at their
wire type limits. PASE subscriptions contribute only to the node total.

## Subscription resource budget

Set `identity.capabilities.subscriptions` before `matter_runtime_new()`. It is
both the Basic Information CapabilityMinima guarantee and the dispatcher's
per-fabric admission limit; there is no separate hidden three-subscription cap.
The existing default initializer still selects three. Core permits 3..10000,
but this host composition also requires enough compiled transport slots.
`matter_host_transaction_capacity()` validates both bounds. Runtime construction
rejects an impossible configuration before calling platform initialization.
Direct dispatcher construction reads the immutable budget from Root through
`matter_root_capabilities()` and applies the same guard.

The dispatcher allocates one transaction table sized for the selected budget,
including every fabric/PASE bucket and protected Read, replacement, response
drain, Invoke/Write, handshake and rejection capacity. With five fabrics it needs
`6 * subscriptions + 34` slots: three needs 52, eight needs 82. The table remains
at stable addresses until successful drain/delete; it is not reallocated during
protocol callbacks. IM Subscribe handlers and their request data still allocate
on demand. This is a bounded allocation at construction, not an unbounded or
automatically growing pool. Table allocation failure releases the dispatcher
context; failed subscription admission leaves existing subscriptions intact.
`KeepSubscriptions=false` retains its verified fabric/node replacement scope.

Each instance owns its own budget/table. Change the budget by stopping/draining
and constructing a new instance; it is not a live mutable attribute. The shared
transport ceiling remains a build option (`MATTER_TRANSPORT_CAPACITY`, 8..128);
this change does not migrate the lower transport tables to dynamic storage.
The default build's 56 slots support the original budget of three; a 128-slot
build supports budgets through fifteen. These are implementation limits, not
Matter's maximum. Existing wire/storage schemas and default admission stay intact.

The host exposes `--subscriptions-per-fabric N`, validates it before opening the
node, and advertises the chosen value. For example, configure with
`-DMATTER_TRANSPORT_CAPACITY=128` and launch with `--subscriptions-per-fabric 8`.
Other CLI options, credentials and state paths remain unchanged.

## Request storage

Read and Subscribe allocate DataVersionFilters for the exact validated entry
count in each request. Empty/absent lists allocate nothing; Read owns the table
until deletion, while Subscribe frees it after priming or on error/cancel/delete.
The previous 16-entry cap was an implementation limit, not a Matter limit.
Read/Subscribe accept up to 1202 application bytes, derived from the secure UDP
packet ceiling minus the 8-byte message header, 16-byte MIC and minimum 6-byte
protocol header (Core 4.4.4). Actual optional headers reduce the wire budget and
are checked by framing/transport. Each accepted receive allocates its actual
length before freeing the old copy; failure returns LIMIT_REACHED without queue
mutation. Its owner can retry. Output is allocated at construction according to
output_capacity, now up to 1198 bytes: reserve four additional bytes for an MRP
ACK. The host dispatcher selects this output budget for Read/Subscribe. Both
buffers are released with the handler. The defensive filter entry bound derives
from the minimum 14-byte concrete DataVersionFilterIB encoding.
Both decoders allow enough TLV tokens for any request within that byte budget.
Filter allocation failure produces ResourceExhausted without reserving a subscription
or reading values. See [regression results](oss/im-version-filters-validation.md).

The UDP ceiling remains 1280 bytes including IPv6/UDP headers. Enlarging heap
buffers does not authorize larger UDP packets. Invoke, Write, the outbound IM
client and other result/transport tables retain their separate budgets; migrating
those is subsequent work, with interoperability tests after each subsystem.

Read/Subscribe expanded attribute results now grow on the heap per interaction,
starting at nine entries and doubling up to the 512-entry application ceiling.
That ceiling is not a Matter protocol maximum. A full-tree Read of the metered
socket profile reproduced ResourceExhausted with the former 320-entry table.
Read also allocates its chunk plan from the output budget (capacity / 8 + 1,
a conservative structural TLV lower bound). No unused full-size result table
is embedded in either handler. Allocation failure returns ResourceExhausted;
the owner retains old allocations until cleanup, then releases all entries.
Subscribe retains its result table until deletion. Snapshot, value, selector
and UDP budgets are unchanged. See [acceptance](oss/plug-energy-validation.md).

TimeSnapshot reads UTCTime from the actual Time Synchronization cluster attached
to Root and converts Matter-epoch microseconds to POSIX milliseconds. The
application must process its external clock cluster with the same monotonic tick
before `matter_runtime_process(now)`. No cluster or a null UTCTime produces a
null PosixTimeMs; a certificate Last Known Good time is not synchronized UTC.
SystemTimeMs continues to use the event clock supplied by the application.
The diagnostics snapshot adds `unfabric_subscriptions` (zero by default) for
unscoped subscriptions. Rebuild consumers against the updated public headers;
the persistent TLV format and on-wire cluster schemas are unchanged.

Recovery of an interrupted commissioning journal is driven before protocol
processing. Admission remains gated until cleanup succeeds. Storage errors
preserve the recovery marker and context for a later retry. A partially built
instance with no submitted work releases its owned allocations; the previous
NULL Root/Admin deletion checks could prematurely stop this cleanup and were
fixed here. A failed Wi-Fi snapshot aborts the transaction without publishing.

OTA uses application sink/artifact callbacks; the library no longer opens the
image. The optional existing signed OTA journal remains a **simulation**.
`Matter_Runtime_Ota_Port_T.discard` is an optional synchronous callback for
Discontinue, receiving the same candidate artifact ID. It must dispose only of
that downloaded candidate, never installed firmware. The runtime logs a cleanup
failure, revokes candidacy and stays Idle even if disposal fails. Without the
callback, disposal remains the application's responsibility (Core 11.20.3.6
SHOULD). The file host supplies it; logical `invalidate` alone still preserves
accepted images for laboratory inspection. Rebuild consumers for the appended
port field and zero-initialize optional callbacks. No persistent or wire schema
changes. Response-receipt and simulation-gate logs include the supplied monotonic
tick, allowing real delay verification without changing the application clock.
Once started, the runtime declares OTA Requestor `0x0012` rev1 alongside Root
Node: its Requestor server and Provider client are exposed regardless of whether
the application currently supplies an OTA sink/journal. Descriptor presence does
not promise that an update can be applied now; the existing UpdatePossible and
download/application gates retain that distinction. CSA03 corrects the former
conditional omission of this device type without enabling update capabilities.
This stage does not implement a production bootloader or change its signature
format. Persistent blob operations remain synchronous and atomic; an MCU port
must schedule them within its own latency budget. No ESP32/NVS claim is made.

Committed fabric removal and rollback notify Administrator Commissioning before
index reuse. The runtime clears only AdminFabricIndex for the opening fabric;
WindowStatus, its original deadline and AdminVendorId remain intact until the
window closes. Failed persistence does not publish this notification. The optional
`Matter_Fabric_Host_Events_T.removed` callback runs synchronously on the owner
thread and must not reenter the fabric adapter; callback users remain borrowed.

The runtime closes its initial or enhanced commissioning window after 20 failed
PASE attempts. Protocol/peer failures and timeouts count once per admitted
attempt; packet duplicates and explicit local cancellation do not. A new enhanced
window resets the counter and advances its epoch, so an older attempt cannot
consume the new window's budget. Admission closes immediately at the limit;
the next owner process pass clears the Admin window and drives discovery
withdrawal. CASE administration remains available. This counter currently covers
PASE failures; later-stage commissioning failures need separate acceptance.
Custom PASE owners can install `matter_pase_on_failure` before starting an attempt
and must keep its borrowed callback context alive through engine deletion.

An optional `Matter_Runtime_Ota_Port_T.progress` callback supplies active download
percentage (-1 unknown, otherwise 0..100) on the owner thread. It must not block,
perform I/O or reenter the runtime. The runtime normalizes out-of-range values to
unknown and marks the Requestor cluster changed only when the integer percentage
changes. The file adapter uses validated size/received counters; the portable
runtime knows no file path. Rebuild consumers and zero-initialize absent optional
fields. See the [OTA host contract](ota-host.md).

Descriptor, Basic Information and General Commissioning use their existing
DataVersion for subscription change reporting. Unrelated application measurement
notifications no longer repeat unchanged built-in values. Reads still return the
current value and subscriptions still recheck access and send heartbeats. The
attribute-only subscription selector budget is 32; mixed attribute/event requests
retain the existing nine-path guarantee. Chunk size, collection work per process,
expanded-result and snapshot limits remain independently bounded.

Read and Subscribe validate attribute path grammar before model callbacks or
subscription reservation. A specific attribute without a concrete cluster must
be global: the full ID is in `0x0000F000..0x0000FFFE` (Core 1.6.1 sections
7.21.2.2 and 8.9.2.6). A manufacturer-prefixed ID with the same suffix is not
global. An invalid path rejects the entire request with `InvalidAction`, even
when earlier paths are valid. A syntactically valid path still undergoes normal
existence and access checks; wildcard omission, concrete path statuses and
DataVersionFilters are preserved. Existing Node/ListIndex/tag-compression and
nonzero provisional wildcard-flag limitations remain unchanged.
