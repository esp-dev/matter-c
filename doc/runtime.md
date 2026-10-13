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

Recovery of an interrupted commissioning journal is driven before protocol
processing. Admission remains gated until cleanup succeeds. Storage errors
preserve the recovery marker and context for a later retry. A partially built
instance with no submitted work releases its owned allocations; the previous
NULL Root/Admin deletion checks could prematurely stop this cleanup and were
fixed here. A failed Wi-Fi snapshot aborts the transaction without publishing.

OTA uses application sink/artifact callbacks; the library no longer opens the
image. The optional existing signed OTA journal remains a **simulation**.
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
