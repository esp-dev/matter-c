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
This stage does not implement a production bootloader or change its signature
format. Persistent blob operations remain synchronous and atomic; an MCU port
must schedule them within its own latency budget. No ESP32/NVS claim is made.
