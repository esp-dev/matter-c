# Memory18: delivery/plain storage shared across phases

Baseline: Memory17 committed as `b122565`. This change preserves public API
signatures, wire/checkpoint formats, all existing quotas and application-owned
scheduling. Laboratory results are
separate from CSA acceptance and certification.

## Phase and ownership audit

One private union replaces two 1232-byte dispatcher arrays. RX owns delivery
until synchronous `dispatch` returns; the delivery pointer/size is then cleared
before any transaction composes TX plaintext. Both private TX entry points also
refuse work while delivery remains active. Each runtime owns its own storage;
there is no shared global buffer, new allocation, resize or new OOM site.

| Handler | Input after synchronous receive returns |
| --- | --- |
| PASE/CASE | Copied into the existing phase-owned handshake input |
| Server Read/Subscribe/Invoke/Write | Copied into the handler's existing request storage |
| Invoke client | Parsed synchronously; returned fields are copied into owned result bytes |
| BDX | Sink open/write/finish completes synchronously; write only borrows bytes during its callback |

The input UDP inbox, deferred RX-service bytes, standalone ACK, secure control
packet and immutable per-transaction ciphertext retain their separate storage.
Secure seal still receives disjoint plaintext/output; the crypto port contract
is unchanged. A peer ACK, cancellation or timeout cannot release ciphertext still
borrowed by UDP. Existing retain/retry, actual completion and drain gates remain.
Snapshot bytes/records and their independent ACK/status gates are unchanged.

Recursive dispatcher process/stop/delete and outgoing start/take return BUSY
before mutation or allocation. RX/sent notifications may enqueue their disjoint
events. Retirement, change and cancellation notifications remain usable by the
existing Root/fail-safe and OTA paths. The runtime also rejects process/stop/delete
inside an active process callback before changing clocks/models. Every process
exit clears its guard, including error and recovery paths. This is an owner-thread
guard, not a mutex, general callback-reentry guarantee or thread-safety extension.
Stop/delete callbacks outside an active process retain their existing contract.
An independent runtime may be processed by a callback on the same owner thread.

## Layout, allocation and stack

Linked C6 DWARF measures dispatcher **7096 ->5864 B**, saving exactly **1232 B per
instance** from its existing allocation, in idle and active phases. Runtime stays
2352 B, transaction 280 B and the SOAK/RGB App 1592 B; guard/probe booleans fit
existing padding. Packet limits, allocation counts and allocator-size ceilings
are unchanged. Host dispatcher is 6368 B; allocation tests verify its size as the
idle requested-byte total and keep transaction/TX OOM and nonce checks intact.

C6 compiler frames are delivery 16 B, prepare 64 B, transaction process 144 B,
ACK 80 B, dispatch body 160 B plus public wrapper 16 B, and runtime body 48 B plus
wrapper 16 B. No packet/value array moves onto the task stack and no RTOS stack
reservation changes. These individual frames are not a complete call-chain bound.
Physical high watermarks below include real callback/crypto/network paths and
the optional SOAK reentry probe. Heap statistics already include reserved SDK/task
stacks; adding the reported reserved stack again would double count it.

## Physical C6 comparison

Consecutive runs use COM23, TL-MR3020, IDF 6.1, identical RGB/SOAK/Wi-Fi-flash
configuration and the same pinned Matter.js 0.17.9 RGB/concurrency oracles. The
Memory17 binary matches the backed-up flash application byte-for-byte before
baseline execution. Final flashing updates only application 0x50000, retaining
partition layout/NVS. Each run restores the original fabric and label, removes
the four fixture fabrics with acknowledged replies and leaves the runtime stopped.

| Observation | Memory17 baseline | Memory18 |
| --- | ---: | ---: |
|Maximum sampled internal heap allocated|357584|356980|
|Allocation-event tracked peak|265272|264412|
|Minimum sampled heap free|60368|60956|
|Minimum sampled largest free block|35840|35840|
|Maximum allocated blocks at SOAK observations|1034|1052|
|Maximum free blocks at SOAK observations|85|88|
|Observed owner stack used /12288 B reserved|2728|2696|
|SDK failed allocation attempts|0|0|
| Final tracked live allocations / bytes |0 /0|0 /0|

Observed sampled heap saving is 604 B;
tracked peak saving is 860 B. The deterministic
structure saving is 1232 B; whole-device peak differences also reflect asynchronous
allocation overlap, sampling and recovery timing. Block counts/largest free block
are observations, not a platform-independent fragmentation percentage. Sampling
is 100 ms and can miss shorter peaks; the SDK lifetime minimum is retained in the
machine-readable final memory records. These short tests are not a new hour of
endurance or a specification-wide worst-case RAM bound.

Both runs complete 71 full Reads of 171 attributes, five fabrics, 15 protected CASE
sessions/subscriptions, an excess-session BUSY probe, tracked OOM position 1,
three-second RX loss, actual radio reconnect and held accepted-TX stop/drain.
Healthy operation errors/unexpected subscription closures and SDK allocation
failures are zero. OOM ends one subscription in each run and the oracle rebuilds
the full load. Reconnect falls after the timed window in both runs. Actual
load/recovery windows are 273.2 /
274.8 seconds; stop/drain waits
3.64 /3.73 s.
The stopped in-flight controller Read's timeout is expected and recorded.
`REENTRY_PASS` confirms recursive process/stop/delete rejection from the final
C6 network diagnostics callback. Both runs finish `RUNTIME_PASS`, zero tracked
live bytes/allocations and successful SDK heap integrity checks.

Original Windows Wi-Fi state (disconnected) is restored; the temporary profile
and its private XML are removed. IPv6 remains enabled as requested, COM23 is
released and AP configuration is unchanged. Backups, keys, credentials, device
state and raw logs remain ignored. The RGB model is still an incomplete
experimental light; this run makes no full light, attestation, routed IPv6,
commercial-controller or CSA conformance claim.

After this stage's cleanup, Wi-Fi is reopened for the user-requested Memory19
continuation and to fetch the final focused logs: disconnecting had removed the
SSH route to the VM. That fetch succeeds after reconnect; test outcomes are
unchanged. The cleanup record describes the completed Memory18 stage.

## Verification and commands

- Windows focused dispatcher/runtime/allocation tests 3/3, then full CTest 101/101.
- Linux normal CTest 98/98 and separate ASan/UBSan/LSan CTest 98/98; short/shared
  snapshot and full-profile component modes also pass in each build.
- Five focused Memcheck cases: snapshots, short subscription allocation workload,
  dispatcher, runtime and runtime-allocation faults. All report zero errors and
  zero live heap at exit. Separate program/tool logs replace an initially mixed
  log stream; original successful runs are retained too.
- Complete two-instance, three-phase host/controller scenario6/6 under Memcheck
  and separately sanitizers. Independent state, CASE/subscriptions, Identify/UTC,
  active-A teardown with live B and both last-fabric responses pass; pair exit 0,
  empty stderr, Memcheck zero errors/live heap.
- IDF 6.1 RGB/SOAK and default no-RGB/no-SOAK builds pass. Compiler logs contain no
  compiler warnings/errors for these builds or the native host builds.
- Inventory 257 mapped files /98 native definitions, `git diff --check`, source
  hash comparison between local checkout and VM test inputs, ELF layouts and
  final binary hashes checked. No test registration/source inventory changed.

Commands (local paths/logs under ignored `build/memory18`):

```sh
cmake --build build/memory16/windows-gcc -j4
ctest --test-dir build/memory16/windows-gcc --output-on-failure
python tools/matter/check_test_map.py
cmake -S source -B source/build/memory18-normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<existing-mbedtls> -DMATTER_SANITIZE=OFF
cmake --build source/build/memory18-normal -j3
ctest --test-dir source/build/memory18-normal --output-on-failure
# Separate build with MATTER_SANITIZE=ON:
# ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
# UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <ordinary-test-or-pair-host>
# From examples/esp32-runtime with ESP-IDF6.1 activated (machine paths normalized):
idf.py -B ../../build/memory16/idf61-rgb build
idf.py -B ../../build/memory16/idf61-default build
```

The physical wrapper runs `esptool write-flash ...0x50000`, UART capture/reset,
`rgb.mjs`, then `soak.mjs ...180 ...run wildcard` with 171 expected attributes.
Exact command arguments, hashes, layout/frame data, checkpoints and physical
results are retained in [machine-readable evidence](memory18-results.json) and
ignored local/VM logs. Secrets are not included in public evidence.

The first extended test attempt failed on fixture isolation: the new real BUSY
exchange increments diagnostic counters, and nested independent-runtime process
adds one legitimate pump. Tests now reset their own counters/expect that pump;
product semantics were not changed to satisfy those assertions. The first full
flash backup at 460800 baud failed on a short serial block (4095/4096 bytes);
read-only retry at 230400 succeeded before flashing. No failure is relabeled as a
successful attempt. Development attestation/unknown-session controller warnings
remain visible in raw logs.

## Files and next task

`matter_dispatch.c/.h` implement/document phase ownership and reentry;
`matter_runtime.c/.h` guard the enclosing clock/model processing;
`app_main.c` adds the SOAK-only physical callback probe. `test_dispatch.c` and
`test_runtime.c` exercise overwrite, nested calls, independent instances and
lifetime/error paths. README, runtime contract, status/test inventory and this
report/results make the new ownership contract and measured limits reviewable.
No port/API signature, CMake default, Matter limit or persistence schema changes.

Next: audit the lifetime/copy of admitted RX-service bytes versus delivery,
including deferred ACK/admission and OOM, before changing that ownership contract.
