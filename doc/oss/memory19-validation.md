# Memory19: borrow RX queue bytes through delivery

Baseline: Memory18 committed as `64b9f49`. Existing API signatures, port layouts,
wire/checkpoint formats, quotas and application-owned scheduling remain intact.
Two additive optional RX functions expose a bounded payload loan.
These are laboratory results, not CSA acceptance.

## Ownership and deferred work

The dispatcher acquires `matter_rx_delivery_hold` inside the deliver callback,
copies only the small descriptor, and consumes the queue's actual payload after
`matter_rx_process` returns. After synchronous dispatch it clears its borrowed
pointer/size and calls `matter_rx_delivery_release`. The old RX-to-delivery
`memcpy` is gone. Handshake/server IM receive still copies its own pending request;
client result fields remain owned copies and BDX sink bytes are call-only views.
The existing RX admission copy still protects caller reuse of decrypted bytes.

The optional hold transfers the queue's existing session pin without a new
retain callback or allocation. Only the active deliver callback can acquire it,
exactly once; its descriptor remains call-only. Second receive while held returns
WOULD_BLOCK before policy/counters/pins change. ACK processing can continue,
but it cannot overwrite/redeliver bytes. The held key also blocks exchange close,
session retirement and stop/dependency drain. Retirement never clears held data.
Release after last use returns the queue pin once; repeat release is harmless.
Inline release and ordinary executor mutations remain BUSY. Existing users that
do not opt in retain their original callback-only borrowing and pin behavior.

Dispatch stays outside RX's callback/busy section so legitimate get/close/retire
operations remain available. The Memory18 runtime/dispatcher reentry guards are
retained. A handler's callbacks cannot recursively process/control that owner,
while disjoint received/sent events can still be queued. This owner-thread model
is not a mutex or a general guarantee for arbitrary callback/thread reentry.

TX plaintext stays independent of deferred/held RX. A slot waiting for ACK,
registry or exchange admission cannot prevent ordinary transaction preparation
and completion/drain work. Inbox, standalone ACK, secure control and immutable
MRP ciphertext retain their existing lifetimes; peer ACK cannot release a packet
still borrowed by UDP. Crypto still receives disjoint input/output buffers.
No limit or ACK deadline changes, new work allocation or resize is introduced.

## Copy, layout and stack measurement

One payload copy is removed per upper-layer delivery: up to 1226 B with the current
minimum six-byte protocol header and 1232-byte RX input ceiling. This is a reduction
in copying, **not a further fixed RAM saving** after Memory18's union. C6 DWARF
confirms both versions have dispatcher 5864 B, RX 3240 B, runtime 2352 B,
transaction 280 B and App 1592 B. RX's new state byte fits existing padding.
No extra resident/transient buffer, heap allocation or stack array is added.
The application image is 1311072 ->1311312 B (+240 B); this small flash cost is
separate from unchanged buffer RAM.

C6 compiler frames: hold 0 B, release 16 B, queued receive 32 B, RX process 32 B,
delivery 16 B, prepare 64 B, transaction process 144 B, ACK 80 B, dispatch body 160 B
plus wrapper 16 B and runtime body 48 B plus wrapper 16 B. These individual frames
are not complete task-call-chain or worst-case stack bounds. Actual task high
watermarks below cover the real C6 paths. Heap metrics already include reserved
SDK/task stacks; adding the owner stack reservation again would double count it.

## Regression and OOM coverage

`test_rx` now holds full-size input while the caller overwrites its source, rejects
another session's input without effects, checks the incoming ACK retry is applied
once, and probes close/retire/stop plus explicit/double release. Every payload byte
and both session references remain stable until release. All ordinary inline
mutations, including release, return BUSY; hold outside the callback/repeated hold
is rejected. Existing generic RX tests retain deferred ACK-sender contention,
original deadlines, duplicate/control/ephemeral handling, capacity and isolation.

The existing allocation variant is now native `test_rx_alloc`: all five constructor
OOM positions, 1000 allocation-free packet/ACK cycles and held full-buffer scenarios
with the next allocation forced to fail. The handoff/release path allocates nothing
and does not consume the armed failure. The test returns all tracked allocations.
`test_dispatch` uses the real RX slot/loan for full-buffer ownership, keeps premature
TX/reentry guards, queues a new UDP event during secure sealing, poisons scratch,
and confirms retained ciphertext through peer-ACK-before-UDP and drain. Real PASE
construction also probes recursive control calls while the payload is held.

Windows focused 4/4 plus RX allocation 1/1 and full CTest 102/102 pass. Linux normal
CTest 99/99 and separate ASan/UBSan/LSan CTest 99/99 pass, as do short/shared/full
snapshot component modes. Seven focused Memcheck cases (RX, RX allocation,
dispatcher, runtime/allocation, snapshots and short subscription workload) show
zero errors and zero heap at exit. Complete two-instance three-phase scenarios
pass 6/6 under Memcheck and separately sanitizers, including independent state,
CASE/subscriptions, active-A deletion with B live and both last-fabric responses.
Pair hosts exit 0 with empty stderr; Memcheck reports zero errors/live heap.

IDF 6.1 RGB/SOAK and default no-RGB/no-SOAK builds pass. Native/IDF compiler logs
contain no compiler warnings/errors. Inventory 257 mapped files /99 definitions /
59 core sources /75 public headers, diff whitespace check and Node syntax check
pass. Frozen VM compiled-source/test-manifest hashes match local code; the later
RGB-only retry change is validated separately by syntax and physical baseline/final
runs. Per-run oracle and image hashes distinguish those inputs.

## Physical C6 comparison

COM23, TL-MR3020, native IDF 6.1, the same RGB 171-attribute model and Wi-Fi-flash
profile. Baseline is the immutable copy of Memory18's final C6 run executed earlier
in this session. Its application flash hash was verified. Control attempts then
reflash that baseline to diagnose Read-resource Busy; final Memory19 updates only
application 0x50000 and verifies flash hash. NVS/partition layout are retained.
The full concurrency soak script is identical across compared runs. RGB's explicit
Busy retry is the only oracle difference, described below.

| Observation | Memory18 baseline | Memory19 |
| --- | ---: | ---: |
|Maximum sampled internal heap allocated|356980|356592|
|Allocation-event tracked peak|264412|264100|
|Minimum sampled heap free|60956|61396|
|Minimum sampled largest free block|35840|36864|
|Maximum observed allocated blocks|1052|1064|
|Maximum observed free blocks|88|96|
|Observed owner stack used /12288 B reserved|2696|2760|
|SDK failed allocation attempts|0|0|
| Final tracked live allocations / bytes |0 /0|0 /0|

The fixed resident RAM delta is 0 B. Sampled/tracked peaks vary with asynchronous
allocation overlap, transient requests and recovery; these observations do not
establish a causal heap saving from removing a memcpy. Largest block/counts are
sampled observations, not an exhaustive fragmentation percentage. Sampling is
100 ms and can miss shorter peaks; SDK lifetime minimum is retained in final
memory records. These short load/recovery tests are not a new hour of endurance
or a specification-wide RAM bound.

The compared load windows are 274.8 /
283.4 s. Each runs five fabrics, 15 protected
CASE sessions/subscriptions, 71 /76 full Reads of 171 attributes, an excess-session Busy
probe, tracked OOM position 1, three-second RX loss, actual radio reconnect and
held accepted-TX stop/drain. Healthy operation errors/unexpected subscription
closures/SDK allocation failures are zero; deliberate OOM losses/rebuilds are
counted in the results. Both finish RUNTIME_PASS, zero tracked allocations/bytes
and successful SDK heap integrity. Actual diagnostics-callback reentry is rejected
on the final C6. Stop/drain waits are 3.73 /
3.80 s; the stopped controller Read timeout
is expected and recorded.

Four fixture fabrics are removed with acknowledged replies; the original fabric
and label are restored. The final runtime is stopped and COM23 released. Original
Windows Wi-Fi state (disconnected), temporary-profile removal and private XML
removal are restored; IPv6 remains enabled. AP configuration is unchanged.
Private states/keys, full flash backup and raw logs remain ignored.

## Intermediate failures and controller correction

The first Memory19 RGB attempt fails on explicit Busy(156) at two parallel concrete
Readbacks in one fabric. The one-active-Read budget is unchanged. Its UART is
subsequently stopped/drained successfully; original failure/cleanup logs remain.
Two baseline probes do not reproduce that race: 40 ordinary pairs finish both
reads; a small pair with held UDP completion also finishes both. These probe
expectation failures are retained, not counted as passing reproductions.

The next unchanged-Memory18 control runs a full wildcard Read concurrently with
a concrete Read: one succeeds and one receives Busy(156). This confirms the same
resource response exists before the RX change. The RGB oracle now retains its
parallel readback but retries only this explicit status, at most ten attempts
with bounded 100–500 ms delays; wrong values, timeouts and other errors still fail.
Retries are logged/counted. The modified RGB passes on Memory18 and Memory19;
final normal RGB consumes 0 retries. The full soak's
healthy-error accounting is unchanged. Development attestation and unknown-session
controller warnings remain visible. No Matter quota is widened to satisfy a test.

## Commands and review scope

```sh
cmake --build build/memory16/windows-gcc -j4
ctest --test-dir build/memory16/windows-gcc --output-on-failure
python tools/matter/check_test_map.py
node --check examples/esp32-runtime/tests/rgb.mjs
cmake -S source -B source/build/memory19-normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<existing-mbedtls> -DMATTER_SANITIZE=OFF
cmake --build source/build/memory19-normal -j3
ctest --test-dir source/build/memory19-normal --output-on-failure
# Separate build: MATTER_SANITIZE=ON
# ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
# UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <ordinary-test-or-pair-host>
# From examples/esp32-runtime, native PowerShell wrapper:
& D:/Work/ww/.tools/idf-v6.1.ps1 -B D:/Work/ww/matter-c-memory/build/memory16/idf61-rgb build
& D:/Work/ww/.tools/idf-v6.1.ps1 -B D:/Work/ww/matter-c-memory/build/memory16/idf61-default build
```

Physical commands run esptool app-only writes, UART reset/capture, RGB and
`soak.mjs ...180 ...run wildcard` with 171 expected attributes. Exact arguments,
raw outcomes and failed/control runs remain under ignored build/memory19; source,
image, oracle, layout and checkpoint data are in [results](memory19-results.json).

`matter_rx.c/.h` add optional loan state/lifetime barriers; `matter_dispatch.c/.h`
consume/release that loan instead of copying. `test_rx.c`/`test_dispatch.c` and
the CMake/test-map registration prove ownership, OOM, deferred ACK and reentry.
`rgb.mjs` handles the existing Read-resource response explicitly. README, runtime
contract, inventory/status and report/results document these contracts/evidence.
The RGB model remains incomplete; no commercial-controller, full light profile,
routed IPv6, strict attestation or CSA certification result is claimed.

Next: audit secure-decrypt scratch -> RX admission for a reserve/authenticate/commit
path that could eliminate another temporary allocation/copy while preserving
failed-authentication, replay and ACK/admission atomicity.
