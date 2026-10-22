# Memory20: one Read/Subscribe encoding area per dispatcher

Date: 2026-10-22 UTC. Baseline: Memory19 commit `95bbb14`. Changes remain
uncommitted for review. Both compared C6 runs use IDF6.1, unchanged sdkconfig,
RGB EP1/171 attributes, the same controller versions and identical corrected
oracles. Raw state, flash backup, binaries and logs remain ignored under
`local/esp32-c6/` and `build/memory20/`. Public metrics: [JSON](memory20-results.json).

The sampled whole internal heap peak changes 357148 ->
334036 B (23112 B, 6.47% lower).
The instrumented peak changes 264428 ->241456 B
(22972 B lower). These observed workload maxima include SDK activity and
scheduling variation; they are distinct from the deterministic buffer saving.

## Ownership and limits

The dispatcher embeds one 1198-byte encoder, separate from delivery/TX plaintext,
RX queue, ACK envelope, snapshot/result storage and retained transaction
ciphertext. A private lease helper centralizes acquire/release/dispose. The
pool is per instance, with no global owner and no large task-stack array.

Optional binding frees the standalone engine's original output allocation.
A process call acquires a lease before parser allocation or provider effects;
a competing engine yields without touching encoded bytes. Clock/timeout checks
still run. Collection that yields without output releases the encoder. An
OUTPUT lease survives polling until its consumer copies the bytes, sends,
cancels, times out or deletes the engine.

The dispatcher releases Read's lease at its existing sent transition, only
AFTER framing, encryption and successful independent MRP retention. Subscribe
has a private copied-output handoff at the same retention point: it relinquishes
the encoder but stays OUTPUT, and further output polling returns WOULD_BLOCK.
Only the first actual accepted UDP send calls sent_at, preserving report timers
and activation. ACK-before-UDP-completion, retry and stop/fabric drain still own
separate immutable ciphertext. Failed TX preparation closes the interaction and
its normal deletion releases the lease. Dispatcher deletion also checks no lease
remains. Existing owner-thread runtime/dispatcher reentry guards remain required;
this mechanism supplies no general thread synchronization.

Unchanged limits: 5 fabrics, 3 protected sessions/subscriptions per fabric,
512 expanded results, 4096 encoded bytes/value, 16384 snapshot bytes/report,
128 events, 56 transports and 1232 UDP payload bytes. The 1198-byte IM budget
still reserves secure framing, protocol header and a piggyback ACK. Standalone
constructors and public output borrows remain compatible, including smaller
configured capacities. Snapshots remain in their existing stable owned blocks.

On C6, the dispatcher grows 5864 ->7064 B (+1200; the 1204-byte pool consumes
4 bytes of prior padding). Read grows 312 ->320 B; Subscribe 368 ->376 B.
Before allocator overhead, 15 retained subscriptions save
`15 * (1198 - 8) - 1200 = 16650 B` (16.26 KiB). Fifteen subscriptions plus five
active Reads that previously retained output save 22600 B (22.07 KiB).
Final Read already released its old private output at sent, so this larger
estimate does not apply after that transition. With no engines, the fixed idle
cost is 1200 B. Binding still briefly allocates/frees the original constructor
output; removing that temporary allocation is outside this change. No new
per-report allocation or OOM site is introduced by the lease.

## C6 peak, free heap, fragmentation and stack

| Metric | Memory19 | Memory20 |
| --- | ---: | ---: |
| Sampled internal heap peak (B) | 357148 | 334036 |
| Tracked library peak (B) | 264428 | 241456 |
| Minimum sampled free heap (B) | 60792 | 83944 |
| SDK aggregate free watermark (B) | 57144 | 80308 |
| Minimum sampled largest free block (B) | 36864 | 59392 |
| Maximum observed free blocks | 88 | 87 |
| Maximum observed allocated blocks | 1047 | 1040 |
| Owner task observed stack use /12288 B | 2760 | 2636 |
| SDK failed allocation attempts | 0 | 0 |

Current free heap and largest block at matching lifecycle checkpoints (bytes):

| Phase | Free19 | Free20 | Largest19 | Largest20 |
| --- | ---: | ---: | ---: | ---: |
| Boot | 397672 | 397672 | 368640 | 368640 |
| Wi-Fi/IPv6 ready, before runtime | 332256 | 332276 | 311296 | 311296 |
| Runtime created | 267240 | 267276 | 249856 | 249856 |
| Runtime started | 234608 | 233476 | 200704 | 200704 |
| First serving sample | 233716 | 232604 | 200704 | 200704 |
| 5 fabrics /15 sessions /15 subscriptions | 134240 | 146012 | 110592 | 122880 |
| After reconnect, full load | 129376 | 145940 | 104448 | 110592 |
| Subscriptions/sessions drained, runtime alive | 228760 | 227604 | 108544 | 110592 |
| Complete, lab resources released | 390112 | 390148 | 303104 | 188416 |

These rows are phase snapshots, not guaranteed minima within each phase. The
100ms nominal sampler provides the separate minimum-free and peak figures above;
blocking crypto/SDK calls can widen gaps. `MEMORY.heap_min` is the SDK aggregate
watermark: per-region minima need not coincide in time. It can be lower than
minimum sampled free heap and cannot be interpreted as a precise simultaneous
whole-device peak. Largest-block and block-count observations quantify this
workload's allocator state; no universal fragmentation percentage is inferred.

The complete-phase largest block is WORSE: 303104 ->188416 B, despite nearly
equal total free heap (390112 ->390148 B), zero tracked core allocations and
successful heap integrity. This single immediate post-teardown observation does
not distinguish residual SDK allocation placement from deferred reclamation.
No settled post-stop sample or SDK allocation trace was taken. Do not claim a
blanket fragmentation improvement: the loaded-workload minimum improves, while
the final contiguous-block result remains an unresolved regression observation.

Both heap records select `MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT`, so allocations
for Wi-Fi, lwIP, mDNS, crypto and dynamically reserved task stacks from this pool
are included. The FULL reserved task stack is already charged, including unused
space; do not add it again to heap peak. `core_peak` counts only calls through
the library wrapper (actual allocator block sizes), excluding uninstrumented SDK
calls. Static `.data/.bss`, IRAM code and other capability pools are outside these
heap figures. Whole RAM use and Matter-wide worst-case requirements cannot be
inferred from one sampled workload.

ELF `.iram0.text`, `.dram0.data` and `.dram0.bss` stay 69066,16235,25168 B.
Flash text grows 946 B. Compiler frames: Read process48 B, Subscribe process32 B,
copied-output handoff16 B, process_transaction144 B, dispatcher process176 B
(previous160 B), enclosing runtime process48 B. Individual frames are not a
complete nested stack bound. The observed owner-task use above and task low
watermarks are evidence for this run, not a safe minimum stack configuration.

## Validation and retained failures

Windows GCC CTest102/102, Linux99/99 normally and separately with
ASan/UBSan/LSan, and both IDF6.1 RGB/soak and default profiles pass.
Nine focused Memcheck runs and the full two-instance scenario have zero errors
and zero live blocks at exit. The full scenario passes6/6 under Memcheck and
separately6/6 under sanitizers, including independent model/Identify/UTC state,
B Read/subscription survival while deleting A, and last-fabric replies.
IDF reports the existing informational PATH-CMake version selection message;
no `warning:`/`error:` compiler diagnostics occur in these builds.

Native focused tests cover competing leases without parser/provider work or
allocation, byte stability until handoff, the 8-byte configured output limit,
copied-before-actual-send timing, activation gating, cancel/delete/timeout and
Read capture OOM. Large Read arrays reconstruct unchanged after provider scratch
poisoning. Fifteen simultaneous512-result subscription captures survive encoder
reuse and both ACK/status orders. The bound encoder runs all14 Subscribe capture
allocation failures and4 continuation RX failures; standalone coverage remains.
Existing provider-callback BUSY guards and the runtime/dispatcher recursive
process/control regressions also pass.

Physical COM23/TL-MR3020 comparison:

| Observation | Memory19 | Memory20 |
| --- | ---: | ---: |
| Load/recovery window (s) | 351.8 | 272.6 |
| Full Reads x171 attributes | 105 | 106 |
| OOM / RX-loss / reconnect cycles | 1/1/1 | 1/1/1 |
| Load rebuilds after OOM / RX loss | 0/1 | 0/0 |
| Held accepted-TX stop wait (s) | 3.754 | 3.738 |
| RGB explicit Busy retries | 0 | 1 |

Both run five fabrics/15 protected CASE sessions/subscriptions, protected quota
rejection, OOM, three-second deliberate RX loss, radio reconnect and held-TX drain.
Healthy operation errors and unexpected subscription closures are zero. SDK
allocation failures are zero, final tracked live bytes/allocations are zero,
heap integrity and the actual diagnostics-callback reentry probe pass. The
controller's interrupted Read during final stop is expected to fail; success
requires the held TX completion and runtime teardown to drain.

An INITIAL UNCHANGED Memory19 run failed: during deliberate RX-loss recovery,
the first count was15 but a delayed expiry left14 after health Reads. Its raw
logs/oracles remain in `failed-baseline01`; separate cleanup restored the original
fabric/label and completed the collector. The cleanup invocation replaced that
attempt's controller summary, explicitly retained as cleanup-results; the original
failure remains in soak.log. It is excluded from the comparison.
The oracle now permits one logged late-count rebuild within the deliberate fault
window, then strictly checks15 again. Healthy-window closure checks remain strict.
An extracted-function mock checks healthy, late-expiry and still-failed rebuild
cases. Both compared physical runs use exactly this corrected oracle. Normal
post-loss session rebuilds and RGB retry of only explicit Busy remain visible;
these tests do not widen the one-Read admission budget.

The flash backup's application region matches the saved Memory19 image. Memory20
is written app-only at0x50000; esptool verifies its hash. The four temporary fabrics
and original fixture label are restored. After the controller and collector both
finish, COM/AP are released, the temporary Windows Wi-Fi profile/XML are removed,
and the initially disconnected adapter is disconnected again. IPv6 remains enabled
as requested. No router configuration change is made. Source hashes, sdkconfig
hashes, firmware hashes, checkpoints and final task watermarks are in the JSON.

Commands executed (raw exact arguments in ignored command/log files):

```text
cmake --build build/memory16/windows-gcc -j4
ctest --test-dir build/memory16/windows-gcc --output-on-failure
ctest --test-dir build/memory16/windows-gcc -R 'im_read|im_subscribe|dispatch' --output-on-failure
python tools/matter/check_test_map.py
node --check examples/esp32-runtime/tests/soak.mjs
node build/memory20/test_fault_oracle.mjs
idf-v6.1.ps1 -B <idf61-rgb> build
idf-v6.1.ps1 -B <idf61-default> build
python build/memory20/start_linux.py
python build/memory20/fetch_linux.py
python build/memory20/run_physical.py baseline
python build/memory20/sequence_final.py
python build/memory20/report.py
```

The VM worker configures Debug normally and with MATTER_SANITIZE=ON, runs each
full CTest, then focused Memcheck (snapshots, Read alloc, Subscribe alloc/full
and short, dispatcher, runtime/alloc, RX/alloc) and runtime-pair-host plus the
independent chip-tool controller. C6 scripts use the existing pinned Matter.js
0.17.9 controller, private credentials/state and UART collector. These are
laboratory regressions, not CSA or complete commercial RGB acceptance. The new
C6 run is short, not another hour or an exhaustive OOM/packet/stack proof.

## Files and purpose

| Files | Necessary change |
| --- | --- |
| model/matter_im_output_internal.h | Private shared lease and ownership operations |
| model/matter_im_read.c, matter_im_subscribe.c | Optional binding, lease lifetime and separate copied/sent handoff |
| runtime/matter_dispatch.c | Per-instance encoder, bind, release after independent ciphertext retention, deletion guard |
| cmake/sources.json | Include the private header in the package inventory |
| tests/test_im_read.c, test_im_subscribe.c, test_subscribe_memory.h | Contention, snapshot, timing, lifecycle and OOM regressions |
| examples/esp32-runtime/tests/soak.mjs | Bounded, visible recovery for delayed closure within intentional fault window |
| doc/runtime.md, ESP runtime README, root README, status and test map | Contract, measurement interpretation and coverage |
| memory20-validation.md, memory20-results.json | Reproducible outcomes, free heap and limitations |

Next: measure settled post-stop heap and trace remaining SDK allocations to
explain the complete-phase largest-block decrease before the secure-decrypt / RX
reserve-authenticate-commit optimization.
