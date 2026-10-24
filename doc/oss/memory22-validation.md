# Memory22: own-fabric response progress and C6 RAM attribution

Memory21 was committed as `5a577e4` (`Measure settled SDK heap and compare C6
memory with ESP-Matter`). Memory22 fixes dispatcher progress without changing
the C API, limits, storage format, fail-safe, ciphertext lifetime or admission.
Detailed public measurements and source/firmware fingerprints are in
[results](memory22-results.json).

## Response timeout

The unmodified Memory21 C6 firmware reproduced the failure with five fabrics,
three CASE sessions/fabric and15 Hue subscriptions. One run lost its second
own-fabric RemoveFabric response. A diagnostic run which closed only local
subscription listeners lost the first response: the fabric was removed, the
InvokeResponse was constructed, but it never reached UDP before the30s reply
deadline. The independent controller then reported its missing-peer timeout.
An additional diagnostic run succeeded, showing that the defect depends on
pending control traffic rather than always occurring with multiple sessions.

The reply-only connection correctly rejects ACKs belonging to its other,
revoked exchanges. However, `send_ack()` set `ack_waiting` **before** checking
that eligibility. RX retains an unsent ACK until successful completion or
session retirement. The rejected ACK therefore became due again every owner
turn, and `ready()` kept denying MRP priority. The final response needed that
same MRP path; session retirement, which would discard obsolete ACK records,
was waiting for its delivery. This was a progress deadlock until the deadline.

The fix sets ACK priority only after the retirement/reply-exchange guard.
Eligible ACKs retain their priority. No fabricated send completion, early free,
counter advance, session authority or new timeout is introduced. A previously
accepted ACK still owns its UDP borrow until actual completion. Obsolete ACK
records are discarded by the existing retirement path after the final reply
is acknowledged, fails or reaches its existing deadline.

The new deterministic `test_dispatch` fixture queues a real RX ACK obligation
on another exchange of the invoking connection. Before the fix it fails at
the assertion that the final MRP packet reaches the fake UDP backend. After
the fix it covers peer ACK before/after local UDP completion, a previously
accepted old ACK held across revocation, local completion failure, reply-packet
OOM, sibling-session retirement, preservation of another fabric and full drain.
It reuses the existing fake UDP backend and allocation accounting.

The shared comparison controller has explicit `live` and `local-close` cleanup
variants. Both require four responses through existing sessions, then read
through every remaining session. `live` additionally requires fresh Hue
updates on every surviving subscription after each removal. Default `drained`
cleanup is preserved. Response construction/validation is shared by variants.

## Why the reference's heap figure is lower

All sizes below are **bytes**, measured on the two complete Memory21 lab
profiles: C/IDF6.1 and pinned ESP-Matter1.6.1/IDF6.0.2. Both had the same three
Wi-Fi IRAM optimizations disabled and the same10/32/32 Wi-Fi RX/TX buffer
settings. Moving Wi-Fi code to flash was not an exclusive C-stack advantage.

| Metric | C | ESP-Matter/ConnectedHomeIP | Difference |
| --- | ---: | ---: | ---: |
| Static D/IRAM |110493|179798|C uses69305 less|
| Sampled dynamic heap peak |256136|143016|C uses113120 more|
| Static + sampled heap peak |366629|322814|C uses43815 more|
| Minimum sampled free heap |163804|206396|C has42592 less|
| Loaded steady free heap |198856|236628|C has37772 less|

Thus the reference does **not** save100kB of total RAM in this comparison.
Its approximately113kB heap advantage is partly offset by approximately69kB
more static D/IRAM. The practical remaining difference is approximately38kB
at steady load and43kB around the measured peak. Static + heap is an accounting
comparison, not an exhaustive worst-case bound. Free-heap observations also
include allocator/layout effects. The SDK-timer samples include Wi-Fi, lwIP,
FreeRTOS task stack reservations, crypto, NVS, drivers and application activity
in internal8-bit heap. They exclude memory already consumed by static D/IRAM.

The reference ELF confirms static `chip::Server`12272 B, Interaction Model
engine9632 B, and event buffers4096+1024+1024 B. These are already contained in
its static total; adding them again to its heap figure would double count.
The static difference consists of46328 B BSS,585 B initialized data and22392 B
IRAM code. Different IDF versions and feature sets remain part of the result.

There is also a crypto configuration difference: the reference enables
`CONFIG_MBEDTLS_HARDWARE_ECC`; the C/IDF6.1 component currently requires it off
to preserve its software blinding/RNG-failure semantics. Crypto algorithms,
SDK versions and temporary allocation behavior are therefore not fully matched.
This audit attributes core allocations, not every SDK allocation; it does not
assign a fabricated byte saving to hardware ECC.

The [Espressif optimization guide](https://docs.espressif.com/projects/esp-matter/en/latest/esp32c6/optimizations.html)
also explicitly says its example numbers use ESP32-C3/IDF5.4.1, despite the C6
documentation URL. It lists code placement, shell/endpoint reductions, BLE
release after commissioning and smaller event/resource pools. Those published
deltas are not measurements of these two C6 images, and reducing pools/events
would change coverage. They were not applied wholesale to our stack.

Source inspection also identifies real design costs on our side:

* `Matter_Fabric_Host_Image` reserves15552 B even with one fabric. Each record
  is1936 B, including fixed400-byte NOC/ICAC/root/VVSC fields. The reference's
  `FabricInfo` is144 B and its whole five-fabric `FabricTable` is904 B in this
  exact C6 ELF. CHIP fetches certificates through its certificate store when
  needed. These sizes compare representations, not complete equivalent
  subsystems or a guaranteed net saving.
* Our cluster-local ACL, Fabric and Diagnostics encoders retain three4096-byte
  buffers:12288 B. ACL/Diagnostics/GroupKey/AdministratorCommissioning retain
 64-tag validation tables; OTA Requestor retains128 tags. IM parser workspace
  optimizations did not remove these separate cluster buffers.
* Our transport metadata reserves56 exchange/ACK/MRP entries to support the
  unchanged52-transaction admission ceiling. The reference has
  `CONFIG_MAX_EXCHANGE_CONTEXTS=8`; its shared path pool rejected the earlier
  seven-path-per-subscription experiment. Equal successful workload does not
  mean equal configured resource ceilings. No limit was reduced here.
* Our standalone per-instance subscription object is376 B plus a280 B stable
  dispatcher transaction and allocated path metadata. The reference
  `ReadHandler` is128 B, with other state in shared pools. Its full engine9632 B
  is static. These object sizes alone cannot be subtracted as total costs.

## Allocation attribution

A separate temporary diagnostic build records allocation call sites, aggregate
live allocations and a snapshot of the tracked core high-water mark. Its
8460 B static bookkeeping table changes layout and timing, so its free-heap
figures are **excluded** from the headline comparison. Addresses are decoded
against that build's exact ELF; totals match accounting, with zero table
overflows. The table is absent from the final firmware and source changes.

The diagnostic evidence separates retained storage from publication overlap;
the final values and allocation groups are recorded in the results file.
At the first idle checkpoint the tracked core owns92992 B; at the five-fabric
checkpoint it owns125624 B. Important live allocation groups are:

| Allocation group | Idle | Five-fabric checkpoint |
| --- | ---: | ---: |
| Fabric image |15552|15552|
| Generic cluster definitions,15 allocations |10488|10488|
| Diagnostics object |8488|8488|
| Dispatcher |7064|7064|
| ACL object |6384|6384|
| OTA Requestor object |5704|5704|
| Fabric encoder object |4224|4224|
| Subscribe objects |0|5640 for15|
| CASE secure objects |0|4808 for15|
| Dispatcher transaction nodes |0|4480 for16|
| Additional adaptive UDP RX nodes |0|8988 for7|

These groups overlap the earlier member-size explanations: for example the
Diagnostics/ACL/Fabric rows already include their4096-byte encoders. They must
not be added twice. The RX adapter keeps one base node, grows to eight under
pressure and trims idle spare nodes after10s; a5s cleanup checkpoint can still
include these spare buffers. This is separate from final teardown, which frees
all tracked core bytes. OTA Requestor retains five512-byte offer metadata slots
plus parsing/storage work even when no download is active.

In particular, a fabric publication simultaneously retains the15552 B image,
15536 B rollback and16048 B encoded TLV buffer. The encoder already allocates
the measured wire size rather than its maximum capacity. Removing that overlap
while preserving atomicity and the existing format requires a deliberately
designed storage transaction; simply lowering a constant would lose coverage.
The eventual tracked core high-water mark is159896 B; its TLV allocation is
16028 B (label/record content changes the measured encoded length). The earlier
159324 B snapshot contains the16048 B example above. These are tracked core
peaks, not whole-system heap peaks.

## Validation and scope

* Windows: full build and CTest102/102.
* Linux: full CTest99/99 normally and separately ASan/UBSan/LSan; nine focused
  Memcheck cases including the new dispatcher regression; full two-instance
  chip-tool scenario6/6 under Memcheck and separately sanitizers. Memcheck
  reports zero errors and zero bytes/blocks at exit, including the pair.
* Physical matched-profile C6 runs: `local-close` and `live` each receive four
  responses through loaded existing sessions, approximately449–654ms. Each
  completes135 Reads/945 values,15 subscriptions and18 RGB invokes. The final
  attribution run additionally completes four Hue changes and30 fresh reports
  from surviving subscriptions:120 updates and22 invokes, zero unexpected
  closures. All retain only the original fabric and complete teardown.
* Physical normal C6 regression:483.45s controller/501.61s UART including setup
  and teardown,279.64s sustained/recovery window,71 complete171-attribute Reads,
  30 CASE resumptions, protected-session limit rejection, one OOM cycle, one
  RX-loss cycle, one Wi-Fi reconnect and held-TX stop/drain in3.77s. OOM ends
  one subscription; the oracle explicitly rebuilds the full15-subscription
  load. Healthy-operation errors and unexpected closures are zero; SDK
  allocation failures are zero. The pending Read is rejected during explicit
  stop, as expected. All tracked library allocations/bytes are zero at exit.

| C6 profile/workload | Heap peak sampled | Minimum sampled free | SDK minimum free | Minimum sampled largest block | Observed main stack use |
| --- | ---: | ---: | ---: | ---: | ---: |
| Timer, seven paths, local-close |256156|163784|163256|143360|3160|
| Timer, seven paths, live |256348|163636|163480|147456|3288|
| Normal,171-attribute wildcard fault/recovery |334508|83516|78412|60416|3192|

The first two use the common100ms SDK timer. The last uses the existing owner
sampler and can miss SDK/blocking peaks; its separate SDK minimum-free watermark
is retained. Do not compare the334508 B wildcard result directly to the
143016 B reference seven-path result. Same-workload comparison remains the
Memory21 table above. The fix adds no allocated object or structure field.
Its whole-system common peaks differ from Memory21 by20/212 B, not a new
reservation. Largest-block placement varies with allocation order, as documented
in Memory21: after complete teardown it is245760/212992/212992 B respectively,
with zero tracked allocations in all three runs. Final normal RGB after
restoring the private Matter snapshot also passes readback, transitions,
subscription updates, off state and full drain.

See the machine-readable results for physical response latencies, whole-system
heap/free/largest-block observations, stack watermarks, OOM/recovery counters,
native test commands and firmware hashes. Compiler stack frames are64 B for `send_ack`,144 B for
`process_transaction`,176 B for `dispatch_process` and16 B for its public
process wrapper; observed task high-water marks include the nested SDK work.

No official CSA rerun, certification result, exhaustive peak-RAM bound or
matched fault-injection campaign of the reference is claimed. Existing IDF6.1
CMake warnings about private SDK include-directory dependencies remain; no SDK
configuration or upstream source was changed. COM24 was not flashed for this
fix. The primary C6 fabric is preserved, normal RGB firmware is restored and
the temporary Windows Wi-Fi connection/profile is removed after testing;
IPv6 remains enabled as requested.

Changed files are the dispatcher guard, its focused test fixture, the shared
comparison controller and its usage README, plus this report/results and the
root README/status links. No unrelated module or SDK source is changed.
Executed commands include `cmake --build build/memory16/windows-gcc -j 3`,
`ctest --test-dir build/memory16/windows-gcc --output-on-failure`, the focused
`test_dispatch` before/after check, Linux CMake/CTest normally and with
`MATTER_SANITIZE=ON`, and Valgrind with full leak/origin checking and
`--error-exitcode=99`. The full native pair uses `runtime-pair-host 2` and
`chip_tool_three_phase.py --source-registers --meter-services` in both modes.
IDF builds use the repository-local6.1 wrapper; C6 wire tests use the pinned
Matter.js0.17.9 common/RGB/soak controllers and private UART capture. These are
independent physical protocol regressions, not chip-tool running on C6.

| File | Reason |
| --- | --- |
| `main/apps/matter/runtime/matter_dispatch.c` | Apply ACK eligibility before MRP priority. |
| `tools/matter/tests/test_dispatch.c` | Deterministic stale-ACK, OOM and borrowed-UDP regression. |
| `examples/esp-matter-memory/compare.mjs` | Shared removal validation and loaded-session cleanup variants. |
| `examples/esp-matter-memory/README.md` | Document the optional cleanup variants. |
| `README.md`, `doc/oss/status.md` | Link the current result and resolve the recorded Memory21 finding. |
| `doc/oss/memory22-validation.md`, `doc/oss/memory22-results.json` | Evidence, measured RAM attribution, scope and limitations. |

The next memory task should target the measured publication overlap and
cluster-local workspace, with storage/atomicity and OOM regressions, rather
than lowering protocol resource limits.
