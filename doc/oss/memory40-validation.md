# Memory40: retire acknowledged Read prefix blocks

Read now releases entire consumed metadata/value blocks during continuation,
after both the successful IM StatusResponse and MRP delivery confirmation.
The normal matched C6 profile changes sampled whole-heap peak from
**325808 to 325056 B**;
core-allocator peak changes **231560 to 231840 B**.
See [machine-readable results](memory40-results.json).

## Ownership and compatibility

The new dense-table helper frees only complete head blocks whose allocated
ordinal span is behind the exclusive released cursor. It performs no allocation,
fixes the cache/tail and leaves remaining addresses and ordinals stable. Dense
capacity remains the reservation high-water mark; retired ordinals cannot be
reused. Clear resets the table. Sparse Subscribe storage does not call this helper.

Read releases snapshot references first and then retires their pages inside the
existing success/MRP gate. A partial ARRAY pins its page. Partial pages, including
tail padding, remain until the existing final-output or deletion path. Compaction
and access revalidation still start at the current cursor. No provider is read
again during continuation. Event snapshots, shared-value owners and the cumulative
16 KiB snapshot admission budget are unchanged, as are 9 selectors /512 results.
The existing final-sent policy remains: metadata can leave after output has been
copied to independent ciphertext; external references remain until confirmation
or cancellation/drain. No retransmission, timeout or application scheduler changes.

Changed files: `matter_im_blocks_internal.h` adds bounded retirement;
`matter_im_read.c` calls it at the existing ownership boundary. Block and Read
tests cover lifetime/OOM behavior; `test-map.json` registers the new test header.
The isolated block generator now counts resident logical records by actual blocks,
rather than the cumulative ordinal ceiling, preventing incorrect occupancy after
prefix removal. Its schema and Subscribe geometry remain unchanged.

## Matched C6 measurements

COM23, UART 1000000, TL-MR3020, exact retained normal Memory38 binary versus the
new normal image, identical fresh private NVS/controller snapshots and unchanged
IDF 6.1 configuration. Fixed profiles cover five fabrics, fifteen protected CASE
sessions/subscriptions, 171 attributes, three parallel Read rounds, three Fabric
publication rounds, four live fabric removals and accepted-TX stop/drain.

| Normal image/workload | Sampled heap peak B | Min sampled free B | Min sampled largest B | SDK min free B | Core peak B | Cleaned largest B | Owner stack observed B |
|---|---:|---:|---:|---:|---:|---:|---:|
| Memory38 baseline fixed | 325808 | 90452 | 65536 | 88660 | 231560 | 262144 | 3192 /12800 |
| Memory40 fixed | 325056 | 91168 | 65536 | 88356 | 231840 | 262144 | 3160 /12800 |
| Memory40 fault | 309036 | 109016 | 86016 | 106484 | 215264 | 229376 | 3192 /12800 |

Minimum sampled free changes by **+716 B**, minimum sampled
largest by **+0 B**, SDK historical minimum free by
**-304 B**. Earlier page release is proved, but these small
and mixed global extrema do not establish a substantial whole-device peak saving.
Releasing acknowledged data does not reduce the memory needed for fresh captures
before acknowledgements. Timing/SDK allocation placement can also affect these
observations. Whole-heap figures include SDK/Wi-Fi/lwIP
and other dynamic allocations. Heap-allocated task stack reservations are already
included there; observed stack use is reported separately and must not be added
again. Sampled extrema and the SDK historical minimum free are distinct counters.
They are workload observations, not a maximum required by the Matter specification.

The fault run exercises one OOM, deliberate RX loss, reconnect/rebuilt load and
held TX completion. OOM uses the existing allocator fail-after hook. The core
failure counter is 13 from deliberate startup probes, or 14 after the one
additional runtime injection; the SDK allocation-failure counter stays zero.
All runs require zero healthy-operation errors, unexpected
subscription closures, SDK allocation failures, and final core live objects/bytes.
Intentional fault losses and rebuilds are retained in results. Largest free block
is an allocable-block metric, not proof that every remaining SDK allocation ended.
Fault teardown leaves 390200 B free in total and a
229376 B largest block, despite zero core live bytes.
This differs from the fixed workload; this stage does not repeat the SDK heap-map
and 65-second settle investigation from [Memory36](memory36-validation.md), so it
does not assign this remaining placement/fragmentation to a specific SDK node.

C6 ReadItem stays 32 B and block header 8 B; context stays 320 B. Writable static
sections are unchanged; flash text grows 84 B. Compiler frames remain
`release_consumed` 16 B, `matter_im_read_process` 48 B, sent 16 B and confirm 32 B.
The isolated observer has the same 20008 B BSS overhead as Memory39 and is excluded
from headline measurements. Its Read-only requested-block maximum is
30080 B, 925 slots /855 resident records,
with 0 B of retained records behind the released cursor.
Separate Read/Subscribe maxima are not summed as a simultaneous heap maximum.
The Read requested-block maximum matches Memory39's 30080 B; its retained consumed
bytes at that maximum are now zero. Early release therefore improves lifetime
within an interaction without eliminating its initial full-capture footprint.

## Executed checks

- Windows CMake Debug build and final full CTest: **112/112**, no compiler warnings.
- Linux CMake Debug and separate ASan/UBSan/LSan builds: **109/109** each, complete
  two-instance scenario (six checks) and all six wire cases each. Normal complete
  scenarios run under Memcheck, with zero errors and zero bytes/blocks at exit.
- Read tests enforce all 512 ordered frozen results in both IM/MRP orders, retain
  every page with either acknowledgement missing, and release exactly 32 pages
  before final sent. Native x64 requested bytes released are **20712 B** per order;
  this cumulative release is not an instantaneous or C6 whole-heap saving.
- Poisoned inline provider ARRAY at the last slot of a page survives prefix/ADD
  chunking; remaining paths survive. OOM after retirement covers RX input/work
  failures with retry, deferred workspace failure, terminal status and cleanup.
  Existing tests retain cumulative snapshot-budget, revocation, event and limit gates.
- Generic block tests cover partial/whole pages, both cache positions, stable
  aligned addresses, empty tail, high-water growth/reset and allocation-free release.
  The pre-change Read fails the new release assertion as an explicit negative control.
- Seven instrumented native tests, two real inventories and eleven decoder tests
  pass. The C6 inventory decodes 144 records, with empty registries.
  Every Read inventory record bounds retained consumed data to at most one partial
  page per live interaction (15 records /480 B each on C6); no full retired page remains.
  Generated source/ELF hashes and allocation accounting are checked separately.
  Source evidence retains exact exported-byte hashes plus normalized-LF hashes
  for matching a Git checkout with different newline settings.

Commands used: `cmake -S . -B <build> -G Ninja ...`,
`cmake --build <build>`, `ctest --test-dir <build> --output-on-failure`,
Linux `ctest ... -E runtime_wire`, `chip_tool_three_phase.py --source-registers --meter-services`,
`runtime_wire.py --memcheck` and separately sanitizer binaries,
`report_blocks.py --kind read|subscribe|allocator|app`,
`report_blocks_decode_test.py`, `report_blocks_decode.py`, IDF 6.1 wrapper `build`,
`esptool ... write-flash`, `uart_capture.py --port COM23 --baud 1000000`,
`rgb.mjs`, and unmodified `soak.mjs` with `MATTER_SOAK_MEMORY_PROFILE=1` for fixed
profiles or a 180-second timed fault window. Full private command/log manifests
are retained outside public evidence.

The first Linux inventory failure (missing test-map entry) was corrected and the
complete series rerun. Three initial Windows UDP sandbox failures pass outside
the sandbox, followed by a passing full series. Those initial logs are retained.
Neither is presented as an unexplained passing initial campaign.
The first sanitizer pair stopped after 3/6 checks when chip-tool's outbound OnOff
send returned kernel `ENETUNREACH` on link-local IPv6; host sanitizer stderr was
empty. The route was present on inspection. The same binaries and unchanged
limits/timeouts/oracle subsequently completed the full pair and wire campaign.
First logs are retained; the transient route failure's cause is not established.

Final normal Memory40 firmware and original fabric/NVS are restored. Nine RGB
updates/transitions and one-fabric checks pass, then zero-live drain. COM23 and
TL-MR3020 are released, temporary Wi-Fi profile/XML removed, IPv6 stays enabled,
COM24 untouched. No new CSA or phone-app pairing claim. Next: compare smaller
sparse Subscribe value pages against both sparse and full 512 captures before
changing geometry; Memory39's padding is a candidate, not a guaranteed saving.
