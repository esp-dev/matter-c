# Memory34: demand-sized Fabric encoding and VID scratch

Baseline Memory33 is committed as `e9f2af1`. The Fabric model's resident
encoded[4096] becomes an exact-size owned provider span. VID signing uses separate
short-lived scratch. Public C signatures, the 4096-byte output limit, TLV format,
certificate/filter/order rules, snapshot capture and ACK/drain remain unchanged.
Source-matched measurements and final validation are in
[results](memory34-results.json).

## Ownership and secure release

The existing array encoder is shared by a measuring pass and the real output
pass, with the original 4096-byte budget and depth 3. One backend view is obtained
per read_index call. There is no further port callback, yield or backend mutation
between passes. The session wrapper retains its index lookup and subsequent read,
guarding both view callbacks against mutating reentry. Scalar reads need no
encoding allocation. No grow/realloc, global scratch or large stack buffer is
introduced.

The output owns copies of NOC/ICAC/VVSC, fabric descriptors and roots. A subsequent
backend callback may invalidate its view without invalidating these copies. The
encoded borrow lasts until the next accepted Fabric read, including a scalar or
an allocation/encoding failure, or model deletion. Unsupported attributes and
busy/reentrant reads preserve it. Revision queries, management/publication,
rollback and VID signing do not release it. Read/Subscribe immediately copy bytes
into independent immutable snapshots. Expiring the provider borrow does not own
or release snapshot references, report ciphertext, MRP ACK or TX drain resources.

SignVIDVerificationRequest no longer overwrites the first 211 bytes of an encoded
read. It allocates exactly 126 bytes without VVS or 211 with the existing 85-byte
VVS, copies the nonce, session challenge, target fabric, root public key, big-endian
fabric ID/vendor and VVS before invoking the backend signer. It never accesses
the record/view after that callback. The scratch is erased and freed after both
backend success and failure; signature output is erased on backend failure or
scratch OOM. Native tests invalidate the entire backend view during signing while checking that an
outstanding certificate read is unchanged. Existing real-crypto VID tests still
check signatures and challenge binding.

A common erase/free helper uses volatile stores across each allocation's full
length, then releases it. This includes encoded output on replacement, scalar
read, failed encoding and deletion, signing scratch on both backend outcomes,
and the model itself on deletion. Tests inspect every byte immediately before
the instrumented free. Erasure is bounded by the unchanged 4096-byte output limit;
it does not require a hardware wait or a new task.

Read/sign allocation failure returns ResourceExhausted. A failed read leaves no
partial output or retained encoding allocation and is retryable. A failed sign
does not invoke the backend, mutate the view or expire an outstanding read; it
clears signature output. Existing generic IM error mappings and publication,
fail-safe, atomic store and key ownership are untouched.

The cost is two bounded TLV passes and one allocation/free per array read, plus
secure erasure, and one 126/211-byte transient allocation per VID signature. A
standalone caller that only reads arrays can retain one bounded provider span
until its next read/delete. At the full 4096-byte output limit, pointer/size and
allocator metadata can make the provider's instantaneous footprint slightly
larger than the original inline context. The measured resident saving is not a
guaranteed saving at every instantaneous peak, nor a fragmentation guarantee.

## Normal C6 profile versus Memory33

Same IDF 6.1 SDK configuration, 12800-byte main task, 100 ms internal 8-bit whole
heap sampler, COM23 at 1000000 baud and TL-MR3020. The fixed corrected-peer profile
uses five fabrics, 15 CASE sessions, 15 full 171-attribute subscriptions, three
parallel-Read rounds, three Fabric publication rounds and four live own-fabric
removals. The initial RGB smoke uses the original pinned peer.

|Metric, bytes|Memory33|Memory34|
|---|---:|---:|
|Fabric model context|4224|136|
|Sampled whole heap peak|338944|333104|
|Minimum sampled free heap|77272|83400|
|Minimum sampled largest free block|55296|57344|
|SDK minimum-free watermark|77200|81328|
|Tracked core block peak|242876|238756|
|Observed owner stack use / reservation|3176 /12800|3288 /12800|
|Largest free block after teardown|245760|262144|
|Free heap after teardown|390200|390204|

The matching normal ELF shows context 4224 -> 136 B: 4088 B less resident heap,
with encoded 4096 -> 4 B and a new 4-byte length. Sampled whole heap falls 5840 B;
minimum free rises 6128 B and minimum largest block rises 2048 B. Tracked core
peak falls 4120 B. Whole heap includes SDK/Wi-Fi and dynamically reserved task
stacks; tracked core is a subset and static D/IRAM is separate. Peaks must not be
added. The 100 ms sample may miss shorter peaks, SDK watermarks and sampled minima
need not coincide, and these single runs do not establish specification-wide
worst-case RAM or statistical improvement.

All normal SDK configuration defines match Memory33. Normal ELF .dram0.data
(16235 B) and .dram0.bss (25192 B) also remain unchanged; this change removes
resident per-instance heap storage rather than a global static RAM section.

After teardown, core live count/bytes are zero. Free heap differs by +4 B and
largest block by +16384 B. Different remaining SDK allocation sizes/placement do
not demonstrate elimination of fragmentation. Compare the fault and observer
lifecycle independently; their final largest block need not match this profile.

Compiler frames: read_index 64 -> 48 B, new encode 48 B and unchanged put 16 B.
The read encoder chain can add 32 B. VID stays 80 B, read wrapper 32 B; erase_free
and clear_encoded each use 16 B, increasing the secure release/delete helper
chain. Parser/management/execute/update frames stay 128/64/96/112 B respectively.
Observed main-task usage rises 112 B. Individual frames and task watermarks do
not bound all nested crypto/SDK paths; the task reservation remains 12800 B.

## Validation and provenance

|Executed validation|Result|
|---|---|
|Focused Fabric encoding, libc/allocation instrumentation|2/2|
|Windows full native coverage|109/109 including three explicit UDP retries|
|Windows wire, both ACK orders/original/corrected peers|6/6|
|Linux CTest, normal and separate sanitizer builds|106/106 each|
|Full two-runtime scenario, Memcheck and separate sanitizers|6/6 each|
|Linux wire including OOM/ACK/drain, Memcheck and separate sanitizers|6/6 each|
|C6 normal/fault/observer/final original-peer RGB|PASS|

All checked Memcheck logs have zero errors and zero bytes/blocks at exit.
The separate ASan/UBSan/LSan runs have no sanitizer diagnostic. Windows, Linux
normal/sanitizer and C6 normal/observer builds have no C compiler warnings/errors.
Inventory has 269 mapped files and 106 native definitions; diff whitespace checks
pass. The initial failures and exact scope of their retries are retained below.

Focused native tests cover all five accessing fabrics and both filters, PASE
index 0, foreign public certificate visibility/order, null ICAC, VVS, pending root
inclusion/deduplication, preserved installed duplicates, separate model instances
and the exact 4096/4097 boundary. Instrumented cases fail/retry construction, all
three array attributes and both VID message sizes, check unchanged backend and
borrowed bytes, reject reentry through view/allocation/sign callbacks and verify
full secure wipe before every owned free. The unchanged real-crypto Fabric tests
exercise admission, signature, fail-safe, storage, VID and management regressions.
Multipart Fabric Subscribe tests additionally expire/wipe the provider before
transport sent/confirm and compare the held report bytes.
The native byte-accounting run checks 59 secure frees, with a maximum request of
4096 B and peak 5294 requested payload bytes across its test models/values. These
host allocator numbers exclude libc metadata and are not C6 heap measurements.

Commands are run through the repository CMake/CTest registration, the normal
ESP-IDF wrapper, existing native wire runner and physical C6 oracle. Frozen
sources and matching binaries/ELFs are kept in the ignored laboratory directory;
public results contain hashes and curated counters. Keys, Wi-Fi configuration,
controller states, NVS backups and raw logs remain ignored.
Production/test C and header text matches the frozen build sources after newline
normalization. A final unrelated JSON formatting change was removed from the
test registration file; its parsed registration data is asserted identical to
the tested frozen JSON, and both text hashes are retained in results.

The first Windows suite has 106/109 passes and three UDP wait_event timeouts in
the sandbox. All three pass by explicit name outside the sandbox after the AP
connection; these two environment changes do not establish exact cause.
The first Linux pair completes commissioning/attestation/subscriptions, then
chip-tool SendMessage reports OS "Cannot assign requested address" on the second
node's OnOff read. Its logs/state are retained. A matched existing Memory33 binary
and fresh Memory34 retry both pass all six checks under Memcheck. No production
source or VM networking configuration is changed to obtain the retry.

The normal C6 run passes in 296.08 s with 51 full Reads and 15 subscription
snapshots. The separate fault run passes in 468.34 s: 76 full Reads, 45 snapshots,
30 CASE pair/resumption operations, one consumed runtime OOM, one three-second
loss window (35 deliberately discarded packets), one Wi-Fi reconnect and one
held-completion drain. It records no SDK allocation failures, healthy-operation
errors or unexpected closures. The OOM phase ends one subscription and rebuilds
the full 15-subscription load; read operations themselves are not rejected. This
is the existing recovery branch also recorded by Memory30--32, whereas Memory33's
single fault run preserved subscriptions through OOM and rebuilt after loss.
The global fail-next injection races with asynchronous reports and does not
identify the exact failed allocation site. It is not evidence that every
subscription survives OOM, or a matched allocation-site attribution. Direct
new-allocation OOM behavior is separately checked by the native tests.

The loss phase has no rejected operation or lost subscription in this run.
After reconnect the full load is verified again. Stop waits 3.62 s for drain and
the normal image ends with zero core live count/bytes, 390200 B free heap and a
258048 B largest block. Its whole-heap sampled peak is 318688 B, minimum sampled
free 99352 B, minimum sampled largest 75776 B and SDK watermark 96824 B. These are
the fault workload's own numbers, not replacements for the fixed-profile table.

The isolated C6 allocation profile passes in 299.27 s with 51 full Reads and 15
snapshots. All 18 dumps have checked live-byte/count and peak-byte sums, zero
overflow, and a final zero-live complete dump. The observer uses 2048 live-record
slots and 160 site slots (128 used), with 1140 peak live records and 19596 B of
static metadata. Capacity was raised from 128 only in the isolated generated
observer, avoiding an attribution overflow if additional sites are exercised.
Normal source/configuration does not contain those tables. Its recorded core
peak is 238676 B; the Fabric context site holds 136 B. Transient Fabric output and
VID scratch do not appear in captured live/global-core-peak maps, so these maps
do not measure each short read/sign allocation. Exact allocation sizes and VID
success/failure/secure wipe are verified by native tests; the fixed C6 profile
does not invoke VID signing. Observer whole-heap values are not headline
comparisons with the normal image.

After the observer, the normal firmware and fresh initial NVS are restored.
RGB passes with the unmodified original peer; exactly one original fabric remains
and final drain has zero tracked allocations. This shorter smoke ends with 390208 B
free heap and 258048 B largest block, separate from the full-profile lifecycle.
COM23 is released, COM24 is untouched, the own temporary Windows Wi-Fi
connection/profile/XML are removed and IPv6 remains enabled. TL-MR3020 firmware
and configuration are unchanged; the access point is free for other work.

Executed command families (build/output/dependency paths are operator-supplied):

```text
cmake --build <windows-build> -j3
ctest --test-dir <windows-build> --output-on-failure -E runtime_wire
ctest --test-dir <windows-build> --output-on-failure -R "^test_fabric_encoding(_alloc)?$"
ctest --test-dir <windows-build> --output-on-failure -R "^(test_udp_windows|test_udp_windows_alloc|test_unsecured_tx_windows)$"
python tools/matter/tests/runtime_wire.py --host <frozen-host> --case all --node <node> --modules <modules> --interface <interface> --output <out>
cmake -S <frozen-source> -B <linux-build> -DMATTER_SANITIZE=OFF ...
cmake --build <linux-build> -j3
ctest --test-dir <linux-build> --output-on-failure -E runtime_wire
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=99 <runtime-pair-host> ...
python tools/matter/tests/chip_tool_three_phase.py --chip-tool <chip-tool> --paa <paa> --source-registers --meter-services ...
python tools/matter/tests/runtime_wire.py --host <linux-host> --memcheck ...
cmake -S <frozen-source> -B <separate-linux-build> -DMATTER_SANITIZE=ON ...
idf.py -C <isolated-esp32-runtime> -B <normal-or-observer-build> ... build
python -m esptool --chip esp32c6 --port COM23 --baud 460800 read-flash 0x10000 0x40000 <fresh-private-backup>
python -m esptool --chip esp32c6 --port COM23 --baud 460800 write-flash 0x50000 <firmware> 0x10000 <fresh-private-backup>
python examples/esp32-runtime/tests/uart_capture.py --port COM23 --baud 1000000 ... --reset
node examples/esp32-runtime/tests/rgb.mjs <modules> <address> <private-state> ...
node examples/esp32-runtime/tests/soak.mjs <modules> <address> <private-state> <out> 180 Wi-Fi run wildcard
python examples/esp32-runtime/tests/allocation_decode.py --log <observer-log> --elf <matching-elf> --addr2line <tool> --source-root <observer-source> --output <decoded>
python tools/matter/check_test_map.py
git diff --check
```

Sanitizers run separately from Memcheck with ASan leak detection and halt-on-error
enabled, and UBSan halt-on-error/stacktrace enabled. Full per-command arguments
and unfiltered logs remain in the ignored laboratory directories.

## Scope and next task

Changed files and purpose:

* `main/apps/matter/clusters/matter_fabric.c`: exact-size read/sign allocations,
  shared encoder/secure release and busy guards, preserving existing field logic.
* `main/apps/matter/clusters/matter_fabric.h`: explicit output borrow/cleanup/OOM
  contract, without changing C signatures or port layout.
* `tools/matter/tests/test_fabric_encoding.c`: direct size/filter/order, boundary,
  OOM/retry, secure wipe, reentry, signing lifetime and independent-owner tests.
* `tools/matter/tests/test_fabric_subscribe.h`: expire/wipe provider output before
  sent/confirm and verify stable multipart report bytes.
* `cmake/test-cases.json` and `doc/oss/test-map.json`: register both new native
  variants and keep the export/test inventory complete.
* `doc/runtime.md`, `README.md`, `doc/oss/status.md`, this report and
  `memory34-results.json`: ownership contract, measurements, provenance, executed
  validation, cleanup and limitations.

Next candidate: audit Operational Credentials' resident tbs[1040] and csr[512]
against its asynchronous prepare/sign/publish/cancel phases. The 1552 B gross
buffer capacity is an audit estimate, not a measured peak saving; candidate key,
challenge, response lifetime and secure cleanup need separate review before any
implementation. No new official CSA, phone-app pairing or matched ESP-Matter
benchmark is claimed by Memory34.
