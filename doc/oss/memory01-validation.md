# Memory01: operation-owned storage scratch and demand-sized event snapshots

Date: 2026-10-20. Baseline: `6977da4f97fbd3b17dcfa173bda912d31d6d6808`.
The [initial audit](memory-audit.md) and its [baseline measurements](memory-audit-baseline.json)
remain historical. This stage changes allocation timing and ownership without
reducing the accepted capacities or changing public function signatures,
persistent TLV schemas, event numbering or wire schemas. All work is isolated
from the checkout continuing CSA campaigns; no official CSA verdict changes.

## Implementation

* Storage's Codec no longer embeds the complete DTO used only by decode. Encode
  owns a small codec; decode owns a codec plus a staging DTO and publishes only
  after complete validation. Both directions share the schema field-presence
  predicate, preserving schema 1..7 field ordinals and migration rules.
* The store allocates its work DTO and 32,768-byte blob buffer during the
  synchronous operation, then erases/frees them on success and every error path.
  Fabric rollback backup is allocated before the first model mutation and is
  erased/freed after publication or rollback. Failed admission leaves model and
  durable data unchanged; failed AddNOC admission also aborts prepared ACL events.
* Read/Subscribe bind only the borrowed event port/enumerator. Attribute-only
  interactions allocate no event metadata or record arrays. Actual event
  requests allocate selector state, then a shared private count-and-copy helper
  allocates exactly the authorized matching record count. An empty snapshot
  allocates no records. Both log passes run on one serialized owner turn with
  no intervening callbacks or log mutation.
* Read retains the immutable snapshot until deletion. Subscribe frees report
  records after all chunks, IM Success and MRP confirmation, or on cancellation,
  failure/deletion. Later log eviction cannot change an in-flight report. OOM in
  deferred event allocations maps to ResourceExhausted and releases reservations
  through the existing failure/drain path.

## ESP32 compiler measurements

Xtensa ESP32 GCC 13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`, transport
56, event capacity 128. These are compiler layouts and requested payload bytes,
not a linked firmware RAM/flash measurement or observed ESP32 heap high-water.

| Resource | Before (B) | After (B) | Lifetime |
| --- | ---: | ---: | --- |
| Store owner | 49,104 | 184 | Between operations |
| Fabric host owner | 19,688 | 4,152 | Between mutations |
| Encoder scratch | 16,280 | 120 | One encode |
| Decoder scratch including atomic DTO | 16,280 | 16,280 | One decode |
| Read event state | 35,256 | 5,568 + 232 x matching records | Actual event request only |
| Subscribe event state | 35,272 | 5,576 + 232 x matching records | Metadata for subscription; records per report |
| Attribute-only event binding | 35,256 / 35,272 | 0 allocated | Read / Subscribe |
| Read / Subscribe base owner | 2,120 / 2,720 | 2,136 / 2,736 | Includes the borrowed binding descriptor |

Storage owners together retain **64,456 B less between operations**. An actual
fabric mutation still needs its 15,536-byte rollback image. A save still needs
the 16,160-byte DTO plus a temporary 32,768-byte blob buffer; these were moved out
of idle ownership, not eliminated from peak demand. Encoder scratch saves
16,160 B during encoding. Decode preserves its original atomic staging cost.

At the full 128-record ceiling, event payload storage still reaches 29,696 B:
capacity was not reduced. At zero or one matching record, there is zero or
232 B of record storage. Attribute-only interactions save about 35 kB per
handler, offset by 16 extra bytes in the base owner. The 16-record comparison
build also compiles all 26 probes; state size is independent of the record
ceiling now. The node event log's retention/staging arrays remain unchanged.

Test-only requested-byte accounting on 64-bit Windows measures deferred Read
storage at 5,887 B for one event and 7,567 B for eight; Subscribe at 5,911/7,591 B.
The 1,680-byte difference is exactly seven 240-byte host records. These include
request/event state allocations after construction, not a full application heap.
Subscribe's confirmed idle footprint is identical for one/eight records; Read
releases its snapshot on deletion. Attribute-only interaction growth stays below
24,576 B, including the still-existing 16 KiB value arena.

A representative save releases all temporary bytes before returning, with a
49,096-byte requested transient peak on the 64-bit host. Its largest request is
32,768 B. The storage test injects each save allocation failure and each restore
constructor allocation failure, checking unchanged publication and no residual
scratch. The [public evidence JSON](memory01-results.json) records final measurements and validation.

## Compatibility and regression coverage

Existing storage tests retain schema 1..7 migration, UpdateNOC, fail-safe
rollback/commit, label/ACL/group-key isolation, EEM and event high-water state,
last-fabric reset and four atomic file failures. `test_store_alloc` is now a
native CTest entry, using the existing crypto-failure expectation as well as
new storage/rollback allocation failures.

Read/Subscribe retain existing grammar, DataVersion, wildcard/fabric/ACL,
chunking, cancellation and IM-before-MRP delivery-barrier tests. New tests cover
allocation-free binding, empty/one/eight-record snapshots, each deferred OOM,
attribute-only memory bounds, snapshot release and **the complete configured
event capacity** while the underlying log evicts every original record between
chunks. Test observation arrays derive from the configured event/path limits;
they do not constrain production retention to the old 32-observation fixture.

The pair fixture required three scoped repairs before its memory acceptance:
initialize the existing default subscription budget (3 instead of zero), enable
the oracle's existing strict metered-switch profile, and free the plug's EPM,
EEM, topology and file objects during teardown. The stale fixture otherwise
rejected startup/profile or leaked 17,040 B in 20 blocks. These are laboratory
driver repairs, not reduced assertions, production limit changes or CSA patches.

jscpd 4.0.5 with the original 8-line/60-token threshold scans 64 implementation
files: **8 clones / 75 lines / 0.56% before; 7 clones / 67 lines / 0.50% after**.
Shared schema gating, event snapshot collection and test allocation accounting
avoid separate implementations of the new mechanisms. This statistic does not
measure semantic duplication or linked flash savings.

## Final validation

| Track | Actual result |
| --- | --- |
| Windows MinGW GCC 16.2 build and CTest | Complete build; 86/89 tests pass inside the sandbox. Three socket tests (`test_udp_windows`, its allocation variant and `test_unsecured_tx_windows`) then pass 3/3 with normal local network access. Modified storage/IM tests were rerun after their final additions and pass. |
| Linux GCC normal full CTest | 86/86 PASS |
| Linux separate ASan/UBSan/LSan full CTest | 86/86 PASS, leak detection enabled |
| Full Linux two-instance scenario under Memcheck | All six grouped acceptance checks PASS; both instances deleted; 49,000 allocations/frees, zero live bytes/blocks, zero errors and zero suppressions |
| Same scenario with separate sanitizers | All six grouped checks PASS; exit 0 and empty native stderr; leak detection enabled |
| ESP32 layout/frame probes | 26/26 compile for each of event limits 128 and 16, with `-Werror` and no diagnostics |
| Source identity / inventory | 161 production/test inputs match the Linux export by normalized SHA-256; inventory checker and `git diff --check` pass |

The pair checks cover commissioning/attestation, CASE, complete wildcard profile
reads, subscriptions, independent application/Identify/UTC state and continued
service on B while A is removed and destroyed. They are independent local
acceptance, not official CSA results. The initial launcher/path, stale profile
and fixture-cleanup failures are retained in ignored laboratory logs; only the
final clean runs are used above. The fixed inventory includes 248 mapped files.

Commands used (normal and sanitizer builds are always separate):

```text
cmake -S . -B <build> -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<pinned-mbedtls> [-DMATTER_SANITIZE=ON]
cmake --build <build> -j 3
ctest --test-dir <build> --output-on-failure
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <build>/cmake/tests/runtime-pair-host <iface> <credentials> <state-A> <state-B> --meter-services
python tools/matter/tests/chip_tool_three_phase.py --chip-tool <chip-tool> --paa <paa> --output <out> --discriminator 3846 --pair-discriminator 1234 --source-registers --meter-services
python tools/matter/memory_audit.py --cc <ESP32-gcc> --nm <ESP32-nm> --events 128 --output build/memory01/esp32
# Repeat the compile-only probe with --events 16 and a separate output folder.
python tools/matter/check_test_map.py
git diff --check
```

Sanitizer acceptance uses the sanitized pair binary directly, with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Its CTest properties retain
the repository's separate sanitizer environments. Host-specific commands and
raw evidence remain ignored under `build/memory01/`; credentials and device
state are not included in the public receipt.

## Remaining work and limits

Changed implementation and supporting files:

| Files | Necessary change |
| --- | --- |
| `main/apps/matter/storage/matter_store_tlv.c`, `.h` | Separate small encoder from atomic decoder staging; share schema gates and document workspace ownership. |
| `main/apps/matter/runtime/matter_store_host.c` | Allocate/erase/free work and blob scratch for each operation; propagate OOM before publication. |
| `main/apps/matter/runtime/matter_fabric_host.c` | Allocate backup before mutation and release on every commit/rollback/OOM path, including prepared ACL events. |
| `main/apps/matter/model/matter_im_read.c`, `matter_im_subscribe.c` | Lazy event state and exact snapshots; preserve chunk/confirmation lifetime. |
| `main/apps/matter/model/matter_im_events_internal.h`, `matter_events.h` | Shared checked snapshot mechanism and explicit count/copy contract. |
| `tools/matter/tests/test_alloc_bytes.h`, `test_store.c`, `test_im_read.c`, `test_im_subscribe.c` | Shared requested-byte/OOM accounting and complete save/restore fault coverage. |
| `tools/matter/tests/test_im_events.h`, `test_im_multi_events.h`, `test_subscribe_complex.h` | Replace obsolete bind-OOM expectation; test lazy OOM, exact growth, empty/full snapshots and confirmed release. |
| `tools/matter/tests/runtime_pair_host.c`, `chip_tool_three_phase.py` | Repair stale default-budget/profile/cleanup handling needed for full two-instance acceptance. |
| `cmake/test-cases.json`, `doc/oss/test-map.json`, `test-map.md` | Register storage allocation tests and the new shared helper without dropping existing coverage. |
| `tools/matter/memory_audit.py` | Measure the new decoder and temporary backup correctly. |
| `doc/runtime.md`, this report, `memory01-results.json` | Record ownership changes, compatibility, measured savings and actual validation evidence. |

The transport transaction table, node event-log arrays, 16 KiB attribute arenas,
fixed selector metadata, cluster encoders and handshake/crypto scratch remain.
The 32 KiB persistence buffer is now temporary but still uses the original bound
because the blob-read port requires capacity before read. Exact serialized-size
buffers or streaming need a separate compatibility-preserving change.

No ESP32 firmware link/flash, physical device acceptance, fragmentation/latency
measurement, ecosystem UI check or new official CSA run is claimed. The extra
event-log count pass is bounded by existing event/path limits. The largest
individual frame among the 26 probe units remains 576 B; this is not the nested
task-stack high-water mark. The complete firmware is not yet proven to fit 128 kB.

Next implementation task: **individually allocated stable Transaction nodes and
pending-TX buffers**, preserving all current per-fabric/protected-work admission,
replacement, cancellation and ACK/drain limits. Measure simultaneous storage,
commissioning, subscription and OTA peaks before selecting retained reservations.
