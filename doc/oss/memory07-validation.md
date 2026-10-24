# Memory07: Fabric publication peak

Baseline: `510a95b`. This stage removes a redundant Fabric copy from publication
staging and allocates exactly the encoded TLV length. It preserves the public C
API, schemas 1..7, five-fabric limit, fail-safe/UpdateNOC journal, atomic blob
replacement, revision/cache publication and transport ACK/drain boundaries.

## Implementation and ownership

The internal `Matter_Store_Source_T` borrows the Fabric candidate and points to
small operation-owned Wi-Fi/root/EEM/OTA snapshots. The host is busy throughout
publication. Fabric mutation callbacks also keep the Fabric host busy; encoding
has no external callbacks or scheduling. The candidate can be either the live
guarded image or `publish_commit`'s separate committed candidate. The encoder
retains no pointer after returning. OTA pruning occurs only in staging and is
published to the host after durable success.

The internal TLV measuring initializer creates a bufferless context. Ordinary
write/finish execute the same token validation, integer/string widths, capacity,
depth and container accounting for both passes. Public writer initialization
still rejects NULL with nonzero capacity. After measuring, one checked allocation
owns exactly the serialized length, and the same schema descriptors encode it.
The field loop and store validator are shared; no second schema or width calculator
was introduced. A failed encode frees/wipes its output, and a completed encode
transfers ownership to the host until synchronous blob.replace returns.

All three save allocations (small staging, codec, output) occur before durable
replacement; Fabric publication also allocates its existing full rollback image
before mutation. An OOM or backend error leaves the old durable bytes and RAM
state intact. No new publication allocation follows successful replacement. Combined Fabric/Wi-Fi
commit, last-fabric reset and credential rollback retain their existing ordering.
Node-wide EEM/event high-water survives reset. The dense live image and complete
rollback remain deliberately unchanged in this stage.

Restore still needs a 32,768-byte read buffer and complete atomic decode DTOs.
Its destination DTO is now allocated only after a successful read; missing storage
uses the small defaults snapshot. Malformed input cannot publish partial state.
This stage does not claim to reduce the populated-blob boot/restore peak.

## Memory measurements

The existing allocation tracker measures requested payload bytes in replaced
production objects, excluding allocator metadata and uninstrumented backend/
crypto allocations. Baseline and final Windows tests use the same seeded
one-fabric fixture and label operation; baseline was executed before changing
production sources.

| Operation | Baseline transient peak | Final transient peak | Reduction |
| --- | ---: | ---: | ---: |
| Store save | 49,096 B | 16,777 B | 32,319 B (65.8%) |
| Fabric label publication, including rollback | 64,632 B | 32,313 B | 32,319 B (50.0%) |
| Largest allocation in these operations | 32,768 B | 15,945 B | 16,823 B |

Tracked Windows idle fixture payload rises 8 B (36,808 -> 36,816 B) because the
store owner records the output allocation length. This is temporary peak work,
not an idle-memory saving. On ESP32 the field fits existing owner alignment.

ESP32 GCC 13.2.0 C99 `-Os -Wall -Wextra -Werror -fstack-usage` compile-only probes:

| Allocation/layout | Baseline | Final |
| --- | ---: | ---: |
| Fabric image | 15,552 B | 15,552 B |
| Fabric rollback | 15,536 B | 15,536 B |
| Publication staging | 16,160 B | 648 B |
| Store owner | 184 B | 184 B |
| Codec | 120 B | 120 B |
| Public DTO / decode destination | 16,160 B | 16,160 B |
| Output ceiling / restore capacity | 32,768 B | 32,768 B |

For the measured 15,945-byte publication, image + rollback + staging + output
falls from 80,016 to 47,681 B. Adding the codec gives 80,136 -> 47,801 B. This
subtotal excludes other owners, callbacks, crypto and allocator overhead; it is
a layout-derived coexistence cost, not an ESP32 live-heap measurement.

A synthetic codec fixture exercises five fabrics, full ACL entries/subjects/
targets, all groupkey sets, all OTA providers, a credential-rotation rollback
record and scalar maxima. Its output is 17,580 B; the Windows codec/output peak
is 17,740 B. The corresponding ESP32 publication subtotal including codec is
49,436 B. This fixture is a codec saturation test, not commissioning five peers
or a proof of the maximum serialized size of every possible valid DTO. The
32,768-byte ceiling remains enforced on the measuring pass.

The price is an additional descriptor/token traversal before copying the output.
No latency, allocator endurance or fragmentation benchmark was performed.

## Stack

No full DTO, certificate or output buffer was moved onto the task stack. The
largest new individual compiler frame is 112 B; the temporary root field pointer
table has nine entries (36 B on ESP32). Relevant compiler frames:

| Function | Baseline | Final |
| --- | ---: | ---: |
| TLV write | 96 B | 96 B |
| Store save helper | 48 B | 32 B |
| Store constructor | 64 B | 96 B |
| encode_object | 64 B | 48 B |
| encode_field | absent | 48 B |
| encode_source | absent | 96 B |
| Source allocation/encoding entry | absent | 64 B |
| Full DTO validation entry | 96 B | 80 B |
| Shared source validator | absent | 112 B |

The 80-byte validation entry calls the shared validator; they are not alternative
frames. Factoring the field loop adds a helper frame on recursive encoding paths,
so a smaller encode_object frame does not mean a smaller total call chain. Schema
nesting remains fixed. Applications must budget the complete caller/recursive
chain and backend/crypto frames; these probes do not measure a task high-water
mark or establish an ESP32 firmware stack budget.

## Regression coverage

`test_store_alloc` injects every allocation failure in save (3), Fabric publication
(4 per operation), restore (4), and the saturated source encoder (2). Publication
faults cover label, combined Fabric/Wi-Fi commit, fail-safe rollback, last-fabric
reset, ACL and groupkey changes. Full Fabric RAM, Wi-Fi/root/diagnostics, revision,
reset flag and durable byte comparisons detect partial publication. Existing
UpdateNOC/VID/cache/file-fault/independent-process restart oracles remain active.

The same tests compare source output against contiguous DTO encoding for schemas
1..7, rotation and EEM maxima. Independent TLV reference vectors run both writer
and measuring contexts at every short capacity. Existing invalid tag/width/UTF-8/
depth/overflow tests also check measuring-context errors preserve state. Backend
callbacks attempt reentrant save/delete/root/event writes and must receive BUSY.

The first full runtime allocation test exposed an instrumentation gap: allocation
of the output moved into the codec but its free remained in the host. The native
runtime allocation variant now replaces both modules; no allocation/leak oracle
was weakened. Final full runs use that corrected configuration.

Final executed results and evidence hashes are recorded in
[memory07-results.json](memory07-results.json): Windows 90/93 in the sandbox plus
3/3 socket tests with socket access; Linux normal 90/90 and sanitizer 90/90;
two-instance scenario 6/6 under Memcheck and 6/6 separately under ASan/UBSan/LSan.
Both node processes exit zero with empty stderr. All four focused Memcheck
seed/load cases (committed/pending) have zero live blocks/errors/suppressions;
the full two-instance run has 50,151 allocations/frees and no leaks/errors.
Final builds and all 27 ESP32 probes have no compiler diagnostics. Inventory
checks cover 251 mapped files, 92 native test definitions and 75 public headers.
The same jscpd4.0.5 scan of 66 implementation C files finds 7 clones and 69
duplicated lines before/after (duplicated tokens 1301 -> 1358); it is not a flash
size measurement. Headers/tests are outside that duplication scan.

Reproduction commands:

```text
cmake --build build/memory01/windows -j 4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$" --output-on-failure
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory07/esp32
cmake -S <source> -B <build> -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<dependency> -DMATTER_SANITIZE=OFF
cmake --build <build> -j 3
ctest --test-dir <build> --output-on-failure
# Repeat with a separate MATTER_SANITIZE=ON build.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <normal-build>/cmake/tests/test_store_alloc <seed|load> <file> <committed|pending>
```

The full two-instance scenario uses `runtime-pair-host 2 ... --meter-services`
and `chip_tool_three_phase.py --source-registers --meter-services`. Normal runs
under Memcheck; ASan/UBSan/LSan use a separate build, without Valgrind.

## Changed files and limits

| Files | Why |
| --- | --- |
| `runtime/matter_store_host.c` | Small staged metadata, borrowed Fabric candidate, exact output cleanup and retained atomic restore. |
| `storage/matter_store_tlv.c`, `matter_store_source_internal.h` | Shared validation/schema traversal and checked measure/allocate/encode ownership. |
| `codec/matter_tlv_writer.c`, `matter_tlv_internal.h` | Internal bufferless sizing through the existing token writer. |
| Store/meter/UpdateNOC and TLV writer tests | Byte equivalence, OOM, reentry, saturation, rollback and sizing errors. |
| CMake source/test inventories | Package the private header and instrument both sides of output ownership. |
| `memory_audit.py`, runtime/status, Memory07 report/results | Reproducible layout/stack/acceptance evidence. |

Not verified: linked ESP32 firmware, physical heap/stack, fragmentation/endurance,
latency, full OTA provider campaign or official CSA tests. Host tests do not change
an official CSA verdict. Next task: phase-sized PASE/CASE handshake buffers while
preserving handoff, fail-safe, resumption and ACK/drain lifetimes.
