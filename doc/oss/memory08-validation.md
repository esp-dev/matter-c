# Memory08: handshake phase storage and memory budget

Baseline: `3f1efa6`. Public C APIs, PASE1024/CASE1200 payload limits,3600-byte CASE
transcript ceiling, deadlines, fail-safe notifications, resumption profiles,
fabric revisions, one-shot secure transfer and ACK/drain gates are unchanged.

## Lifetime changes

| Storage | Ownership and release |
| --- | --- |
| PASE/CASE RX | Attempt copies exactly the accepted payload length. OOM returns LIMIT_REACHED before changing queued state; caller may retry. Freed/erased after processing or failure/cancel/delete. |
| Parser/field/tag workspace | Per process call only. No workspace during idle/output polling. Process OOM is terminal, with the existing failure status/notification policy. |
| PASE parameter transcripts | Exact request/response allocations. Erased/freed immediately after the SPAKE context hash, before PBKDF/ECP/SPAKE state allocation. Unknown accepted TLV bytes still participate in the hash. |
| PASE/CASE TX | Unchanged1024/1200 capacity, allocated when encoding a message. Immutable across output retries. Erased/freed at sent, after caller retained an independent immutable MRP packet. |
| CASE transcript | Exact local Sigma1 initially. Full CASE reserves3600 before allocating full-Sigma scratch, avoiding a large grow/copy overlap with crypto buffers. Released after session-key derivation. |
| CASE full-Sigma scratch | One3600-byte allocation for TBS/plaintext/ciphertext, only in process calls that encrypt or verify full Sigma messages. Released before awaiting the next message/ACK. |
| CASE resume MIC |16 bytes in the temporary parser workspace; successful resumption never allocates full-Sigma scratch or3600-byte transcript. Full fallback still uses the exact original Sigma1 bytes. |
| Success/failure status | Eight bytes in each owner. Failure reply remains available under OOM without allocating output. |

The shared private handshake-buffer helper performs checked atomic growth/copy
and volatile wipe before free. Receive does no parsing/crypto. Active processing
retains independent buffers until all local readers finish, with no shared arena
or task-stack replacement.

PASE responder still waits for final MRP ACK before COMPLETE/transfer. CASE final
success sender still completes at sent, retaining the transport's independent
packet until ACK/timeout; a late MRP failure cannot revoke a handed-off session.
Cache save remains optional at one-shot transfer, not at scratch allocation.
Failed resume MIC can fall back to full CASE under the existing rules. No change
was made to dispatcher's admission, fail-safe or secure-session handoff code.

## Layouts and tracked peaks

ESP32 GCC13.2.0 C99 `-Os -Wall -Wextra -Werror -fstack-usage` compile-only probes:

| Attempt layout | Baseline | Final |
| --- | ---: | ---: |
| PASE owner |6384 B |744 B |
| CASE owner |14112 B |2440 B |
| PASE process workspace |embedded |1576 B |
| CASE process workspace |embedded |2128 B |
| CASE full-Sigma scratch |embedded |3600 B |

The two owners save5640 and11672 B respectively while no phase buffers are live.
The CASE owner still holds a1312-byte local Fabric snapshot; it is needed across
the selected-fabric/revision/transfer checks and was not changed here.

The new phase test harness was also compiled against the original baseline core
in an isolated local source export. The same deterministic fixture setup and
public APIs measure requested production payload bytes. Mbed TLS adapter work is
tracked; internal Mbed TLS allocator calls, test metadata and allocator overhead
are excluded. These are BOTH handshake peers, with crypto backend and (for CASE)
the fixture's Fabric hosts/images, not a single ESP32 node or a normative RAM bound.

| Whole tracked fixture peak | Baseline | Final | Saving |
| --- | ---: | ---: | ---: |
| PASE |17776 B |8561 B |9215 B |
| Full CASE |68876 B |58680 B |10196 B |
| Resumed CASE |67392 B |47226 B |20166 B |

Tracked completed/idle fixture sizes are14656 ->2944 B for PASE,66896 ->43024 B
for full CASE, and67120 ->43248 B for resumed CASE with warm caches. Pure handshake
phase allocations return to the original idle level after completion. Existing
Fabric cache nodes retain their independent authenticated-save lifetime.

This improves actual lifetimes, not every hypothetical saturation ceiling.
PASE owner+parser+four1024-byte buffers totals6416 B versus6384 B before (+32 B).
CASE owner+parser+RX/TX+full transcript+Sigma scratch totals14168 B versus14112 B
before (+56 B), before allocator overhead. These sums deliberately overcount
some phase-exclusive allocations; they are layout ceilings, not measured peaks.
Separate allocations also increase allocator metadata/churn. Callback/crypto work
can coexist with the active phase; none of these sums covers all of it.
The largest new handshake buffer block is3600 B, rather than embedding all
buffers in one14112-byte CASE allocation; the crypto/backend allocator remains
outside that buffer-only bound.

## Stack

No large buffer/DTO was moved onto the task stack. Existing relevant ESP32 frames:

| Function | Baseline | Final |
| --- | ---: | ---: |
| PASE process |96 B |96 B |
| CASE process |64 B |64 B |
| PASE receive |48 B |32 B |
| CASE receive |48 B |48 B |
| CASE encrypted |64 B |48 B |
| CASE verify |112 B |112 B |
| CASE destination |176 B |176 B |

New buffer-copy/clear/delete helpers have32-byte compiler frames. They add calls;
unchanged process frames do not prove an unchanged whole call chain. These are
individual frames, not a task stack high-water. Crypto, libc/OS and application
callbacks need their own budget. A Linux stack profile cannot establish the
required ESP32/FreeRTOS task stack.

## What the specification requires, and what a memory number means

The locally supplied Matter1.6.1 Core specification (23-27349-012, September16,
2026) defines resource capabilities rather than one implementation's byte layout:

- Operational Credentials SupportedFabrics has a5..254 constraint (11.18.5).
- At least3 CASE contexts per fabric (4.14.2.8); this five-fabric composition
  protects15 operational sessions and additionally has its PASE bucket.
- At least3 subscriptions per fabric, each supporting at least3 attribute/event
  paths (2.11.2.2); one9-path Read per fabric (2.11.2.1).
- At least4 ACL entries per supported fabric (2.11.1.1).
- CapabilityMinima reports these guarantees (11.1.4.4); device types can impose
  additional requirements. This is not complete conformance/certification evidence.

These constraints do not produce one universal heap/stack byte requirement.
Attribute sizes and expansion, retained events, concurrent reports, queued TX,
handshake/crypto backend, platform and application callbacks all affect peak.
The application owns scheduling and memory; no new task/global arena was added.

For example, this build permits512 expanded attributes and16384 snapshot payload
bytes per Subscribe. On ESP32, a saturated attribute subscription alone may hold:

```text
328 owner +512*72 result slots +16384 values +512*4 snapshot links =55624 B
15 such subscriptions =834360 B (about815 KiB)
```

This excludes selectors/filters, event snapshots, RX/TX, growth overlap, other
owners and allocator/crypto overhead. It is the arithmetic of configured caps,
not an observed allocation, guaranteed reachability on this model, or memory
that Matter requires preallocated. Nevertheless, a small workload's measured peak
cannot be advertised as a bound for every input accepted by these capacities.
The current profile cannot be assigned a universal small ESP32 RAM guarantee
merely by adding the new PASE/CASE owner sizes.

The separate live capacity workload commissions five independent fabrics on ONE
host, keeps three CASE sessions/subscriptions on each, requests three concrete
Basic Information attributes per subscription, performs nine-path Reads and
Writes at capacity, checks heartbeat delivery and fourth protected CASE BUSY.
Massif includes the DUT process's allocator-visible backend/crypto allocations
and profiles stack as well. Controller processes are outside the DUT measurement.
This is a concrete observed workload, not the maximum of every legal request,
wildcard expansion, event retention or input timing. It also excludes ESP-IDF,
Wi-Fi/BLE/lwIP, RTOS stacks and target allocator behavior.

Final observed capacity-profile numbers, test results and hashes are in
[memory08-results.json](memory08-results.json). No hard ESP32 heap/stack budget
or complete normative resource proof is claimed before target integration and
simultaneous worst-case workload/high-water measurements.

The final ONE-node Linux x86_64 Debug run passed50/50 checks without profiling
at a3-second maximum interval and50/50 under Massif at30 seconds. The16 controller
processes (15 protected sessions plus the rejected fourth-session probe) exit
zero; they are outside the DUT's memory measurement. Observed Massif snapshots:

| Measurement | Bytes | KiB |
| --- | ---: | ---: |
| Largest sampled allocated heap payload |413884 |404.18 |
| Allocator overhead at that heap snapshot |5076 |4.96 |
| Largest sampled used stack |6744 |6.59 |
| Largest combined heap + overhead + used stack |424368 |414.42 |

The maxima occur at different snapshots; adding all independent maxima would not
describe one observed instant. The largest combined snapshot has413876 B heap,
5068 B allocator overhead and5424 B stack. These are sampled observed process
values, not an exhaustive or target-specific guarantee.

At the largest heap sample, major direct allocation groups include81360 B in
the host mDNS advertiser adapters,13560 B in the host resolver,30976 B in event
retention/preparation,26800 B in cluster owners,24840 B in secure CASE owners,
22672 B in Meter Source and21984 B in four EPM models. The two discovery/resolver
groups alone are94920 B of reference host adapters. Subtracting them would still
not establish an ESP32 core budget: target discovery/networking has its own cost,
other host/application allocations remain, and ABI/crypto implementations differ.

ESP32 accounting must also distinguish task stack reservation from stack usage.
With dynamically created FreeRTOS tasks, the reserved stack is normally already
allocated from heap; do not add its high-water usage to the same total heap metric
again. Static task stacks need separate accounting. ESP-IDF reports stack
high-water free space in bytes and recommends measuring all task states; see
[Espressif RAM measurement guidance](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/performance/ram-usage.html#determining-stack-size).

## Validation and reproduction

`test_pase_alloc` retains the existing PASE/MRP/admin suite and instruments the
matching core/crypto objects. PASE adds34 RX/process allocation faults; CASE
adds54 across full/resumed handshakes, including allowed resume fallback. Tests
verify rejected RX does not accept a message, idle/output polling allocates
nothing, output remains stable until sent, every failed phase denies keys,
failure statuses need no allocation, and all phase allocations are released.
Existing timeout/revocation, certificate/confirmation, both resumption profiles,
fail-safe, replay, final delivery and secure-transfer tests remain enabled.

Full final Windows CTest is91/94 inside the sandbox plus3/3 socket tests with
socket access. Linux CTest is91/91 independently in normal and sanitizer builds;
two-instance checks are6/6 under Memcheck and6/6 separately under ASan/UBSan/LSan.
Both two-instance processes exit zero with empty stderr. PASE and CASE phase/OOM
Memcheck runs release every tracked block and report zero errors/suppressions.
All27 ESP32 probes and final builds have no compiler diagnostics. The same
jscpd4.0.5 scan of66 implementation C files finds7 clones/69 duplicated lines
before and after; headers/tests are excluded and no linked flash claim is made.

The first capacity oracle incorrectly required unchanged attributes in heartbeat
reports. Actual decoded ReportData carried the correct subscription ID with
empty data and successful IM responses. The final workload reuses the existing
report parser to require two complete responses for each decoded ID; unchanged
attributes may be omitted. Production sources and completed memory regressions
were unchanged for the separate profile retry.

At fifteen sessions/subscriptions, the instruction-level Massif stack profiler
also caused liveness timeouts with a3-second maximum report interval. The same
capacity workload passes all50 checks without profiling at3 seconds. The heap/
stack profile therefore requests30 seconds and waits for two complete reports
on every subscription; it is a different timing workload, not a claimed3-second
instrumented PASS. No production timing, admission or protocol limit was changed.

```text
cmake -S . -B build/memory01/windows
cmake --build build/memory01/windows -j4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$" --output-on-failure
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory08/esp32
# Linux: independent Debug builds, MATTER_SANITIZE=OFF and ON; CTest in each.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <test_pase_alloc|test_case_alloc> --memory-only
valgrind --tool=massif --stacks=yes --time-unit=ms --detailed-freq=1 --max-snapshots=1000 --massif-out-file=<out> <matter-node> --interface <iface> --seconds 600 --port 5543 --discriminator 3860 --credentials <development-dir> --state <file> --three-phase --source-registers --meter-services
python tools/matter/tests/chip_tool_memory_capacity.py --chip-tool <tool> --paa <paa> --output <dir> --discriminator 3860
```

Full two-instance regression uses the existing `runtime-pair-host` and
`chip_tool_three_phase.py --source-registers --meter-services` under Memcheck,
then separately ASan/UBSan/LSan. Individual frame probes and saturation arithmetic
are separate from that interoperability evidence.

Changed files: PASE/CASE implementations and lifetime comments; shared private
handshake-buffer helper; allocation tracker hooks and existing PASE/MRP/CASE
tests; native allocation and private-header inventories; external capacity
driver; layout/stack probe definitions; runtime/status/inventory documentation
and this report/results. All serve phase ownership, regression or budget evidence.

Not verified: linked/physical ESP32 peak or task high-water, target allocator
fragmentation/endurance/latency, exhaustive simultaneous request/event/TX
saturation, full OTA provider campaign or official CSA rerun. Next task: bound
whole-node reporting/snapshot demand and examine persistent per-session RX
storage, without weakening the promised per-fabric guarantees or ACK lifetimes.
