# Initial embedded memory and duplication audit

Date: 2026-10-20. Baseline: `6977da4f97fbd3b17dcfa173bda912d31d6d6808`.
This pass inventories opportunities; it changes no production C/header, wire
behavior, persistent schema, capacity, PICS or CSA result. The owner's request
authorizes this parallel audit while the original checkout continues CSA work.
Implementation and acceptance remain separate subsequent steps.

The audit follows [roadmap stage 3](../roadmap.md#3-memory-and-code-size-optimization)
and the [runtime ownership contract](../runtime.md). The application continues to
own memory, scheduling, I/O and lifecycle. Limits remain admission ceilings.

## Isolation and evidence

An independent local Git clone includes the baseline's unpushed history, on
branch `work/memory-audit`. It was created with `--no-hardlinks --no-checkout`,
then checked out at the explicit baseline. There is no object alternates file.
The source worktree was clean at capture. Ignored builds, private fixtures,
credentials, stores and `local/` state were not copied. The clone's source is
a local repository; there is no automatic synchronization or publication.
Machine-specific reproduction commands and snapshot paths are retained under
ignored `build/memory-audit/` and `local/`.

The [probe](../../tools/matter/memory_audit.py) compiles 26 actual implementation
translation units with ESP32 Xtensa GCC 13.2.0, `-std=c99 -Os -Wall -Wextra
-Werror -fstack-usage`, transport capacity 56 and event capacity 128 or 16.
Sized ELF symbols measure real compiler layouts, including padding and 4-byte
pointers. Nothing is linked, executed on an MCU or flashed. Marker arrays exist
only in disposable probe objects; they are not part of a library/firmware build.
An attempted MinGW PE/COFF measurement cannot provide the required `nm` symbol
sizes and is not used. The probe explicitly requires an ELF-producing compiler.

Both final configurations compiled all 26 probes without compiler diagnostics.
The [portable evidence summary](memory-audit-baseline.json) records layouts,
source SHA-256 values, tool versions, capacities and duplication results.
Raw commands, objects and function-frame reports are in ignored
`build/memory-audit/{esp32,esp32-events16}/layouts.json` and sibling `.su` files.

## Measured costs

All sizes below are bytes for the ESP32 ABI. These are allocated structure
sizes, not a measurement of live heap, allocator overhead or total firmware RAM.
Most large arrays already live inside a heap-allocated object: changing the
outer allocation mechanism alone saves nothing.

| Owner/resource | Size | Finding and proposed direction |
| --- | ---: | --- |
| Dispatch transaction table, 52 entries | 78,208 | `calloc(count, sizeof(Transaction))` reserves the entire admission budget. Allocate individual stable nodes for admitted work; retain per-fabric and protected-work counters. |
| One Transaction | 1,504 | 1,232 bytes are its packet. Separate live transaction metadata from an immutable pending-TX allocation with an explicit drain lifetime. |
| Dispatch object, excluding transaction allocation | 8,152 | Includes 2,176 bytes for 16 Connection records and 4,928 bytes for four packet buffers. Migrate connections after transaction lifetime is proven; review buffer overlap only from actual I/O ownership. |
| Event log at 128 records | 60,184 | Includes two 29,696-byte record arrays. Store actual live records and stage only the new batch plus an eviction/commit plan. |
| Read event state | 35,256 | Includes 29,696 bytes of event records and bounded selector/expansion scratch. Allocate event-specific state only for actual event requests. |
| Subscribe event state | 35,272 | Same full record allocation, retained for subscription lifetime. Use per-report snapshots sized to matching records, then release after confirmation. |
| Read/Subscribe value snapshot arena | 16,384 each | Allocated on first copied value, including a scalar; retained until handler deletion. Use bounded actual-use segments/offsets or per-value stable allocations. |
| Store host object | 49,104 | Contains a permanent 32,768-byte blob buffer and a 16,160-byte work DTO. Make transaction scratch temporary, with bounded serialized capacity; idle store metadata should remain small. |
| Fabric host image | 15,552 | Persistent live model includes all five fabric slots, fixed certificate arrays and rollback data. Later migrate live internal storage while preserving serialized schema and borrowed public views. |
| Fabric host | 19,688 | Includes a permanent 15,536-byte backup and 1,560 bytes of CASE resumptions. Allocate rollback state for the active mutation and resumptions for actual entries. |
| Storage Codec scratch | 16,280 transient | 16,160 bytes are a DTO needed for atomic decode. Encode walks the supplied DTO directly; split encoder workspace from decoder staging. |
| Read/Subscribe base contexts | 2,120 / 2,720 | Already exclude separate RX/TX, results, event state and snapshots. Measure complete interactions, not just these base sizes. |
| Invoke / Write / outbound IM contexts | 5,600 / 4,288 / 2,968 | Fixed payload buffers: Invoke 4 x 1,024; Write 2 x 1,024 + 256; client 2 x 1,024. Allocate actual input and bounded output on demand. |
| CASE / PASE attempt | 14,112 / 6,384 | Already per-attempt allocations, but several maximum-size buffers coexist. Review phase-specific scratch and transcript ownership; retain cryptographic limits and secret erasure. |
| Secure session | 1,552 | Includes per-session plaintext scratch. Consider request-owned scratch after tracing RX references and session pins. |
| Exchange table / RX object | 1,832 / 3,240 | Both retain capacity-sized exchange bookkeeping. Migrate only with handle, closing and callback-drain invariants preserved. |
| ACK / MRP ledger / MRP sender | 1,856 / 3,176 / 1,016 | Fixed tables scale with transport capacity. Smaller gains than transaction/event/storage work; keep admission and emergency control paths bounded. |
| EPM / EEM cluster context | 5,448 / 632 | EPM reserves all measurement descriptors/ranges plus 3,072 encoded accuracy bytes. Size immutable configuration and encoding to configured measurements; four EPM instances multiply the cost. |
| Optional source-register cluster | 22,512 | Two 8,192-byte arenas plus saved/pending snapshots. Size to the actual configured channel set while preserving atomic publication. |
| Diagnostics / ACL context | 8,488 / 6,384 | Permanent 4,096-byte encoders plus snapshots, pending entries and validation scratch. Separate immutable/live state from operation-specific scratch. |

The transaction table and event log alone total **138,392 B**, exceeding even
128 KiB (131,072 B), before other modules. A non-overlapping subset comprising
those two allocations plus dispatch, store host, fabric image and fabric host is
**230,888 B (225.48 KiB)** for the current default composition. This is a source-
and-layout-derived subtotal of allocations, not an observed idle heap trace;
it excludes allocator overhead and many runtime, application and crypto objects.

Reducing event capacity to 16 lowers the event log to 8,216 B and Read/Subscribe
event state to 9,272/9,288 B. The same subtotal is still **178,920 B**. This is a
comparison only: no default was changed and smaller retention is not a substitute
for the requested memory model or an acceptance result.

`matter_dispatch.c:create_handler` binds event storage whenever the node has an
event log, before knowing whether the incoming interaction requests events.
Thus attribute-only Read/Subscribe also pay the 35 kB event-state cost.
`matter_im_read.c:snapshot` and `matter_im_subscribe.c:copy_value` reserve the
full 16 KiB arena on first use. Subscribe resets its used length between reports
but does not release that arena or its event allocation until deletion.
The base Subscribe, bound event state and 1,198-byte output alone cost 39,190 B;
the arena adds another 16,384 B, before input/results or transport allocations.

Source entry points: `runtime/matter_dispatch.c` (Transaction, create_handler,
admit_work, delivery_slot, new/delete), `model/matter_events.c` (prepare/finish),
`model/matter_im_{read,subscribe}.c` (event binding, snapshots, growth, cleanup),
`runtime/matter_store_host.c` (capture/save), `runtime/matter_fabric_host.c`
(before/after), and `storage/matter_store_tlv.c` (Codec and encode/decode).

## Duplication scan and manual assessment

jscpd 4.0.5 scanned the **64 C implementation files** under `main/apps/matter`;
headers, host adapters, tests, dependencies and generated artifacts are outside
these statistics. The default mode with `--min-lines 8 --min-tokens 60` reports
**8 clones / 75 duplicated lines / 0.56%**. The sensitive `--mode weak
--min-lines 5 --min-tokens 40` pass reports **63 candidates / 380 lines / 2.84%**.
Modes count different input lines; candidates can overlap. Neither percentage
measures semantic duplication, removable code size, defects or flash savings.
Changing identifiers or expressing the same operation differently can evade
the scan. All eight default hits and representative sensitive groups were read.

| Candidate | Evidence in the baseline | Assessment |
| --- | --- | --- |
| Bounded result growth | Read 513-524; Subscribe 371-382 | Nearly identical checked geometric allocation/copy/replace. A private vector-growth helper can preserve element sizes, counters, overflow/OOM rules and old allocation on failure. |
| Snapshot TLV normalization/validation | Read 366-375; Subscribe 291-300 | Shared mechanism suitable for a private snapshot helper/arena. Preserve the current container validity and error-mapping differences until tested explicitly. |
| DataVersion matching | Read 459-467; Subscribe 303-311 | Extract matching predicate over a common private filter representation. Conflicting versions must keep their current behavior. |
| IM cursor/field collection and scalar checks | Invoke 76-104; Write 60-88; Subscribe 136-154 | Common TLV container traversal, bounded field collection, duplicate LIST-field detection and scalar validation. Keep message grammar, revision handling, budgets and state transitions with each owner. |
| Saturating deadline arithmetic | Query 13; Apply 12; Subscribe 55; Read 73; Invoke 33/298; Write 37/312; others | Manual semantic finding beyond the block threshold. A small private checked/saturating time utility is already planned in the roadmap. Preserve reject-on-overflow cases such as Admin Commissioning rather than silently saturating every caller. |
| Secret erasure | `erase`/`wipe` helpers in runtime, sessions, storage and crypto | Review one private implementation with compiler-safe semantics and existing validation requirements. Do not replace secure erasure with ordinary memset. Savings require a linked measurement. |
| Diagnostics/Wi-Fi attribute branches | 18 sensitive intra-file Diagnostics hits; 5 Wi-Fi hits | Similar scalar encoding often has distinct identifiers, nullability and state. Prefer small encoding primitives or descriptors only where they simplify semantics; low priority. |
| Codec encode/decode traversal | Default intra-file hit at 53-61 / 91-99 | Symmetric operations are not interchangeable. Retain separate encode/decode direction and atomic decode behavior. Splitting Codec scratch has a clearer memory benefit than merging traversal. |
| Transport lookup / PASE versus CASE | Sensitive transport comparisons and session-output fragments | Similar syntax does not justify one generic state machine. Session pinning, handshake secrets, retry and retirement semantics differ. Share small typed predicates only when their contracts match. |

Existing shared mechanisms are worth extending: `matter_im_paths_internal.h`,
`matter_im_events_internal.h`, `matter_utility_internal.h`, the TLV validator,
the generic storage Field codec and the centralized host admission limits.
They already avoid some duplication; new helpers should build on them.

Raw reports: ignored `build/memory-audit/duplicates/jscpd-report.json` and
`build/memory-audit/duplicates-sensitive/jscpd-report.json`. The portable evidence
summary also retains both scans' statistics and all file/line pairs.

## Proposed implementation sequence

1. Record observed allocation sizes, current/peak bytes, largest allocation and
   fragmentation for idle, PASE, CASE, one and fifteen subscriptions, Read burst,
   fabric mutation and OTA. Include crypto/storage and application task stacks.
   Keep a stable baseline revision and independent two-instance scenarios.
2. Separate encoder scratch from atomic decoder DTO, then make the store's
   temporary work/blob and fabric backup operation-owned. Preserve persistence
   failure rollback, secret wiping and supported schema 1..7 compatibility.
3. Change event binding to store only the borrowed port until events are needed.
   Use count-then-snapshot collection on the serialized owner thread. Preserve
   ACL/fabric checks and report consistency; do not retain borrowed log-record
   pointers across eviction, callbacks or multi-chunk delivery.
4. Migrate Transaction storage to individually allocated stable live nodes and
   packets to pending-TX ownership. Remove free-slot scans; preserve quotas with
   counters, including replacements, rejection capacity and ACK/draining work.
5. Migrate event-log retention and batch staging. `prepare` must perform every
   fallible allocation and persistence operation; `finish` remains infallible.
   Preserve number reservations, priority eviction, fabric removal and abort.
6. Introduce a common bounded snapshot/growth mechanism for Read/Subscribe,
   then migrate Invoke/Write/client buffers. Stable value references must survive
   chunking and OOM; a moving realloc requires offsets or pointer rebinding.
   Release report payloads only after all callback/I/O/ACK users have drained.
7. Migrate lower transport/connection tables and optional cluster encoders after
   their larger owners are measured. Then review phase-local CASE/PASE/crypto
   scratch. Consolidate the small shared time/TLV predicates in scoped steps.

The **first implementation task** should be splitting storage encoder scratch
from decoder staging: encode currently allocates a 16,280-byte Codec although
it serializes the caller's DTO directly. Its embedded 16,160-byte data image is
used meaningfully by decode, not encode. This is a bounded change with a clear
peak-memory benefit and existing storage/alloc-failure coverage. It is not yet
implemented. Event binding is the next high-value, separately reviewable change.

Use intrusive lists for live transactions/sessions when stable addresses matter;
use bounded segments/spans for payload bytes. Lists remove empty-slot scans but
lookup over live nodes is still O(n). Do not replace fixed keys, nonces, hashes,
small protocol fields or `static const` attribute/dispatch tables with lists.
Keep a small measured emergency ACK/rejection reservation if OOM handling needs
it; document that exception. Preserve the owner-thread model and separate
allocations between instances. Account for allocation overhead, fragmentation,
old-plus-new growth peaks and bounded work per process call.

## Validation and limits

Executed: two final complete sets of 26 compile-only ESP32 probes, both jscpd
scans, manual source/caller/lifecycle review and Python syntax validation.
Production source/header content matches the baseline under Git's line-ending
normalization. The original checkout's CSA documentation continued changing
during the audit; this report remains pinned to the captured revision. The only new
deliverables are this report, its portable evidence JSON and the probe script.
No commits or pushes were made; the original checkout was only read.

No full linked ESP32/ESP-IDF firmware, flash/text/rodata measurement, observed
heap trace, allocator-fault execution, CTest/CSA rerun, Valgrind, sanitizers,
ecosystem or physical-device test was performed. The largest individual frame
in the sampled probes is 576 B (`apply_done`), followed by 432 B
(`matter_runtime_start`); `.su` sizes are not a nested stack high-water mark and
exclude unprobed functions, crypto, libc, interrupts and task context.
No claim is made that the complete firmware fits 128 kB.

Each later runnable-host change must pass focused native and allocation-failure
tests, a complete Linux scenario under Memcheck, and a separate ASan/UBSan/LSan
scenario, with multi-instance isolation, delayed ACK/cancellation/drain, OOM and
persistence-error coverage. Re-run affected unmodified CSA cases and retain
their actual verdicts separately from local acceptance and memory measurements.
