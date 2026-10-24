# Memory09: concurrent reporting storage and transient secure RX

Baseline: `e09beb4`. Public provider/session APIs and layouts, wire encodings,
512 expanded results,4096-byte encoded values,16384-byte report payload budget,
fabric/session/subscription admission and report deadlines remain unchanged.
Application ownership of scheduling, per-instance storage and lifecycle remains.

## Changes and delivery gates

Read/Subscribe share a private compact captured value: type, DataVersion and a
union holding either one scalar or an immutable encoded span. The provider DTO
is unchanged. Signed/unsigned extremes, Boolean/null, strings and both container
types retain their encoding. Subscribe evaluates the provider's report policy
before storing the compact value; that flag is not needed during serialization.

Subscribe's persistent item table retains paths, activation/status and reported
versions. Its compact value table is allocated for the exact expanded count only
when a data report is captured. Idle subscriptions and heartbeat-only processing
keep no value table. Allocation failure produces the existing ResourceExhausted
response, without publishing a partly captured successful report. Earlier copies
remain owned until their normal cleanup; no global arena or scheduling quota is
introduced.

The chunk cursor advances only past completely encoded attributes. Once BOTH
MRP confirmation and a successful continuation StatusResponse have arrived,
Read/Subscribe unlink and free those consumed value nodes. A partial ARRAY keeps
its complete copy through all remaining ADD fragments. Permissions are still
rechecked for remaining data; providers are not read again while encoding or
retrying. Status-before-ACK and ACK-before-status retain the same gates. Malformed
or failed statuses cannot advance a successful continuation. Immutable MRP packet
ownership is unchanged and independent of value nodes.

Releasing consumed nodes does NOT decrement the cumulative encoded-byte counter.
Only whole-report cleanup resets it: reclaimed heap cannot silently increase the
admitted16384-byte report budget. Final Read confirmation frees remaining value
nodes; Subscribe frees its value table before response/idle. Cancel, timeout and
failure leave remaining value storage subject to owner transport drain/delete.
The linked-node release search is bounded by the existing result/byte ceilings;
it adds no allocations, and remaining value addresses never move.

Secure session plaintext is allocated at the candidate plaintext length for
synchronous receive only (one byte for a malformed empty candidate).
Header/path/size checks run first. Allocation failure returns LIMIT_REACHED before
crypto, admission, replay commit or timestamp changes. Every success/error path
erases and frees plaintext; admission must still copy into its own RX queue.
Duplicate authentication and MRP metadata, retain/release during admission,
counter commit, keys, handoff, close and ACK/drain behavior remain unchanged.
The maximum scratch request is1208 B under the unchanged1232-byte packet ceiling.

## ESP32 compile-only layouts and stack

GCC13.2.0, C99, `-Os -Wall -Wextra -Werror -fstack-usage`; no linked firmware.

| Private layout | Before | After |
| --- | ---: | ---: |
| Read owner |280 B |288 B |
| Read expanded item |72 B |48 B |
| Subscribe owner |328 B |336 B |
| Subscribe persistent item |72 B |24 B |
| Subscribe captured value |included above |16 B, report only |
| Secure session owner |1552 B |320 B |

A saturated attribute-only Subscribe owner/results/value-data/node-links subtotal
is now `336 +512*24 +512*16 +16384 +512*4 =39248 B`, previously55624 B.
Fifteen such subtotals fall834360 ->588720 B (about815 ->575 KiB), before
input/output, selectors/filters, parser, event snapshots, growth overlap, peers,
allocator, crypto and application/platform resources. This is configured-cap
arithmetic, not normative RAM, a complete node bound or an ESP32 fit claim.
Idle512-path subscriptions retain the24-byte persistent entries without the
8192-byte captured-value table or value nodes. Full512-result Read tables need
24576 B versus36864 B; a large table still needs a contiguous allocation.

Fifteen idle CASE session owners save18480 B, or19712 B including the separate
PASE session bucket. Simultaneously active receive calls on independent instances
still need separate scratch. Same-session reentry remains BUSY. New transient RX
allocations add allocator churn/metadata; no fragmentation or latency guarantee
is inferred from the owner reduction.

| Compiler frame | Before | After |
| --- | ---: | ---: |
| Read process |160 B |160 B |
| Subscribe process |208 B |208 B |
| Read report encoder |48 B |48 B |
| Subscribe attribute encoder |48 B |48 B |
| Secure receive |112 B |128 B |

Compact values load directly into the existing heap owner DTO, avoiding an extra
returned DTO on the encoder stack. No large parser/value buffer was moved onto
the stack. Individual frames are not whole call-chain or RTOS high-water values;
crypto, transport, libc and callbacks also contribute.

## Saturated component workload

The same new public-API harness was compiled against baseline and final core in
separate builds. It holds fifteen CASE-bound Subscribe engines across five fake
fabric identities, each with512 BYTES values of32 encoded bytes: exactly16384 B
per report. All first outputs remain outstanding together. It then adds five
Read engines with nine large ARRAY values each (55 BYTES entries per array,
1762 encoded bytes,15858 payload bytes per Read). Those Reads remain outstanding
while subscription chunks drain round-robin. Provider scratch is overwritten
after capture, each delivered byte is independently checked, both ACK/status
orders alternate, and provider read counts cannot increase during delivery.

All7680 subscription values and45 arrays/2475 Read list entries arrive unchanged.
Each subscription uses57 chunks. These are engine instances, not actual concurrent
network sessions/dispatcher capacity proof. The separate full-host controller
scenario covers real composition. Requested production allocation bytes below
instrument Read and Subscribe only, excluding test fixtures/tracker metadata,
libc allocator overhead, networking, crypto and other host resources.

| Windows x86_64 component payload | Before | After |
| --- | ---: | ---: |
| Fifteen reports captured |1008840 B |701880 B |
| Plus five outstanding nine-path Reads |1125225 B |816865 B |
| Halfway through subscription delivery, Reads still held |1124955 B |659995 B |
| Subscriptions idle, Reads deleted |701370 B |210090 B |
| Observed tracked allocation peak |1127553 B |819193 B |
| Largest individual request in this workload |45056 B |12288 B |

Peak saving308360 B (27.3%); idle saving491280 B (70.0%). This deliberately
heavy supported-cap workload still exceeds a small ESP32 internal-RAM budget
before the rest of the system. It cannot establish the RAM needed for every
conforming device: model sizes, expanded wildcard results, retained events,
overlapping traffic, platform/backend and declared capabilities all matter.

## Validation and reproduction

Local validation: full Windows CTest92/95 in the restricted sandbox; the exact
three socket failures (`test_udp_windows`, `test_unsecured_tx_windows`,
`test_udp_windows_alloc`) pass3/3 with local socket access. After the final
malformed-status cleanup review, focused Read/Subscribe/snapshot/secure/MRP tests
pass9/9. Builds have no compiler diagnostics; all27 ESP32 probes pass. The same
jscpd4.0.5 scan of66 implementation C files finds7 clones/69 duplicated lines
before and after. Headers/tests are excluded; no linked flash-size claim.

The allocation variant faults all14 allocations of a nine-value initial capture
and both continuation-RX allocations in each ACK/status order (four faults).
Other retained tests cover yielded parser OOM, result growth/overflow, per-value
OOM, unchanged cumulative limits, partial lists, permissions/version filtering,
events, cancellation/timeout, and independent MRP ownership. A new secure
allocation target checks rejected plaintext allocation, unchanged replay/time,
retry, backend OOM and zeroization at free, alongside existing crypto/replay/
handoff/exhaustion/reference tests. This is not exhaustive allocator-fault
coverage of every host workload or backend-internal allocation.

Linux CTest passes92/92 in normal and separate ASan/UBSan/LSan builds. The full
two-instance three-phase/source/meter-services scenario passes6/6 under Memcheck
and6/6 separately under the sanitizers, with clean process exits and empty stderr.
Dedicated saturated-report/OOM, Read and secure-session Memcheck runs report zero
live blocks, errors and suppressions. The native one-host five-fabric capacity
driver passes50/50 checks at a3-second maximum interval. Whole-host Massif at a
30-second interval also passes50/50 checks; all16 controller processes exit zero
in both runs. The saturated component workload separately passes ASan/UBSan/LSan,
with the same requested-byte profile as normal and Memcheck. Private ignored data and controller states
are excluded from the source transfer and portable evidence.

The same full Linux x86_64 Debug host composition and capacity driver used in
Memory08 yield these largest sampled Massif values (`--stacks=yes`):

| Whole-host sample | Memory08 | Memory09 |
| --- | ---: | ---: |
| Allocated heap payload |413884 B (404.18 KiB) |388317 B (379.22 KiB) |
| Largest used stack sample |6744 B |6752 B |
| Heap + allocator metadata + used stack |424368 B (414.42 KiB) |399176 B (389.82 KiB) |

The new heap and combined maxima coincide:388317 B payload,5387 B allocator
overhead,5472 B stack. The6752-byte stack maximum is a separate early snapshot;
do not add independent maxima. Heap reduction25567 B (6.2%) and combined
reduction25192 B (5.9%) apply to these observed runs. Larger reductions in the
saturated component workload reflect its much larger wildcard expansion/value
population; the live host workload keeps fifteen three-path subscriptions and
checks nine-path Reads, heartbeats, Writes and protected-session admission.

Massif includes allocator-visible host/application/Mbed TLS allocations, excluding
controller processes. It is sampled, includes reference Linux discovery/network
adapters, and excludes ESP-IDF, radio/lwIP, target allocator/ABI and RTOS task-stack
reservations. Neither sampled Linux stack nor compiler frames determine the ESP32
task stack. No universal worst-case heap/stack bound or normative RAM requirement
is claimed. Results and source/evidence hashes are in
[memory09-results.json](memory09-results.json).

```text
cmake --build build/memory01/windows -j4
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_udp_windows|test_unsecured_tx_windows|test_udp_windows_alloc)$" --output-on-failure
ctest --test-dir build/memory01/windows -R "^(test_im_read|test_im_subscribe|test_im_read_alloc|test_im_subscribe_alloc|test_im_snapshots|test_secure|test_secure_alloc|test_case_mrp|test_mrp_pair)$" --output-on-failure
test_im_subscribe_alloc --memory-only
python tools/matter/check_test_map.py
python tools/matter/memory_audit.py --cc <xtensa-gcc> --nm <xtensa-nm> --output build/memory09/esp32
# Linux normal and separately MATTER_SANITIZE=ON: CTest and runtime-pair-host
# with chip_tool_three_phase.py --source-registers --meter-services.
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 test_im_subscribe_alloc --memory-only
# Same Memcheck options: test_im_read_alloc and test_secure_alloc.
# Native3s, then separate Massif stacks=yes30s:
python tools/matter/tests/chip_tool_memory_capacity.py --chip-tool <tool> --paa <paa> --output <dir> --discriminator 3860 --max-interval <3|30>
```

Changed files and purpose:

- `main/apps/matter/model/matter_im_snapshot_internal.h`: shared compact value
  storage/load and allocation-free removal of consumed immutable nodes.
- `main/apps/matter/model/matter_im_read.c` and `.h`: compact results, consumed
  chunk/final-confirmation cleanup and documented reference lifetimes.
- `main/apps/matter/model/matter_im_subscribe.c` and `.h`: persistent path state
  separate from report-only values, consumed-node cleanup and lifetime contract.
- `main/apps/matter/session/matter_secure.c` and `.h`: exact receive-only plaintext,
  checked OOM, erasure/free and documented retry semantics.
- `tools/matter/tests/test_subscribe_memory.h`: saturated component/Read oracle,
  scratch poisoning, delayed confirmations and initial/continuation fault cases.
- `tools/matter/tests/test_im_subscribe.c`: explicit memory-profile/memory-only
  modes plus default capture/continuation OOM regression.
- `tools/matter/tests/test_subscribe_complex.h` and `test_im_complex.h`: ownership
  assertions updated for confirmed consumed-value/final-Read release.
- `tools/matter/tests/test_im_snapshots.c`: compact scalar/span round trips,
  stable remaining references and non-renewable cumulative limit.
- `tools/matter/tests/test_secure.c`: exact plaintext failure/retry, replay/time
  invariants and existing erasure/backend fault coverage in the registered target.
- `cmake/test-cases.json`: secure allocation target and both Read/Subscribe
  instrumentation for the shared saturated component measurement.
- `tools/matter/memory_audit.py`: compiler-derived compact Subscribe value size.
- `doc/runtime.md`, `doc/oss/status.md`, `doc/oss/test-map.json` and `.md`, and
  `memory09-validation.md`/`memory09-results.json`: contracts, inventory and
  reproducible evidence with explicit scope limitations.

No admission defaults, persistence or unrelated modules were refactored.
No physical ESP32, target allocator endurance/high-water,
exhaustive event/TX/closing-handler saturation or official CSA rerun. Next task:
derive and measure an application-specific whole-node reporting budget, including
event snapshots and closing/replacement delivery tails, before target RAM sizing.
