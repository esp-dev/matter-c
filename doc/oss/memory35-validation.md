# Memory35: phase-owned Operational Credentials workspaces

Baseline Memory34 is committed as `b7289d2`. The Operational Credentials model
replaces resident `tbs[1040]` and `csr[512]` with per-operation heap storage.
Public signatures, command limits, TLV responses, candidate-key publication,
fail-safe and session/challenge binding remain unchanged. Final source-matched
measurements and validation are recorded in [results](memory35-results.json).

## Ownership, phases and failure handling

Attestation and CSR start retain only the nonce and session challenge. PREPARE
allocates a 512-byte CSR scratch buffer only for CSRRequest. The synchronous port
retains the staged key handle, never the borrowed DER buffer. A shared TLV encoder
first measures, then writes elements using the same CSR and one timestamp.
Both passes retain the original 900-byte elements budget. The exact allocation
adds a 16-byte challenge tail (maximum 916 bytes); CSR scratch is securely erased
and freed before leaving PREPARE, on success and every error path.

SIGN consumes elements plus challenge and erases the challenge tail immediately.
CSR publication retains the existing staged/candidate-key transition. Elements
remain stable through SIGN/PUBLISH/READY, until poll copies the full response
into the caller's writer. They are then securely erased and freed. The published
candidate, session and challenge binding survive response release and subsequent
attestation, until the original consume/rollback boundary. Key material remains
owned by the existing backend.

Fabric commands retain an exact-size copy of their validated request (maximum
1024 bytes), independent of the caller input. PREPARE frees it immediately after
the synchronous Fabric operation finishes. Scalar certificate responses need no
new workspace. Nonce-only start, idle process/poll and output cleanup do not
allocate. Cancel and DISCARD release workspaces immediately, even when backend
key discard must be retried. The model remains busy around port callbacks,
allocations, erasure/free and response copy; reentrant mutation is rejected.

Direct workspace OOM returns ResourceExhausted. Failure before CSR generation
creates no key; failure after generation preserves staged-key ownership until
discard completes. Backend failures retain their existing mapping. No partial
response is published by these new allocation failures. IM still owns response
snapshots, report ciphertext and ACK/drain resources after copying; freeing
Operational Credentials workspace cannot free those objects.

## Size, overlap and stack

The matching C6 debug ELFs show context size **2016 -> 464 bytes**, saving
**1552 resident bytes per instance**. The old TBS starts at offset 409 and occupies
1040 bytes; the replacement pointer is 4 bytes at offset 412. The separate inline
512-byte CSR is gone. Writable allocated ELF sections and normal SDK configuration
defines match Memory34, including UART 1000000 and the 12800-byte owner task.

The mock backend exercises 900-byte elements, 916-byte signed input, 512-byte CSR,
973-byte outer response and 1024-byte request copies. CSR scratch overlaps its
encoded elements briefly during PREPARE; it is not a single shared scratch
buffer. The maximum 512-byte CSR yields 553-byte elements, so that pair requests
512+569 bytes. Attestation requests at most 916 bytes, and Fabric requests at
most 1024. These payload sizes exclude allocator metadata, backend crypto and
the rest of the runtime. Resident savings are not a guaranteed reduction at
every instantaneous heap peak.

Using the measured C6 context plus requested workspace payloads gives these
model-only ceilings (the old context alone occupied 2016 B in every phase):

| Phase | Context + requested workspace |
| --- | ---: |
| Idle / nonce-only admission | 464 B |
| Attestation elements at the 900-byte limit | 1380 B |
| Maximum CSR scratch overlapping its encoded elements | 1545 B |
| Maximum CSR after PREPARE | 1033 B |
| Maximum Fabric request copy | 1488 B |

These sums exclude allocator bookkeeping, the generic cluster interface, backend
key/crypto allocations and owner call-stack frames. They are ownership budgets,
not a bound on the whole node's heap or compliance workload.

GCC `.su` files show process 64 -> 48 bytes, elements 48 unchanged, and new helper
frames prepare_elements 32, encode_elements 32, allocate_tbs 16, clear_tbs 16 and
erase_free 16. The measuring initializer can add 16 bytes. For example, the
process/prepare/elements/encoder chain can use 48 more bytes than the old
process/elements chain before common encoder descendants. Free/cleanup paths
also add bounded helper frames. No large stack array or shared static buffer is
introduced. Individual frames and runtime watermarks are not a worst-case bound.

## Native regression coverage

New `test_opcreds_memory` and its allocator-instrumented variant exercise phase
lifetime, exact limits, immutable copied responses, input overwrite after start,
all new allocation sites, retry, full-allocation secure wipe and reentry from
port/allocation/free callbacks. Cancellation covers PREPARE, SIGN, PUBLISH and
READY, including an already published candidate. Backend prepare/sign/publish
failure, malformed CSR sizes 0/513, revoked or changed challenge, timestamp error,
and pending/error discard retries are covered. Fixtures containing large byte
arrays live on the heap.

The existing real-crypto Operational Credentials test is additionally registered
with allocation injection (`test_opcreds_alloc`), preserving actual signature,
CSR, candidate replacement and Fabric behavior checks. The focused six tests
include both Opcreds variants, both new memory variants, Fabric and root allocator
coverage. The test inventory contains 270 mapped files and 109 native definitions.

## Measurements and full validation

The normal C6 image uses IDF 6.1, the unchanged SDK configuration, a 100 ms
internal 8-bit whole-heap sampler and 12800-byte owner task. COM23 runs at 1000000
baud with TL-MR3020. Each profile restores the fresh Memory35 pre-test NVS and
matching controller state. COM24 is untouched.

| Normal profile metric | Memory34 | Memory35 |
| --- | ---: | ---: |
| Resident Opcreds context | 2016 B | 464 B |
| Sampled whole-heap peak allocated | 333104 B | 331396 B |
| Sampled minimum free heap | 83400 B | 84920 B |
| Sampled minimum largest free block | 57344 B | 61440 B |
| SDK minimum free watermark | 81328 B | 82780 B |
| Core requested-byte peak | 238756 B | 237288 B |
| Observed owner stack used | 3288 B | 3288 B |
| Cleaned core live bytes | 0 B | 0 B |
| Cleaned whole free heap | 390204 B | 390188 B |
| Cleaned largest free block | 262144 B | 303104 B |

Memory35 normal elapsed 294.6709 seconds, with 51 full 171-attribute Reads,
15 subscription snapshots, three parallel-Read rounds, three Fabric publication
rounds, four live own-fabric removals and held-completion/drain checks. Healthy
operation errors, unexpected subscription closures and SDK allocation failures
are all zero. Measured peak falls 1708 B and minimum free rises 1520 B; the sampled
largest-block floor rises 4096 B. The post-stop largest block is larger while total
free differs by 16 B. This is allocator placement in a single run, not evidence
that fragmentation has been eliminated. SDK Wi-Fi/lwIP, runtime and other tasks'
heap allocations are included; statically reserved memory is separate, and
100 ms sampling may miss short peaks. Compare only normal images for whole heap.

The normal-image fault run passes in 459.4573 seconds: 76 full Reads, 45
subscription snapshots, 30 CASE pairs, one global OOM, one reconnect, one RX-loss
cycle and one held completion. OOM ends one subscription, then full 15 load is
rebuilt (the same recovery branch as Memory34). The loss cycle rejects no
operations and needs no subscription rebuild. There are 36 deliberate RX drops,
zero healthy-operation errors/unexpected closures and zero SDK allocation
failures; tracked core failures increase 13 -> 14 as the injected OOM is consumed.
Whole-heap sampled peak is 316864 B, minimum free 101224 B, minimum largest 79872 B,
and SDK watermark 99476 B. Observed owner stack use is 3176/12800 B, compared with
3288/12800 B in the normal profile; this is path coverage, not a reduced stack
requirement. Drain reaches zero core bytes/live allocations.

Fault-run cleaned whole free is 390188 B and largest free 151552 B, versus
Memory34's 390200 B and 258048 B. The largest block is 106496 B lower despite only
12 B less total free. This is a worse fragmentation observation and is retained,
not averaged away with the better normal run. Existing [Memory21](memory21-validation.md)
attributed similar placement-sensitive holes to persistent SDK mutexes, but this
Memory35 run has no new paginated heap-walk attribution or settled 5-second map;
its exact remaining allocation placement is not established. Zero core live
bytes excludes retained core workspace, not all SDK fragmentation or retention.
No SDK OOM or workload failure accompanies this observation.

The separate allocation-observer run passes in 296.0608 seconds with 51 full
Reads, 15 snapshots and no healthy-operation errors. All 18 decoded dumps match
the exact observer ELF and have consistent byte/count totals. There are 130/160
site slots, 1141/2048 peak live records, no overflow, and a final zero-live dump.
Attribution metadata is 19596 B; observer core requested-byte peak is 238596 B.
Its extra static footprint makes whole-heap comparisons with normal images
invalid. Captured Opcreds context allocations are 464 B; one peak map contains
a 292-byte TBS allocation. Phase snapshots do not capture every short-lived CSR
scratch; direct native allocation hooks establish that lifetime separately.

Windows native coverage is 112/112 after explicit-name retries of three UDP
tests outside the sandbox. Initial sandbox failures are retained: all three
timed out in wait_event; there was no source change between attempts. The six
focused tests and all six wire cases pass. Original-peer single-ACK tests retain
their expected 14/15 diagnostic result; corrected-peer variants check full 15
survival. An initial wire launcher pointed at a missing executable and exited
before starting a case; the corrected artifact path was then used for the full
run. These setup failures are not relabelled as protocol passes.

Normal Memory35 firmware and the fresh Memory35 pre-test NVS are restored.
The original controller's RGB test passes (nine updates, concurrent transitions,
final off), exactly one original fabric remains, and final drain reaches zero
tracked bytes/live allocations without SDK OOM. COM23 and TL-MR3020 are free;
the temporary Wi-Fi profile/XML are removed, Windows IPv6 remains enabled and
COM24 is untouched. No keys, AP configuration or controller/device state enter
the public report or commit.

The Linux Memcheck build passes 109/109 native tests, all six full two-instance
checks, and all six wire cases, with zero errors and zero exit bytes/blocks.
The separate ASan/UBSan/LSan build also passes 109/109 native tests, all six
two-instance checks and all six wire cases, without sanitizer diagnostics.
Both Linux builds and the Windows/normal-C6/observer-C6 build logs have no new
compiler warnings/errors. Final source hashes, binary/ELF provenance and
complete Linux results are collected in the results JSON. Memcheck checks zero
exit bytes/blocks for the full pair and each wire case; ASan leak detection is
enabled in the separate sanitizer run.

The VM receives 837 public source/test files; raw SHA256 hashes are verified
after transfer. Tested C/H/Python/MJS/CMake content matches the working tree
after newline normalization. Normal and observer binary/ELF hashes are retained
separately, and each physical profile records its flashed binary hash. The
observer differs in only the allocator and application audit hooks. Local keys,
AP configuration, build trees and controller/device state are excluded from the
source transfer and commit. Curated results retain source hashes and public
metrics, with repository-relative decoded source locations.

Executed command families (complete arguments and raw logs stay in the ignored
laboratory directories):

```text
cmake --build <windows-build> -j3
ctest --test-dir <windows-build> --output-on-failure -E runtime_wire
ctest --test-dir <windows-build> --output-on-failure -R "^(test_opcreds_memory(_alloc)?|test_opcreds(_alloc)?|test_fabric|test_root_alloc)$"
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

Memcheck precedes a separate ASan/UBSan/LSan build. Sanitizer environment enables
ASan leak detection/halt-on-error and UBSan halt-on-error/stacktraces.

## Scope and next task

Changed production files are `main/apps/matter/clusters/matter_opcreds.c` (shared
encoding/secure cleanup and phase ownership) and its header (lifetime/OOM contract).
`tools/matter/tests/test_opcreds_memory.c` adds direct lifetime/failure tests;
`test_opcreds.c` updates the newly introduced CSR-scratch OOM expectation.
`cmake/test-cases.json` and `doc/oss/test-map.json` register three additional native
definitions and the new mapped file. README, runtime contract, status, this report
and the results JSON document evidence and limits.

No new official CSA, Apple/Google Home pairing or matched ESP-Matter benchmark is
claimed. Next task: repeat the post-fault teardown with Memory21's bounded
settled samples and paginated heap attribution, using the matching diagnostic
ELF, to explain the lower largest free block before selecting another RAM change.
