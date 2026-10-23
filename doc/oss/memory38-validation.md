# Memory38: phase-owned OTA Requestor memory

OTA Requestor's C6 resident context shrinks **5704 -> 344 B**, saving **5360 B**.
The normal image keeps the original startup after the rejected Memory37 RMT
experiment. All public signatures, persisted defaults, TLV shapes and limits stay
unchanged. See [structured evidence](memory38-results.json).

## Ownership and failure handling

- Input readers, validation workspace and all 128 tag slots allocate only for a
  synchronous validated command/list operation (1872 B). Limits remain 1024 input
  bytes, 512 metadata bytes, 256 tokens, 2048 comparisons and depth 4.
- The parser borrows metadata only through that synchronous call. Before successful
  start returns, an accepted offer owns its copy. Five pointer slots retain the
  existing latest-announcement-per-fabric policy; each pending public offer is
  544 B. Replacement is published only after parsing/allocation succeeds. An old
  pending offer survives OOM; selected providers still use live fabric generations.
- A shared encoding allocation helper owns the 336-byte writer/token/256-byte
  output span. Scalar reads need no allocation. Read output survives until the
  documented next read/process/state-event operation; IM immediately copies it.
  Event output releases after the event log has copied it, including error paths.
- Default selection still precedes the queued announcement for each fabric. Its
  temporary offer allocates only when defaults await delivery. OOM preserves all
  delivery flags/offers and returns normal process success so runtime reaches the
  dispatcher and ACK/TX can release memory. The next owner iteration retries.
- The five-entry provider cache/snapshot remains small and fixed; refreshing every
  owner iteration allocates nothing when there is no delivery. Storage success
  remains the Write commit; no fallible read/allocation follows model publication.

A conservative OTA-owned requested-payload bound is 344 + 1872 + 336 + 5*544 =
**5272 B**, below the old always-resident 5704 B. This is not a whole-runtime bound:
allocator metadata, cluster/framework objects, event records and user callbacks
are excluded. Default delivery uses a different phase, without parser/encoding.

## C6 memory and protocol results

Matched fresh initial NVS/controller state, C6 COM23, UART 1000000, TL-MR3020.
The fixed workload holds five fabrics and fifteen sessions/subscriptions, overlaps
full Reads with three Fabric publications and performs four live Fabric removals.
Both fixed runs finish with largest free block 262144 B and zero core live bytes.

| Workload | Sampled heap peak B | Min sampled free B | Min sampled largest B | SDK min free B | Observed owner stack B |
|---|---:|---:|---:|---:|---:|
| Baseline fixed profile | 331456 | 84804 | 60416 | 82728 | 3176 |
| OTA fixed profile | 326256 | 90172 | 63488 | 88048 | 3160 |
| OTA fault workload | 310792 | 107208 | 79872 | 104640 | 3192 |

The matched whole-heap peak decreases by **5200 B**; minimum sampled free increases by
**5368 B**. Timing/SDK allocation variation means these are observations,
not an exact attribution of every byte or an all-traffic bound. Whole-heap samples
include SDK/Wi-Fi allocations and heap-backed task resources; static data is not
part of the allocated-heap counter. SDK lifetime watermark and largest blocks are
reported independently. All three physical runs have zero SDK allocation failures
and healthy-operation errors. The fault run covers consumed OOM, RX loss,
reconnect/rebuild, held TX completion and full ACK/drain; deliberate-fault losses
and rebuilt load counts are retained individually. No runtime/resource limit or
ACK policy was reduced. All terminate with zero core objects/bytes and successful
heap integrity checks. Owner stack reservation remains 12800 B.

C6 compiler frames: constructor 160 B; command start 64 B; input/metadata helpers
64 B; Write/Read/state/error at most 48 B; process 32 B. There is no large new task
stack workspace. Frames and ELF layout are recorded; these are not a complete
worst-case stack proof for all SDK/user callback chains.

## Host validation and reproduction

Windows: full build and **112/112 CTest** pass. The extended Requestor tests cover
all new parser/queue/read/event OOM positions, zero-allocation idle/scalar work,
retry, five queues, latest-wins metadata copies, port failure, generation changes,
provider reentry, instance isolation and atomic Write/state/event failures.
Two concurrent multipart Read/Subscribe captures keep values and DataVersion
stable across provider mutation/free/reencoding with both IM/MRP ACK orders.

Linux: **109/109 native CTest** in each build. Full two-instance lifecycle (six
checks) and all six wire cases pass under Memcheck, then separately ASan/UBSan/LSan.
Memcheck reports zero errors and zero exit bytes/blocks. Build/sanitizer diagnostics
are absent. Native CTest is separate from the Memcheck-wrapped full scenarios.
The final exported source hashes are verified; ignored/private files are excluded.

Representative commands (use the existing configured toolchain/build directories):

```text
cmake --build <build>
ctest --test-dir <build> --output-on-failure
ctest --test-dir <build> --output-on-failure -R '^test_ota_requestor(_alloc)?$'
python tools/matter/tests/runtime_wire.py --host <runtime-wire-host> --node <node> --modules <pinned-modules> --case all --output <wire-output> --memcheck
```

For the sanitizer build, run separately with leak detection and halt-on-error,
without Memcheck. The pair fixture uses the existing complete two-node controller
scenario. Physical fixed/fault tests use the unchanged `soak.mjs` oracle,
`MATTER_SOAK_MEMORY_PROFILE=1` only for the fixed profile, 171 expected attributes,
and the explicit corrected peer in the C6 lab; role-negative wire controls retain
the original peer and its expected 14/15 outcome.

An earlier, superseded prototype's ordinary wire `after` attempt observed 14/15
initial subscriptions before intentional faults (zero healthy errors/unexpected
client closures). There is no packet trace assigning its cause; it is not claimed
fixed by OTA. All final six-case gates pass. A second superseded worker was stopped;
its partial results are not promoted to final validation. No new CSA, Home pairing
or reference ESP-Matter result is claimed.

Next: measured Read/Subscribe block occupancy. Normal firmware/original fabric
restoration and network cleanup are recorded after that separate audit.
