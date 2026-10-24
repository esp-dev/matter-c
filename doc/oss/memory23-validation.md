# Memory23: bounded Fabric undo and committed TLV projection

Memory22 is committed as `13ffe87`. This change reduces publication scratch in
the C host backend used by the ESP32-C6 adapter. Public APIs, schema1..7, five
fabric slots, certificate/ACL/group-key limits and the NVS publication point
remain unchanged. This commit records Memory23. This is laboratory evidence, not an
official CSA rerun or certification result.

## Implementation and ownership

`runtime/matter_fabric_host.c` keeps the stable live image. A mutation allocates
one private undo block containing the header/journal and only the slot fields it
can change. Shared capture, restore, lookup and erase helpers cover root,
AddNOC/UpdateNOC, label/VID, ACL/group keys, rollback and removal. Each operation
changes at most one slot. Saved ranges retain uint64 alignment; unchanged fields
serve as their own old values during revision/resumption checks. Publication
failure restores all saved bytes before releasing scratch. Removed callbacks,
credential/CASE revisions and resumption invalidation still follow successful
publication. Last-fabric reset uses the same undo mechanism.

The private Store publication callback can request a committed projection.
The TLV encoder emits cleared pending-root/journal/previous-key fields directly,
without allocating or mutating another Fabric image. The live pending view stays
unchanged throughout validation, measurement, encoding and the blob callback.
The commissioning owner still applies the combined Fabric/Wi-Fi commit only
after durable publication; no new fallible work follows that point. Named field
ordinals, widths, fixed byte extents and migration gates are unchanged. A 400-byte
constant zero span resides in `.flash.rodata`, not DRAM or the task stack.

The NVS port continues to receive exactly one contiguous TLV buffer. Its exact
length is measured before allocation; codec and small Store staging remain
per-operation heap allocations. Removing the final buffer would require a
different blob-port contract. The live image is also retained to preserve stable
borrowed views and the existing backend contract. No ACK, TX or drain code changes.

## Allocation measurements

Actual C6 layout from the compiled ELF, bytes:

| Operation | Memory22 rollback/candidate | Memory23 undo/candidate |
|---|---:|---:|
| Stage root | 15536 | 576 |
| Label / VID | 15536 | 2512 |
| AddNOC / remove committed fabric | 15536 | 3200 |
| UpdateNOC | 15536 | 4512 |
| Pending removal / rollback with a slot | 15536 | 5168 |
| Final combined commit | 15536 | 0 |

The selected ranges include bookkeeping and rounded payload sizes. A rollback
without a matching pending slot is smaller. The live image remains15552 bytes
including its host wrapper; the underlying DTO is15536 bytes.

Windows allocator payload measurements (excluding malloc metadata): label
publication19425 B transient peak, final committed publication16785 B, TLV15945 B;
ordinary save16785 B. Label has four allocation fault sites; committed publication
has three. A saturated five-fabric/full ACL/key-set/OTA/rotation DTO encodes to
17580 B; codec plus output peak17740 B. These are workload-specific payload sizes,
not a bound on complete device RAM.

## Physical C6 memory and concurrency

COM23 / TL-MR3020, IDF6.1, unchanged normal RGB and optional100ms observer
profiles. The common oracle is byte-identical to Memory22: five fabrics,
15 CASE sessions,15 subscriptions,135 Reads/945 values,22 Invokes,120 updates
in the fully live variant. Both variants receive all four own-fabric removal
responses and preserve other fabrics. Timings:414–622ms live,427–500ms after
local subscription close. Final counters include teardown:

| Common profile, bytes | Memory22 live | Memory23 live | Memory22 local-close | Memory23 local-close |
|---|---:|---:|---:|---:|
| System heap peak,100ms sampled | 256348 | 244480 | 256156 | 244228 |
| Minimum sampled free heap | 163636 | 175504 | 163784 | 175748 |
| Minimum sampled largest block | 147456 | 147456 | 143360 | 147456 |
| Observed main-stack use | 3288 | 3176 | 3160 | 3160 |

The measured publication-workload savings are11868/11928 B. The live run's SDK
minimum-free watermark is173724 B; after owner cleanup free heap390204 B,
largest block245760 B, tracked core0 bytes/allocations. The local-close run ends
at390180 B free and245760 B largest, also core0. Larger end blocks than in the
previous runs describe allocation placement, not removal of SDK singleton holes.
IDF size reports unchanged static D/IRAM:110493 B common,110469 B normal RGB.

The strict normal full-wildcard retry passes:171 attributes,106 complete Reads /
18126 values,15 live subscriptions,20 resumed CASE pairings, one consumed OOM,
one RX-loss window, one physical radio reconnect and an actually held accepted
TX during stop. The held-TX stop waits3.614s; the intentionally interrupted
Read is rejected when the stopped peer no longer responds. There are no healthy
operation errors, unexpected subscription closures or SDK allocation failures.
Controller duration469.94s; UART duration489.03s; sustained/recovery interval269.37s.

The full-wildcard peak is334644 B, sampled minimum free83408 B, SDK minimum
free78272 B and minimum largest block60416 B. This is essentially unchanged
from Memory22's334508/83516/78412/60416 B: concurrent whole-model reports, rather
than Fabric publication, dominate that workload. Do not apply the11–12KiB
publication saving to the overall worst observed wildcard peak. Compiler frames
are160 B for undo capture,48 B for source encoding and32 B per recursive object
encoder; no certificate/DTO was moved onto a task stack. Full-wildcard observed
main-stack use is3288 B of the12800 B reservation.

A separate physical reboot probe writes a distinct label through CASE/Write,
restarts C6, reads that label from NVS and verifies a full171-attribute Subscribe.
Event numbers1728–1729 after restart exceed the prior saved watermark. The
original private NVS/fabric is then restored and the final normal Memory23 image
passes RGB/readback/transitions/subscription checks again. Its owner-thread
teardown has no live tracked core allocation. Temporary Windows Wi-Fi/profile/XML
are removed, COM23 is released and the AP is free; IPv6 remains enabled. The
test runtime is stopped; reset starts the installed normal image again.

**Open stress-test finding:** the first normal wildcard attempt completed15
Subscribe snapshots but immediately reported14 live subscriptions instead of15,
before any OOM/loss injection or sustained Read rounds. It was stopped and retained
as a failed run, not overwritten or counted as a pass. The unchanged full retry
passes, and a separate initial-load-only replay on the exact verified Memory22
normal binary also reaches15/15. That baseline replay is not another full soak.
These observations do not establish the cause or rule out a timing-dependent
regression. No counter expectation, wait threshold, resource limit or production
code was relaxed to obtain the successful retry. Initial-load stability remains
an acceptance limitation requiring further per-subscription TX/ACK tracing.

## Validation coverage

`tools/matter/tests/test_store.c` adds byte comparisons of the committed projection
against the existing contiguous DTO encoder for schemas1..7, saturated limits,
AddNOC, UpdateNOC and root-only journals. Success and each codec/output OOM preserve
the original serialized input. Publication tests verify the live image from inside
the blob callback, absence of another full DTO, all remaining allocation fault
sites, complete RAM/durable-byte rollback and cleanup. Existing file faults,
credential rotation, independent-process restart, key erasure and resumption tests
continue to exercise the same publication paths.

Reproduction uses the existing configured build directories:

```text
cmake --build build/memory16/windows-gcc -j 8
ctest --test-dir build/memory16/windows-gcc --output-on-failure
ctest --test-dir build/memory16/windows-gcc --rerun-failed --output-on-failure
ctest --test-dir build/memory16/windows-gcc -R ^test_store_alloc$ -V
../.tools/idf-v6.1.ps1 -C examples/esp32-runtime -B build/memory21/idf61-compare build
../.tools/idf-v6.1.ps1 -C examples/esp32-runtime -B build/memory16/idf61-rgb build
```

The first Windows run passed99/102; three Windows UDP tests were denied socket
access by the sandbox and all passed when rerun with local network access.
Both IDF builds retain the SDK's five CMake private-include dependency warnings
between esp_wifi and wpa_supplicant; no new C compiler warning was observed.
Linux CTest passes99/99 normally and99/99 separately with ASan/UBSan/LSan.
The complete two-instance chip-tool scenario passes all six groups under
Memcheck and separately under sanitizers. All17 focused Memcheck executions
(including committed/pending Store seed/load, normal and allocation-fault builds)
and the full pair report zero errors and zero bytes/blocks at exit. Source hashes
for all seven changed core/header/test files match the tested VM export.
Raw logs, exact commands, firmware, map/ELF, source hashes and private state are
in ignored `build/memory23` / `local/esp32-c6`. Public numeric results are recorded
in the accompanying JSON. The initial460800-baud NVS read failed its transmission
digest; a115200-baud read succeeded before any test firmware write. Subsequent
flash writes verified their hashes.

## Apple Home / Google Home status

The user reports successful pairing of the pre-optimization stack with both
Apple Home and Google Home. This is useful compatibility history, but the current
optimized C6 image has not been exercised in either phone app in this campaign.
The independent controller covers real PASE/CASE, commissioning, multiple fabrics,
On/Off, brightness, hue/saturation, transitions, readback and subscriptions driving
the physical WS2812 on GPIO8. A usable RGB demonstration is distinct from a complete
ExtendedColorLight implementation: Identify/TriggerEffect, Groups, Scenes, XY/CT,
other required lighting operations and durable light settings remain incomplete.

The C6 laboratory build has preconfigured Wi-Fi, BLE disabled and development
attestation, VID0xfff1/PID0x8000. Its QR encoder supports on-network commissioning. Adding the device
to both ecosystems still needs a physical phone-app check of the actual firmware,
commissioning window and test VID/PID setup. Apple documents adding Matter devices
through Home, including devices paired with another app; Google documents separate
development-device pairing restrictions and test integration configuration.
See [Apple Home Matter support](https://developer.apple.com/apple-home/matter/)
and [Google pairing restrictions](https://developers.home.google.com/matter/integration/pair).
No current app success or complete lighting conformance is claimed here.

## Changed files

| Files | Purpose |
|---|---|
| `runtime/matter_fabric_host.c` | Shared range undo/restore and committed-publication request without another image |
| `runtime/matter_store_host.c`, `runtime/matter_store_internal.h` | Private commit flag through publication/staging, unchanged public blob contract |
| `storage/matter_store_source_internal.h`, `storage/matter_store_tlv.c` | Borrowed-source flag and byte-identical committed projection |
| `runtime/matter_commissioning_host.c` | Adapt ordinary Wi-Fi publications to the private callback signature |
| `tools/matter/tests/test_store.c` | Projection/schema, input immutability, memory ceiling and exhaustive remaining OOM sites |
| `README.md`, `doc/oss/status.md`, this report and `memory23-results.json` | Current findings, exact measured evidence and open acceptance limitation |

Runtime/storage paths in this table are relative to `main/apps/matter`.

## Limits and next work

Whole-device heap measurements include dynamic SDK/Wi-Fi/lwIP/task allocations;
static D/IRAM is reported separately. The library payload tracker is a different
metric. Task stacks reserved from that heap must not be added a second time.
The 100ms timer and owner-loop samples can miss shorter peaks; the SDK
minimum-free watermark is separate. Largest free block and post-teardown values
describe each run and do not prove a universal fragmentation bound. No reference
COM24 reflash, new BLE implementation or official CSA campaign is part of Memory23.

The next task is isolating the intermittent14/15 initial full-subscription result
with per-session/subscription TX, ACK and retirement traces on unchanged old/new
firmware. Completing required lighting behavior and phone-app QR/multi-admin
acceptance remain necessary before calling the RGB profile a complete light.
