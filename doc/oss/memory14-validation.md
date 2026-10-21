# Memory14 — C6 UDP/IPv6, discovery and durable runtime

The complete C runtime now serves real network requests on the ESP32-C6 through
application-owned IDF adapters. Physical tests use COM23 and the existing lab
AP. The core creates no task; scheduling, radio, lwIP, mDNS, PSA and NVS lifetime
remain with the application. Public C APIs, TLV/wire formats and the existing
128-event, 56-transport-slot, five-fabric and three-subscriptions-per-fabric
limits are retained. This is experimental laboratory evidence, not a CSA result.

The preceding Memory13 integration was already committed as `40c1f68`; its tree
was clean when this stage started. No source/state from the concurrent public
CSA checkout was changed. No push, router firmware/configuration change or
eFuse operation was performed.

## Implementation and ownership

`components/matter_c_esp32` supplies three separately owned adapters:

- **UDP:** a raw IPv6 PCB with one demand-allocated receive slot, actual
  destination/interface metadata and owner-deferred delivery/completion. TCP/IP
  core locking protects activation, callback and deactivation barriers. The raw
  callback neither allocates nor calls Matter. Occupied slots drop UDP; MRP
  retains retry/ACK ownership. Payload is bounded by the existing 1232-byte
  ceiling and the complete IPv6 packet by 1280 bytes. Extension-header validation
  accounts for header bytes and rejects fragments, including atomic fragments.
  A send copies into an SDK pbuf and releases it before deferred completion;
  local acceptance is not peer acknowledgement. Stop preserves pending terminal
  completions and borrowed objects until drain.
- **Discovery:** one binding per advertisement, staged SDK registration and
  deferred completion on the owner. The SDK copies strings. Partial subtype
  publication rolls back the exact instance before failure is reported; OOM
  permits retry. Withdrawal drains before record/backend deletion. The
  application follows commissioning mode and fabric identities, owns the shared
  SDK service and keeps it alive through every binding's stop/delete.
- **Storage:** two complete unchanged TLV blobs plus a one-byte active selector
  in a dedicated NVS namespace. Only the inactive candidate is staged; selector
  publication is the commit point. Invalid/missing selected data fails closed,
  without silently formatting or resurrecting an older fabric set. Software
  faults before staging/publication preserve the previous checkpoint, including
  after handle reopen. The synchronous backend does not own a task or partition.

The NVS adapter deliberately pins its reviewed semantics to IDF 6.1. Its
`set_item` writes synchronously and `commit` is a no-op on a live handle.
`ESP_ERR_NVS_REMOVE_FAILED` during selector replacement means the new item was
written: publication succeeds and further writes latch offline. Other physical
storage errors also latch writes offline. Electrical/flash failures can have an
ambiguous whole-old/whole-new outcome; they are not equated with an injected
software rejection. See the [official NVS documentation](https://docs.espressif.com/projects/esp-idf/en/release-v6.1/esp32c6/api-reference/storage/nvs_flash.html)
and re-review the pinned implementation on SDK upgrade. Power-cut testing was
not performed.

`examples/esp32-runtime` composes these adapters with the complete runtime and
an application-owned Wi-Fi port. Settings/jobs/results/scan arrays and large
SDK configuration objects use bounded heap allocations. SDK scan callbacks only
latch completion; the owner advances model time and completes requests. Scan
cancel drains without disconnecting an active UDP connection. Radio stop/start
acts as the effects barrier for a replaced connection request. Restore waits for
actual association and IPv6 readiness. Public TEST identity material, build-time
UTC and an ignored AP credential header are explicitly laboratory provisions.

The two examples share `examples/esp32-common/matter_lab_memory.h` for identical
heap/task reporting. The older Memory13 example was rebuilt successfully after
this extraction; it was not reflashed over the new partition layout.

## Findings exposed by physical validation

1. **Pending boot recovery:** the core previously attempted to clear recovery
   before pumping a deferred physical radio backend. Shared `recover()` now
   advances that backend before cleanup. PENDING/error preserves the durable
   marker and closes commissioning admission. Stop becomes terminal before
   waiting, so deferred recovery cannot reopen admission. Host tests cover
   pending/error/success and stop-during-recovery.
2. **Live interface index:** after real Wi-Fi stop/start, lwIP re-adds the same
   netif object with a new numeric index. A PCB bound to the old index answered
   no UDP although IPv6 ping succeeded. The final port reserves its UDP port
   globally, filters the actual input netif and explicitly chooses the output
   interface; it does not retain that stale numeric PCB binding. The repaired
   binary was exercised through another persisted restart and CASE traffic.
   Applications must not bind another PCB to this same port on another netif.
3. **NVS staging headroom:** a 128 KiB partition passed a maximum-size fixture
   when empty but exhausted staging/GC space beside a real runtime checkpoint.
   The final dedicated partition is 256 KiB at 0x10000, app at 0x50000. Its full
   32768-byte fixture now passes on every boot beside the live checkpoint.
   The controlled lab migration backed up the old partition/state, erased only
   the new extension and retained the original fabric/NodeLabel. This is not an
   atomic production partition-migration or OTA design. Never flash the older
   example at 0x10000 over the new Matter NVS partition.
4. **CASE resumption interoperability:** the laboratory explicitly selects the
   existing CHIP profile, matching the host and Matter.js 0.17.9. Its traffic KDF
   uses the previous resumption ID; core default SPEC uses the new Sigma2Resume
   ID and remains unchanged. The mismatch allowed handshake MIC validation but
   broke subsequent encrypted traffic. Generated Kconfig and the target marker
   now confirm CHIP; resumed encrypted Read/Write and ECM passed. There is no
   ciphertext-based profile detection or fallback.
5. **Controller cache oracle:** the normal Matter.js ClientNode wrapper injects
   cached DataVersionFilters even when given an empty filter list. The public
   oracle now uses the SDK's public unbound-client factory. Its actual full
   Subscribe snapshots contain 133 attributes, with event reports, rather than
   treating a smaller filtered report as a missing-target-data failure.

## Toolchain and independent physical tests

Final target: ESP32-C6FH4 rev. 0.0, 4 MB flash, no PSRAM. Unmodified native
Windows ESP-IDF v6.1 commit `fff9895c82d744c7237be8847347bdd1b07c6643`,
GCC 15.2.0, Mbed TLS 4.1.0 with software ECC. External official Espressif mDNS
`mdns-v1.12.0`, commit `db06b19b7be729c163d346f62ec0eba01047b7f1`, retains
its Apache-2.0 license. No automatic build-time dependency download or SDK patch.
See [lwIP documentation](https://docs.espressif.com/projects/esp-idf/en/release-v6.1/esp32c6/api-guides/lwip.html)
and the [pinned mDNS source](https://github.com/espressif/esp-protocols/tree/mdns-v1.12.0/components/mdns).

Actual independent controllers: Matter.js 0.17.9 with Node.js 24.22.0 and Python
zeroconf 0.147.0. Public reproducible scripts are in
`examples/esp32-runtime/tests`; state and raw captures remain ignored.

- Commissioning over PASE/UDP, operational CASE and explicit CASE resumption;
  remote Read, durable NodeLabel Write/readback and full Subscribe snapshot
  delivery, including chunk ACKs/drain.
- Operational mDNS PTR/SRV/TXT/AAAA on IPv6; initial commissionable CM1 records
  and default discriminator subtypes were also independently resolved in the
  earlier run of the same discovery implementation.
- Authenticated ECM opening, a separate second fabric, snapshot delivery and
  successful RemoveFabric response before that fabric's session is retired.
  A subsequent original-controller remote read confirms exactly one fabric.
- Local UART `r` atomically stages a deliberately marked pending Wi-Fi journal,
  retaining committed fabrics/settings, then resets. Next boot forces real
  driver stop/start/reassociation before cleanup/admission. Fresh CASE verifies
  the original fabric, persistent NodeLabel and event numbers above the saved
  pre-reboot watermark. This is an injected crash-checkpoint fixture, not an
  interrupted on-wire AddNOC or an electrical power-cut experiment.
- Raw UDP probes at 0, 1, 1232, 1233 and 1500 bytes, plus target-side pure
  extension/fragment/truncation/overrun checks. Oversize ingress is rejected;
  no exhaustive raw extension-packet fuzzing is claimed.
- Forty-one runtime-constructor allocation-failure positions on the target
  (earlier run; final core archive has the same hash), plus twelve per-boot
  adapter/model/Wi-Fi allocation faults. Discovery constructor/publication/retry,
  runtime/UDP constructor and RX allocation, Wi-Fi job, and model publication
  failures retain state and permit cleanup. Two storage prefaults also preserve
  the selected blob after reopen. SDK/PSA internal allocations are not an
  exhaustive OOM campaign.
- UART `q` drains runtime/MRP/IM/UDP and advertisement lifetimes before deletion;
  `RUNTIME_PASS` requires zero tracked live allocations and SDK heap integrity.

The pinned wrapper's known-address branch uses its default development
attestation policy. It accepted the public TEST CD parser finding
`Structure element tags should have an id.`; that success does not prove strict
attestation validation. Repeated second-fabric tests also elicited a recoverable
duplicate admin-label warning, while commissioning and removal succeeded.

The TL-MR3020 already supports same-link IPv6, so no router rebuild was needed.
Its image lacks routed RA/DHCPv6 services; routed IPv6 was not tested. Windows
Wi-Fi was temporarily connected to the lab and IPv6 enabled for these tests.
Original device flash and migration backups remain private; no keys, credentials,
controller state, binary firmware or raw payload captures are committed.
After testing, Windows Wi-Fi was disconnected, the temporary profile/XML removed
and its IPv6 binding confirmed disabled again, restoring the original state.

## Memory and stack interpretation

[Machine-readable results](memory14-results.json) record final binary/source
hashes, separate boot/workload samples, task watermarks and compiler frames.
The final BIN is **1280192 B**, SHA256
`30d23ea0f74e8f524795f281e38e561b18b35f7d848c2cc96fdd50f98bbb55b6`.

| Final-binary observation | CASE/ECM/second fabric and local crash fixture | Recovery/CASE/snapshot/UDP probes/stop |
| --- | ---: | ---: |
| Maximum sampled system internal-heap allocation | 191992 B | 188724 B |
| SDK internal-heap low-water (sum of region minima) | 161664 B free | 169580 B free |
| Tracked allocation-event peak | 133612 B | 123452 B |
| Largest tracked request | 32768 B | 32768 B |
| Owner stack observed use / reservation | 2600 / 12288 B | 2572 / 12288 B |

Final teardown reports **0 tracked live allocations / 0 B**. Individual compiler
frames: UDP receive32 B, send96 B, process32 B; store read48 B, replace32 B;
discovery process16 B; Wi-Fi process144 B; app_main176 B. The largest new
application/port frame is256 B. These small individual frames do not include
their callees' frames. Static linked DIRAM is140735 B, including99652 B of IRAM
code,25104 B BSS and15979 B data; it is distinct from heap measurements.

This stage adds the actual network runtime;
its workload is larger than Memory13's local-engine profile, so subtracting their
heap values would not measure an optimization saving. The adapters avoid
permanent large parser/packet/store arrays: RX is allocated while active, TX
pbufs per send, discovery TXT per publication and large fixtures on the heap.

Tracked memory covers the library, new adapters and Wi-Fi port, excluding their
allocator headers and SDK/PSA internals. System internal-heap samples include
SDK resources, fixtures and reserved task stacks. **Do not add the task stack
reservations again to system heap totals.** Library peaks are allocation-event
peaks; whole-node samples can miss short-lived peaks. SDK low-water values sum
per-region minima and need not describe one coincident instant. Compiler frames
are individual frames, not complete call-chain bounds. Target stack watermarks
include the actually exercised nested crypto/SDK work only.

No universal heap/stack amount required by the Matter specification is asserted.
Five simultaneously active full fabrics, maximum reports/TX concurrency,
long-duration fragmentation, all handshake phases under OOM, arbitrary AP loss,
SDK-wide failures and mDNS conflict/rename stress still need a workload envelope.
Build-time UTC, public TEST credentials, disabled flash encryption/Secure Boot,
the region-agnostic lab Wi-Fi mapping and synchronous crypto/storage require
production application decisions.

## Host regressions and executed commands

The changed core and tests were built/tested locally and transferred without
private/ignored data to the authorized VM lab root. All 159 transferred core
source/header/test hashes match this checkout; later changes affect the target
adapter/application and independent oracle, not that tested host core.

- Windows full CTest: 97/98, with `installed_consumer` failing because the child
  compiler DLL directory was absent from PATH. A corrected-PATH retry passed
  1/1. Focused runtime and allocation variant: 2/2. This is not a single 98/98 run.
- Linux full CTest: 95/95 normal and separately 95/95 ASan/UBSan/LSan.
- Independent two-instance controller scenario: 6/6 under Memcheck, then
  separately 6/6 sanitizer checks. Each run hosts two independent runtimes in
  one process. Memcheck reports zero errors, live allocations and suppressions;
  sanitizer stderr is empty.
- Test-map inventory: 256 mapped files, 97 native definitions, 59 core sources,
  75 closed public headers. `git diff --check` passes (Git CRLF notices only).
- Native IDF runtime build and Memory13 example compatibility rebuild pass.
  Official SDK configuration notices remain; compiler warning logs were checked.

Representative actual commands (private paths abbreviated):

```text
idf.py -C examples/esp32-runtime -B build/memory14/idf61-runtime reconfigure build
python -m esptool --chip esp32c6 --port COM23 ... write-flash ...
python -m esp_idf_size --format json2 build/memory14/idf61-runtime/matter_c_runtime.map
ctest --test-dir build/memory01/windows --output-on-failure
ctest --test-dir build/memory01/windows -R installed_consumer --output-on-failure
ctest --test-dir <VM>/source/build/memory14-normal --output-on-failure
ctest --test-dir <VM>/source/build/memory14-sanitize --output-on-failure
python3 tools/matter/tests/chip_tool_three_phase.py ... --source-registers --meter-services
python tools/matter/check_test_map.py
```

Next task: define and run a sustained C6 concurrency envelope (fabric/session,
Read/Subscribe and TX occupancy, reconnects and allocation failures) with
fragmentation/latency telemetry before deciding another representation change.
