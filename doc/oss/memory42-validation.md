# Memory42 — signed native ESP OTA

2026-10-24. New platform functionality after optimization closed at Memory40.
This is actual signed firmware installation on C6, distinct from the existing
WWOTA host simulation. No certification result is asserted.

## Implementation and ownership

- `runtime/matter_ota_install.h` adds an optional, borrowed application-owned
  installer contract. The runtime preserves BDX retirement, Apply event delivery,
  IM/MRP ACK and normal stop/drain before reboot. Existing download-only and
  simulated update configurations retain their behavior. The runtime and SDK
  store formats are unchanged; the optional new installer has its own journal.
- `components/matter_c_esp32/matter_idf_ota.[ch]` streams the standard Matter OTA
  header and ESP payload, verifies applicability, SHA-256, numeric version,
  project identity and the SDK's software signature, then rechecks the same flash
  artifact before accepting Apply. Its bounded download and reread workspaces
  are heap-owned and checked for failure. The new 144-byte MOTA01 journal binds
  the original provider/token and fabric certificate fingerprint to the selected
  app partition. It uses the existing atomic two-blob store.
- Boot reconciliation checks the real partition, image version, payload hash and
  SDK trial/valid state. Confirmation precedes durable notification readiness.
  A reset between those steps is recoverable. Unknown pending images and damaged
  metadata fail closed. Removed/replaced fabrics cannot inherit notifications.
- Notification consumption is persisted before its single application-level
  attempt. MRP retries remain active. A crash after consumption but before
  dispatch can lose Notify: exactly-once delivery across power loss is **not**
  promised. OOM retry of VersionApplied publication is covered separately.
- `matter_idf_resolver.[ch]` supplies eight bounded demand-owned SRV/AAAA/TXT
  jobs, optional MRP intervals and cancellation drain. mDNS/netif ownership stays
  with the application. No extra Matter or resolver task is created.
- `codec/matter_ota_header_internal.h` factors the existing header validation
  shared with the host file port; original header size/tag limits remain intact.
- The C6 lab wires these ports, pins the concrete outbound local IPv6 source,
  performs service checks before confirmation and preserves backends through
  stop/drain. Shared provisioning/observation headers support the disposable
  matched workload. Normal historical lab defaults remain unchanged.

NVS source was reviewed for both IDF6.0.2 and6.1 before extending its version
guard: the publication behavior remains synchronous `set_item`, with the same
handling of selector publication uncertainty. No SDK checkout was patched.
See the [installer contract and configuration](../../components/matter_c_esp32/OTA.md).

## Executed validation

Windows MinGW:

```sh
cmake --build build/memory42/windows -j 4
ctest --test-dir build/memory42/windows --output-on-failure
```

The complete pre-existing suite passed **112/112** after the runtime/header
changes. The two new SDK-boundary models were added afterwards; both passed,
along with focused runtime, runtime allocation and inventory tests. This is
not represented as one complete 114-test invocation.

Linux in an isolated VM directory, using mbedTLS3 and the recorded native
chip-tool/Matter.js peers:

```sh
cmake --build <normal-or-sanitize-build> -j 3
ctest --test-dir <build> --output-on-failure -E runtime_wire
# Complete two-instance --meter-services scenario via chip_tool_three_phase.py
# Normal pair under Memcheck; repeat separately with ASan/UBSan/LSan
python3 tools/matter/tests/runtime_wire.py --host <runtime-wire-host> \
  --node <node> --modules <node_modules> --output <new-output> --memcheck
# Repeat all six wire cases separately with the sanitized host, without Memcheck
```

Both builds passed **109/109 CTest**, all **six full pair checks**, and all
**six wire cases** (original/corrected peer and loop order/ACK fault coverage).
The pair Memcheck log reports no live blocks or errors at exit; wire cases
finish with zero core live allocations. The source inventory and installed
consumer passed. These campaigns cover the portable runtime changes; later
ESP-only resolver fixes were rechecked with the boundary tests below.

The real production OTA/resolver adapter implementations are also compiled
against SDK boundary models in `components/matter_c_esp32/test/`:

```sh
cmake --build <build> --target test_idf_ota test_idf_resolver -j 3
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
  --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=99 <test>
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 <sanitized-test>
```

Both tests pass under Memcheck and separately ASan/UBSan/LSan. Final OTA model:
65 allocations/65 frees, 35239 cumulative bytes, zero leaks/errors. Final resolver
model: 40/40, 6554 cumulative bytes, zero leaks/errors. They cover OOM, malformed
images, artifact mutation, signature rejection, failed boot selection, rollback,
confirmation/journal crash ordering, orphaned providers and corrupt metadata;
resolver limits, stale IDs, interface scope and cancellation lifetimes. SDK
signature/bootloader behavior is modeled here, not cryptographically emulated.

Both stacks' real signed version1/version2 images compiled on IDF6.0.2. The C
native profile also compiled on Windows IDF6.1, including the final route fix;
that compatibility image was **not flashed**. The matched physical benchmark
uses IDF6.0.2 exclusively.

## Physical C6 evidence

COM23, UART1000000, Wi-Fi/IPv6 through the lab AP; full flash backed up first.
RSA3072 keys and provisioning are local, ignored data. No eFuse, hardware Secure
Boot, flash-encryption or anti-rollback setting was changed. Dual OTA partitions
are 0x1d0000 bytes each. Initial and update ESP images are signed; the outer
Matter image has its own SHA-256. The private signing key never left Windows.

The successful full run performs BDX download, authenticated Apply, ACK/drain,
boot into version2, real SDK confirmation, a new device-initiated CASE,
NotifyUpdateApplied with the matching token, version readback, subscription/RGB
operation and orderly Matter deletion. Apply=1, Notify=1; no unexpected
subscription closure or SDK failed allocation. The remaining primary fabric and
provider's original identity remain consistent across restart. The matched
reference also completes real installation/reboot/Notify; see
[Memory43](memory43-validation.md).

Three additional disposable physical fault runs exercise the C installer:

- Different RSA signer, valid Matter digest: SDK reports signature verification
  failure; version1 remains operational, no Apply/VersionApplied/Notify.
- Reset during an actual BDX transfer: incomplete inactive flash is not selected;
  version1 resumes CASE/RGB and retains its fabric. Flash readback checks the
  written image prefix and an erased final sector.
- Reset the pending trial image before confirmation: the SDK bootloader returns
  to version1; no VersionApplied/Notify for version2. Existing fabric/CASE/RGB
  remain functional.

Each fault run requires zero SDK OOM, no false version2 notification, and zero
tracked core live objects/bytes after normal ACK/drain teardown. Numeric evidence
is exported with [the comparison results](memory43/faults.json).

## Investigations retained as limitations

Early test runs exposed two defects in the **new integration**: mDNS ANY could
complete with TXT alone, and the lab configured outbound local source `::`.
Strict reverse-path admission therefore rejected Sigma2 sent to its actual
link-local address. SRV/AAAA/TXT resolution and a concrete local source fix both
causes; no core admission check, protocol limit or timer was weakened. A retained
provider-only probe proves fresh device-initiated CASE/Query after the fix.

Other discarded runs hit client parallel-Read Busy, cold-boot readiness and an
expired commissioning window. The final harness waits for actual UART readiness
and performs bounded client Busy retries, identically on both stacks. Failed
exploratory runs remain private; they are not included in headline RAM figures.

Abrupt loss of power at every physical flash/NVS instruction, production key
rotation, strict production attestation and manual Apple/Google Home are not
verified. Journal crash ordering and allocation failures have boundary/native
test coverage, not an exhaustive physical power-cut campaign. The next product
task remains the minimum compliant Wi-Fi RGB model, QR and recovery policy.
