# CSA22: ApplyUpdateRequest binding and dynamic IM buffers

2026-10-16. Prior work was committed as **`76ea851`**. This step uses disposable
Linux hosts and the unchanged installed TC-SU-2.4 manual procedure. The paired
Windows instance, external CHIP sources, PICS, persistent formats and production
OTA behavior were not changed. [Machine-readable results](csa22-results.json)
retain hashes, individual checks and classification changes.

## Result and normative basis

**TC-SU-2.4 manual PASS in TH run445**: its verification step and manual evidence
upload both pass. This is an agent-evaluated manual result supported by captured
protocol evidence, not automatic CSA assertions, certification or an accredited
laboratory result. Only this row moves from BLOCKED to MANUAL with result PASS.
The cumulative matrix is **97 PASS, 14 FAIL, 11 BLOCKED, 36 MANUAL, 704 NA**;
all other official rows are inherited, not rerun.

Core R1.6.1 11.20.3.6 requires the ApplyUpdateRequest token to come from the last
QueryImageResponse; the OTA Provider command definition requires NewVersion to
identify the image ready to apply. This profile retains the token through
download, so the token-loss fallback is not exercised. A provider's approval is
not image authentication: the existing runtime checks the vendor signature,
artifact and offered version before starting Apply, and rechecks the artifact
at application handoff. The OTA engine already implemented these checks.

The unchanged TH YAML source SHA-256 is
`1b488627a9f5a0f102bdf88eb702217dd1e828ed156e8faef0f644860b3aa13e`.
Its required PICS is MCORE.OTA.Requestor; the current execution PICS hash matches
the project snapshot. No PICS or test source was modified to obtain this result.

## What changed

| Files | Purpose |
| --- | --- |
| `model/matter_im_read.c/.h`, `model/matter_im_subscribe.c/.h` | Separate RX/TX allocations, actual-length RX copies, transport-derived limits, OOM cleanup and documented ownership. |
| `runtime/matter_dispatch.c` | Use the increased, ACK-safe Read/Subscribe output budget. |
| `test_im_read.c`, `test_im_subscribe.c`, `test_im_complex.h`, model/selector fixture headers | Request boundaries, 83 filters, constructor/RX allocation failure, retry and snapshot-allocation failure after RX admission. |
| `test_ota_apply.c` | Verify that both token and version are copied, even if the caller changes them after begin. |
| `test_ota_chip_provider.py` | Decode peer Query/Apply/Notify traces, verify exact token/version correlation, test version 3 and reject offered/signed version mismatch. |
| Runtime, fixture, status, roadmap and test-map documentation | Record the new budgets, executed validation, remaining scope and next task. |

Production files above are under `main/apps/matter`; tests are under
`tools/matter/tests`. No public function signatures or persistent schemas changed.

## UDP budgets and allocation ownership

Core 4.4.4 limits a UDP message including IPv6 and UDP headers to **1280 bytes**.
The current secure-unicast framing yields:

- UDP payload ceiling: 1280 - 40 IPv6 - 8 UDP = **1232 bytes**.
- Maximum incoming IM payload: 1232 - 8 message header - 16 MIC - 6 protocol
  header = **1202 bytes**. Actual optional headers reduce the available space;
  framing and transport must enforce the real wire size.
- Outgoing Read/Subscribe payload: reserve another four bytes for a piggybacked
  MRP ACK, giving **1198 bytes**. The dispatcher selects this budget.

Read/Subscribe allocate the exact received length before replacing the previous
copy. Failed allocation returns LIMIT_REACHED with state and queue unchanged,
so the owner can retry. The output allocation uses configured capacity and is
unwound if construction fails. Both buffers are owned by the handler and freed
on deletion; version-filter tables retain their separate priming/read lifetimes.
No large automatic buffers or shared static scratch storage were introduced.

The filter count safety bound follows the minimum concrete filter wire size,
not an allocated fixed table. Tests use 83 entries, including malformed final
entries and conflicting versions. Requests of 1025, 1198 and 1202 bytes succeed;
1203 bytes is rejected before allocation. Existing output capacities remain
valid. Invoke, Write, outbound IM and result/connection/transport tables keep
their separate existing budgets and remain future migration work. Larger heap
allocations do not permit larger UDP packets; larger-message transports are
outside this change. Existing platform-specific IPv6 enforcement limits remain.

## Executed acceptance

The independent CHIP Provider and chip-tool are unmodified; SDK commit is
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7`, with a clean source checkout.
The provider trace is independently decoded by Python, rather than trusting its
CLI flags or the logged token length. Each positive request must echo the latest
offered token byte-for-byte and use the offered/authenticated version. The same
binding is required in decoded NotifyUpdateApplied. Public results contain token
lengths and digests; raw traces and controller state stay private.

| Scenario | Memcheck host | Separate ASan/UBSan/LSan host |
| --- | --- | --- |
| Fresh fixture version 1 to signed version 2; BDX, Apply, simulated restart, Notify, fresh CASE readback | PASS | Not repeated; version 3 covers this path |
| Independent fresh fixture version 1 to signed version 3, with a different token | PASS | PASS |
| Offer/header version 3 with a valid signature over simulation payload version 2 | PASS: authentication rejects, no Apply/Notify/reboot, version remains 1 | PASS |
| Full-profile Read/Subscribe, 17 filters, fresh-controller discovery/CASE, switch reports and RemoveFabric | PASS | PASS |

These are separate fresh fixtures, not a sequential update of the same node.
Both rejected fixtures' ECDSA P-256/SHA-256 signatures were independently
verified with their public keys: rejection concerns the signed version, not a
broken signature.
The image is an application-specific signed host simulation; the same executable
is restarted. No executable firmware or physical bootloader was installed.

Across six Memcheck-instrumented C host boots: **179,089 allocations and frees,
zero errors, zero live bytes, no suppressions**. The independent CHIP processes
are not instrumented by these counts. Sanitizer runs exit cleanly with empty
host stderr. All successful positive trace files were re-evaluated with the final
oracle; controls with an altered token, altered version, missing Apply and missing
Notify are rejected. The final explicit Notify-presence assertion was added
after the live runs and checked against those saved traces without replaying OTA.

Linux normal and sanitizer builds each pass **11 focused CTests**: Read,
Subscribe, dispatcher, Apply, update journal, runtime and their applicable
allocation variants. Windows passes **five focused CTests**: Read, Subscribe,
dispatcher and both allocation variants. Compiler logs contain no warnings.
The initial Read snapshot-OOM fixture failed because RX now allocates first;
its injection point was moved after successful RX admission, preserving the
original assertion and adding separate RX-OOM/retry coverage. No failed run is
reported as PASS.

The compiled Linux snapshot hashes 353 C/H files. Only block comments in the two
IM API headers changed afterwards; comment-stripped source tokens were compared.
Windows also passes its five tests; the final header-only wording edits do not
change declarations or compiled source tokens.
No full CSA campaign, ecosystem UI, physical target or production-credential test
was performed in this step.

## Commands

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/normal -j 3 --target matter-node test_im_read test_im_read_alloc test_im_subscribe test_im_subscribe_alloc test_dispatch test_ota_apply test_ota_apply_alloc test_ota_update test_ota_update_alloc test_runtime test_runtime_alloc
ctest --test-dir build/normal --output-on-failure -R '^test_(im_(read|subscribe)(_alloc)?|dispatch|ota_(apply|update)(_alloc)?|runtime(_alloc)?)$'

python tools/matter/tests/test_ota_chip_provider.py \
  --exe build/normal/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa --credentials /path/to/credentials \
  --interface 2 --mode update --apply-binding --image-version 2 \
  --valgrind --output build/csa22-v2
# Fresh output directories: repeat with --image-version 3, then
# --mode version-mismatch without --apply-binding or --image-version.

python tools/matter/tests/test_im_version_filters_chip.py \
  --exe build/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/paa --credentials /path/to/credentials --interface 2 \
  --memcheck --output build/csa22-im
```

Build a separate directory with `-DMATTER_SANITIZE=ON`; run its CTests and the
version-3, mismatch and IM scenarios without Valgrind/Memcheck flags. Never run a
sanitizer binary under Valgrind. For TH, select only TC-SU-2.4 in SDK YAML Tests /
FirstManualSuite, evaluate its verification prompt against the real evidence,
and upload the manual log. The private runner records all prompt decisions.

Next: **CSA23 — TC-SU-2.5, ApplyUpdateResponse actions and real delay/retry timing**.
