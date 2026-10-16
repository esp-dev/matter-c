# CSA23: ApplyUpdateResponse actions, delays and retries

Target: **Matter 1.6.1, TC-SU-2.5**. Results are recorded in
[csa23-results.json](csa23-results.json). The installed case has five disabled
YAML verification steps, executed as manual prompts by SDK YAML Tests /
FirstManualSuite. This is agent-operated manual acceptance using captured peer
traffic, not automatic CSA assertions or certification.

## Normative behavior and correction

Core **11.20.3.6** specifies Proceed, AwaitNextAction and Discontinue. Proceed
waits at least DelayedActionTime from receipt, then applies without another
ApplyUpdateRequest. AwaitNextAction waits the requested delay, with a mandatory
120-second minimum, before another ApplyUpdateRequest. Discontinue ignores its
delay. Clearing the downloaded verified image is a **SHOULD**; the official
manual step additionally asks the operator to verify physical removal and Idle.
The Provider command definition in **11.20.6.5, ApplyUpdateResponse** permits
assuming 86400 seconds when the provided delay exceeds 24 hours. The existing
Apply engine already implements these rules; its action/timer policy is unchanged.

The preceding CSA22 binary reproduces the missing host cleanup: it returns Idle
and does not install, but retains the verified download. Runtime now calls the
optional application `discard(user, artifact)` callback on Discontinue, before
logical invalidation. The file host removes only its live candidate, checks its
volatile artifact ID, and revokes candidacy even if removal fails. A missing
callback leaves physical disposal to the application. Accepted images remain
available for laboratory inspection. This does not delete installed firmware or
add a filesystem dependency to the library.

Consumers must rebuild for the appended port field and initialize optional
callbacks to zero. No persistent or Matter wire schema changed. The application
continues owning scheduling, time, artifacts, installation and storage. Removal
failure is logged, with no automatic disposal retry; paths must remain exclusive
to the application throughout artifact use.

## Validation

**TC-SU-2.5 manual PASS in TH run446**: five evaluated verification prompts
plus evidence upload. No official test source or PICS changed. Its YAML SHA-256 is
`3ad0f1ba76d02433b2547dae78f70f37359546fbbadbf38fc2cf29294ceba1aa`; PICS/executable/source/log hashes are in the
result delta. Only this row changes classification. Cumulative counts:
**97 PASS, 14 FAIL, 10 BLOCKED, 37 MANUAL, 704 NA**. Other rows are inherited;
manual PASS does not increase automatic coverage.

| Provider first response | Memcheck host | Separate ASan/UBSan/LSan host |
| --- | --- | --- |
| Proceed / 0 | PASS: 0.000 s; version 2 after restart | Not repeated |
| Proceed / 180 | PASS: 180.001 s; version 2 after restart | Not repeated |
| Await / 60 | PASS: 120.208 s; version 2 after restart | PASS |
| Await / 180 | PASS: 180.267 s; version 2 after restart | Not repeated |
| Discontinue / 180 (ignored) | PASS: Idle, disposed, unchanged version 1 | PASS |

Across the five successful Memcheck scenarios, **9 host boots,
260,130 allocations and frees, zero errors, zero live bytes, no
suppressions**. Separate full Await/60 and Discontinue sanitizer scenarios pass
with clean exits and empty host stderr; the retry interval is
**120.186 s**. The same eight focused BDX/Apply/update/runtime
CTests pass in each Linux build, including all four allocation variants. Build
logs contain no compiler warnings. The 353-file C/H manifest still matches the
compiled snapshot exactly. Local inventory and Python syntax checks pass.
All seven final trace sets were rechecked; altered token/version, missing Apply,
missing Notify and unexpected Notify controls are rejected. The failed old-binary
cleanup reproduction is retained separately, never counted as successful acceptance.

The unmodified official CHIP provider supplies the selected action/delay on its
first Apply response, then Proceed/0 on subsequent requests. Its actual decoded
IM fields, rather than CLI arguments alone, must match each scenario. All
fixtures begin at version 1 with separate state; positive fixtures use a signed
simulation image for version 2 and restart the same executable.

The oracle checks one Query/BDX, exact Apply counts, latest offered token/version,
retained version during delay, and fresh CASE readback after restart/Notify.
Proceed timing uses the requestor's monotonic response-receipt and installation
gate logs. Await timing independently uses provider response-send and next
request-receive timestamps; gate logs also require the second response before
application. No application clock is accelerated.

Discontinue supplies an otherwise meaningful 180-second delay: disposal and Idle
must occur without waiting for it. The runner observes a further 15 seconds
without install/Notify, checks both completed/partial files absent and reads
unchanged version 1 through a fresh CASE connection. This finite observation is
not an indefinite no-Notify proof.

The native suites also retain malformed TLV/type/action handling, timeout and
cancel/drain, allocation failure, publication failure, fabric-generation changes,
24-hour capping and clock-overflow coverage. The file suite adds successful
scoped disposal, zero/wrong/stale IDs, a restarted non-owner and removal failure
with candidacy revocation. No unmodified CSA assertion or PICS is bypassed.

## Changed files

| Files | Purpose |
| --- | --- |
| `main/apps/matter/runtime/matter_runtime.c/.h` | Optional candidate-disposal callback and monotonic receipt/gate diagnostics. |
| `tools/matter/host/matter_ota_file.c/.h`, `matter_server.c` | Host implementation and wiring of candidate disposal. |
| `tools/matter/tests/test_bdx.c` | Ownership and cleanup/error regressions, including allocation variant. |
| `tools/matter/tests/test_ota_chip_provider.py` | Five real-time action scenarios and independently decoded peer checks. |
| Runtime/fixture/test-map/status/roadmap documents | Public contracts, measured evidence and remaining acceptance scope. |

## Commands and limits

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/normal -j 3 --target matter-node test_bdx test_bdx_alloc test_ota_apply test_ota_apply_alloc test_ota_update test_ota_update_alloc test_runtime test_runtime_alloc
ctest --test-dir build/normal --output-on-failure -R '^test_(bdx(_alloc)?|ota_(apply|update)(_alloc)?|runtime(_alloc)?)$'

python tools/matter/tests/test_ota_chip_provider.py \
  --exe build/normal/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa --credentials /path/to/credentials \
  --interface 2 --mode apply-proceed-180 --valgrind --output build/apply-proceed-180
```

Repeat with fresh output directories for `apply-proceed-0`, `apply-await-60`,
`apply-await-180` and `apply-discontinue`. Configure a separate build with
`-DMATTER_SANITIZE=ON`; run the same eight CTests, then full `apply-await-60`
and `apply-discontinue` scenarios without `--valgrind`. Never combine sanitizers
with Valgrind. Python cryptography is required on the laboratory host.

For TH, select only TC-SU-2.5, evaluate all five prompts from their corresponding
captured scenarios and upload the manual log. Unknown prompts must stop the
manual runner; evidence is prepared before entering any PASS.

No physical firmware/bootloader, radio, Google/Apple Home UI or full CSA campaign
is verified by this step. The paired Windows node remains unchanged. Windows
runner import failed because native Windows Python lacks cryptography;
the controller scenarios execute on Linux. Sanitizers/Memcheck instrument the C
requestor, not the independent CHIP processes.

The catalog also contains a separate **SDK Python Tests / TC_SU_2_5** row,
SHA-256 `91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`.
It remains **BLOCKED / not executed**, separate from this YAML manual PASS.
Source review shows named-pipe provider commands, provider termination/restart
and attribute-subscription assertions. The pinned provider source contains the
required IPC commands, but that provider/image/key/process-control fixture still
needs acceptance inside the TH Python runner environment. Source inspection is
not a test outcome; do not infer either correctness or a test discrepancy.

Next: **CSA24 — automatic TC_SU_2_5: provider IPC, subscriptions and provider
interruption**. Complete that automation before TC-SU-2.6 NotifyUpdateApplied.
