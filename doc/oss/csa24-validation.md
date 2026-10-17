# CSA24: automatic ApplyUpdateResponse acceptance

Target: Matter 1.6.1, **SDK Python Tests / TC_SU_2_5**, distinct from the
manual YAML TC-SU-2.5 accepted in CSA23. The unmodified installed Python case
has SHA-256 `91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`.
**Official run449: FAIL.** Both AwaitNextAction/provider-loss scenarios pass.
The Discontinue step fails while creating its progress subscription, before
announcing the provider or testing disposal. This is not automatic OTA acceptance.

## Implementation corrections

Core 11.20.7.4 defines DelayedOnQuery for a Busy response. Query transport/IM/
decoding failures previously used that state during backoff as well. The retry
policy now waits in Idle for errors and a successful deferred image; Busy still
uses DelayedOnQuery. The 120-second global query floor, provider delay and
bounded exponential retry intervals are unchanged. Apply action/delay policy
and signature/token/version authorization are unchanged.

A new regression fails against the original library at the assertion requiring
Idle after timeout. It also checks valid Busy, IM Busy, transport failure, IM
failure, malformed TLV and unchanged retry deadlines. A Busy response missing
its required delay is a malformed response, not a valid Busy state.

The runtime previously left download progress at zero. A new optional
application callback supplies percentage without adding filesystem knowledge
to the runtime. The file adapter uses received bytes and validated image size;
it reports unknown until the header is validated and again after commit/cancel.
Only changed integer percentages dirty the Requestor cluster. No per-percentage
StateTransition events, new tasks, locks or heap workspaces are introduced.
Out-of-range callback values are exposed as unknown. Rebuild consumers and
zero-initialize optional port fields; persistent and Matter wire schemas do not
change. The callback does not authorize installation.

## Isolated fixture

The C requestor runs on the TH Linux host, using a separate state/download
directory. The TH starts/stops its own unmodified CHIP OTA provider inside its
SDK container. FIFOs stay inside that container. The provider wrapper only maps
the actual requestor download into the case's `/tmp/test.bin` file check and
executes the real provider; it does not synthesize IPC replies, states or PASS
decisions. Both processes use host networking.

Fresh random PAA/PAI/DAC keys are generated on the TH host. Existing device keys
and user-paired state are not exported. The project uses an explicit laboratory
PAA store and a signed public development CD for test VID/PID. The synthetic
image contains version 2 and an independently signed payload; the host begins
at version 1. The final image is 262342 bytes, including its Matter header.
This is simulated OTA, not executable firmware or a physical bootloader.

Only commissioning-readiness prompts are answered by the launcher. Official
Python assertions and PICS are unchanged. Unknown prompts abort the launcher.
The standalone Windows instances are outside this fixture.

## Validation and limitations

Ten focused native CTests pass in the normal Linux build and separately with
ASan/UBSan/LSan: BDX, Query, Apply, update journal and runtime, each including
its allocation variant. A full Memcheck Await/retry/update/restart scenario
passes with 55265 matched allocations/frees across two boots, zero errors and
zero live bytes. The separate ASan/UBSan/LSan scenario also passes with two
clean boots and empty host stderr. Each full scenario has 21 checks. These
native/controller results do not substitute for automatic CSA assertions.

Run447 was deliberately aborted after the original incorrect backoff state was
diagnosed; it is not an official FAIL or PASS. Run448 passed the first Await/60
and provider-loss step, then was deliberately aborted before completing the
remaining case, to include actual progress in the final fixture. Run449 is the
full attempt with both corrections and fresh state: five harness steps passed
(including setup/log handling), one failed. The two substantive delay scenarios
passed; the remaining scenario did not reach its OTA assertions.

The failure is IM `RESOURCE_EXHAUSTED` at `TC_SU_2_5.py:382`, when starting
UpdateStateProgress. The script creates a new UpdateState handler in each of
steps 3, 4 and 5, but does not cancel the handlers from steps 3 and 4. Its installed
helper defaults to `keepSubscriptions=True` (line 278). After the two obsolete
state subscriptions and the current one, progress is the fourth live subscription
on that fabric. The host advertises and enforces three per fabric through the
shared `matter_host_limits.h` budget; no allocation failure is demonstrated.

Core 1.6.1 section 2.11.2.2 requires at least three subscriptions per fabric;
section 8.2.5.3 defines resource-error responses and section 11.1.4.4 defines the
CapabilityMinima field. The observed test assumes capacity beyond the Core
minimum. This is a **suspected harness resource assumption**, not a CSA-confirmed
test defect or proof of complete device-profile conformity. The official script,
PICS, host limit and acceptance assertions were not changed to obtain a PASS.
In particular, Discontinue/progress subscription acceptance remains unverified
by this automatic case despite the native progress tests and prior manual OTA
acceptance. A separate, explicitly declared higher-capacity fixture or a CSA
clarification is needed before rerunning that scenario.

The automatic Python matrix row changes from BLOCKED to FAIL. The separate
manual YAML row retains its CSA23 result. Cumulative counts are **97 PASS,
15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA** (862 rows); all other rows are inherited.
See the machine-readable [delta](csa24-results.json). The isolated Linux test
node was stopped after TH returned idle; user-paired Windows nodes were unchanged.

## Commands and next task

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/normal -j 3 --target matter-node test_bdx test_bdx_alloc test_ota_query test_ota_query_alloc test_ota_apply test_ota_apply_alloc test_ota_update test_ota_update_alloc test_runtime test_runtime_alloc
ctest --test-dir build/normal --output-on-failure -R '^test_(bdx(_alloc)?|ota_(query|apply|update)(_alloc)?|runtime(_alloc)?)$'

python tools/matter/tests/test_ota_chip_provider.py \
  --exe build/normal/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa --credentials /path/to/credentials \
  --interface 2 --mode apply-await-60 --valgrind --output build/csa24-memcheck

th-cli test-run-execution --id 449 --json
python tools/matter/check_test_map.py
```

Repeat the ten CTests in a separate `-DMATTER_SANITIZE=ON` build, then run the
same full scenario without `--valgrind` using that binary and a fresh output
directory. Valgrind and sanitizers instrument the C host, not CHIP processes.
TH uses the pinned unmodified Python script with an isolated project and provider
IPC; private generated artifacts and the readiness-only launcher stay outside Git.

Next: **CSA24a — resolve the automatic test's subscription-capacity assumption**:
prepare the resource evidence for CSA and determine an explicit host capacity
configuration without changing protocol semantics or silently redefining the
minimum. Re-run the complete unchanged case before claiming automatic PASS.

No certification, production credentials, physical installation, Windows OTA
execution or Apple/Google UI acceptance is claimed.
