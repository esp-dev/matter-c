# MP04 validation - 2026-10-12

Prior MP02/MP03 work was committed as `6e81b72` before this stage. MP04 adds
opt-in x86 meter services; no publication, firmware integration or replacement
of the default profile was performed. [Contracts and usage](../meter-services.md)
separate mandatory baseline behavior from unimplemented optional features.

Normative references inspected locally: Matter 1.6.1 Application Clusters
1.2 (Identify) and 9.10 (Meter Identification), Core 11.17 (Time Synchronization)
and 3.5.6.1 (LKG), Device Library 14.6 (Meter Reference Point). The CSA documents
and SDK test distribution remain outside the public repository. This stage
prepares that composition; it does not advertise a complete utility-meter type.

## Official CSA acceptance

Unmodified CSA TH v2.15.1+summer2026 scripts, separate newly imported endpoint
projects, disposable commissioned nodes, strict certificate verification.
The pinned runner logs identify SDK data_model/1.6; normative implementation
review used the downloaded 1.6.1 documents. These focused results do not certify
all 1.6.1 requirements or the entire stack.

| Case | Endpoint | Final result |
| --- | --- | --- |
| TC_TIMESYNC_2_1 | 0 | PASS |
| TC_TIMESYNC_2_2 | 0 | PASS |
| TC_MTRID_2_1 | 1 | PASS with step-report caveat below |
| TC_I_2_4 | 1 | PASS |
| TC_DESC_2_1 | 0 | PASS |

The Meter Identification report marks ProtocolVersion and PowerThreshold steps
NOT_APPLICABLE. PowerThreshold is correctly undeclared. ProtocolVersion is
present with PICS `MTRID.S.A0003=1`: the SDK log shows step5, a successful Read
exchange, then "Skipping: 5" immediately before skipping the unsupported
PowerThreshold step6. Source review shows ProtocolVersion read/assertions before
the next feature guard. Retain the report as emitted; do not relabel the skipped
step as PASS. The separate chip-tool oracle verifies the actual `1.0` value.
No CSA assertions or expected values were modified to obtain results.

Final log suffixes: `MP04-final2-ep0-TC_TIMESYNC_2_1` (09:44:57 UTC),
`MP04-final-ep0-TC_TIMESYNC_2_2` (09:43:20),
`MP04-final-ep1-TC_MTRID_2_1` (09:43:37),
`MP04-final-ep1-TC_I_2_4` (09:43:54),
`MP04-final-ep0-TC_DESC_2_1` (09:44:23).

## Native and independent-controller checks

| Check | Result |
| --- | --- |
| Linux GCC Debug full CTest | 82/82 PASS before final host-only floor changes; final affected native tests also pass |
| Separate Linux ASan/UBSan/LSan full CTest | 82/82 PASS, including IM reporting policy; final storage-failure test passes separately |
| Windows MinGW GCC15.2 host and pair build, focused CTest | 5/5 PASS: IM Subscribe, meter services, allocation faults, host clock, inventory |
| Final single host with chip-tool under Memcheck | 7/7 checks PASS; node/controller exit0; zero errors and bytes at exit |
| Final single host, separate ASan/UBSan/LSan | 7/7 PASS; node/controller exit0; no findings |
| Final pair, one process/thread under Memcheck | 6/6 checks PASS; both last-fabric responses and clean deletion |
| Final pair, separate ASan/UBSan/LSan | 6/6 PASS, controller/node exit0, no findings |
| Partial start with second UDP port occupied | Expected exit1; Memcheck: zero errors and zero bytes at exit |
| Full-host restart, preserved CASE credentials and LKG | Two restarts PASS without pairing; live UTC reacquired, LKG preserved |
| Inventory / Python syntax / whitespace review | 225 mapped files, 84 native definitions, 59 core sources, 75 public headers |

Final Memcheck allocations/frees: 24289/24289 (single), 48591/48591 (pair),
4359/4359 (partial start). Each reported zero errors and zero bytes/blocks at exit.
Evidence directories: `memcheck-final2`, `sanitize-final2`, `pair-memcheck-final5`,
`pair-sanitize-final5`, `partial-start-final5`, `restart-final`. The two full
sanitizer scenarios exited successfully without ASan/UBSan/LSan findings.

Native tests cover constructor allocation failures, independent instances,
reentry rejection, Identify timer/overflow/expiry, invalid and duplicate fields,
read-only access, optional/null/invalid UTF-8 metadata, TimeFailure throttling,
clock acquisition failures, atomic SetUTCTime rejection, integer overflow,
exclusive file locking, corrupt/missing storage, and actual atomic-write failure
with the old clock/LKG preserved. The IM regression proves that unrelated dirty
notifications cannot report each countdown tick, while ACL checks still run.

The independent chip-tool scenario checks attestation, CASE, exact placement of
servers, readable identity, countdown Read versus Subscribe, explicit-write and
expiry reports, advancing UTC, Admin source, invalid granularity, read-only
attributes, Operate/Manage/Administer privilege differences and ACL restoration.
Pair checks additionally change only A's Identify/UTC, delete A while Identify
is active, and continue B's subscription, phase, source and meter-service access.

## Failed attempts and limitations

The first single-host oracle used incorrect SDK CLI spellings (`set-utc-time`
and `utc-time`); these were corrected to `set-utctime` and `utctime` against the
installed tool's help, then the complete scenarios were rerun. An initial pair
launcher supplied two mutually exclusive fixture options; the fixture rejected
it before allocation. The launcher now uses the documented combined profile.

A genuine startup discovery race was observed: the controller requested A's
long discriminator but selected B's port. The oracle caught it; no assertion
was removed. A later run after initial mDNS announcements settled passed.
At the MP04 snapshot this was an unresolved multi-node discovery acceptance
limitation, not evidence that all discovery timings work. The subsequent
[MP04a investigation](mp04a-validation.md) identifies the controller path and
replaces the delayed pair acceptance with an active-browse startup regression.
Concurrent external TH/pair scenarios also
caused an unsuccessful DUT start and PASE Busy; final external runs were
serialized and the affected CSA case rerun. Retained failure logs are not
counted as successful acceptance.

No physical indication/source adapter, Google Test Suite/UI, embedded firmware,
production provisioning, metrological accuracy, NTP/TZ/trusted-source features,
MSan/TSan or new fuzz campaign was verified. TimeFailure and long-term drift/
monthly-persistence boundaries are exercised through native simulated time,
not a month-long run. Four earlier CSA failures remain open in [status](status.md).
The public IM value struct grew an opt-in field: rebuild consumers with the library.

## Changed files and rationale

| Files | Purpose |
| --- | --- |
| `main/apps/matter/clusters/matter_identify.c/.h` | Owned Identify timer, presentation port, ACL and reporting semantics |
| `main/apps/matter/clusters/matter_meter_identification.c/.h` | Copied/validated nullable source identity through a callback |
| `main/apps/matter/clusters/matter_time_sync.c/.h` | Root time server, SetUTCTime, acquisition and TimeFailure |
| `main/apps/matter/clusters/matter_utility_internal.h` | Private bounded TLV command/global-attribute helpers |
| `main/apps/matter/model/matter_im_read.h`, `matter_im_subscribe.c` | Opt-in report-on-version policy; unchanged default behavior |
| `tools/matter/host/matter_time_host.c/.h` | Independent UTC anchor, atomic LKG sidecar, clock/certificate adapters |
| `tools/matter/host/matter_server.c/.h`, `matter_node.c` | Clock injection before start, explicit profile, EP attachment and lifetime |
| `tools/matter/tests/runtime_pair_host.c`, `chip_tool_three_phase.py` | New profile in two complete instances, independent state and teardown checks |
| `tools/matter/tests/test_meter_services.c`, `test_time_host.c` | Behavioral, allocation and storage failure tests |
| `tools/matter/tests/test_im_subscribe.c`, `test_subscribe_model.h` | Reporting-policy regression without bypassing authorization |
| `tools/matter/tests/chip_tool_meter_services.py` | Independent real CASE/Read/Write/Invoke/Subscribe oracle |
| `tools/matter/th/meter_services_project.py` | Explicit generation of endpoint-specific PICS import projects |
| `CMakeLists.txt`, `cmake/sources.json`, `cmake/test-cases.json`, `doc/oss/test-map.json` | Build floor, source/public-header registration and test packaging |
| `README.md`, `doc/meter-services.md`, `doc/roadmap.md`, `doc/oss/status.md`, `doc/oss/test-map.md`, this report | Usage, coverage and the requested ordered acceptance plan |

## Reproducible commands and evidence

```sh
cmake --build build/gcc -j 3
ctest --test-dir build/gcc --output-on-failure
cmake --build build/sanitize -j 3
ctest --test-dir build/sanitize --output-on-failure
ctest --test-dir build/gcc -R 'test_im_subscribe$|test_meter_services|test_time_host$|inventory' --output-on-failure
ctest --test-dir build/sanitize -R test_time_host --output-on-failure
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_meter_services.py tools/matter/tests/chip_tool_three_phase.py tools/matter/th/meter_services_project.py
git diff --check
```

Build configuration: Debug, official pinned mbedTLS, and `MATTER_SANITIZE=ON` only
for the separate sanitizer build. Full host/pair launch commands and oracle
arguments are in [meter-services](../meter-services.md). Memcheck used
`--leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all
--track-origins=yes --error-exitcode=99`; sanitizer runs used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, `UBSAN_OPTIONS=halt_on_error=1`.

Raw build/controller/TH logs and local runners are retained under ignored
`build/mp04/` and the isolated lab directory. No credentials, live node state,
lab project exports or specification files are tracked. Final successful build
logs were checked for compiler warnings.

The original MP05 follow-up is deferred by the updated [roadmap](../roadmap.md):
MP04a discovery investigation, then CSA01 full-matrix acceptance before tariffs.
The roadmap requires all applicable CSA cases before Google
acceptance, then measured optimization, then downstream integration outside this repo.
