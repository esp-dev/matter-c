# CSA01: complete installed-catalog matrix for the x86 profile

Acceptance baseline: `d722a0b`, whose C sources are unchanged from MP04
`ff00f26`. MP04a was committed before this campaign. No C implementation,
test assertion, certificate validation policy or device type was changed to
make this campaign pass. This is development acceptance, not certification.

## Results: 2026-10-13

The first pass is complete: **862 catalog/endpoint entries**, covering **844
distinct test-plan IDs**, with no remaining PLANNED entry. Catalog aliases and
different endpoints are retained explicitly; these are not 862 independent
requirements. Executed **112 official TH runs** (IDs 123 through 234) for **109
matrix entries**. Three reruns retain their original evidence.

| Final classification | Entries |
| --- | ---: |
| PASS | 73 |
| FAIL | 32 |
| BLOCKED | 21 |
| MANUAL, not executed | 32 |
| NA, with applicability reason | 704 |

Of the 21 blocked entries, four reached an operator-action boundary and were
cancelled explicitly; 17 lack the required OTA or three-phase trigger fixture.
FAIL retains the official state even where triage identifies a lab prerequisite,
development identity or possible test/specification mismatch. The counts are
not a certification percentage. The final TH state is idle.

Passing coverage includes all five final endpoint PICS checks, EPM and Power
Topology on aggregate/L1/L2/L3, cumulative EEM, static Meter Identification,
Identify's automated cases, three Time Synchronization cases, CASE/resumption,
operational and QR/manual-code discovery, and the 15-session/five-fabric SC 3.6
scenario. The latter received all expected reports without resubscription; the
separate, broader RR 1.1 subscription/resource scenario still fails.

All four historical CGEN/OPCREDS/ACL failures reproduced. CADMIN 1.5 passes after
correcting DUT startup; its first setup error remains in the attempts history.
CADMIN 1.3's second run still fails, now at RevokeCommissioning rather than the
initial whole-test watchdog. No implementation failure was relabelled as PASS.

## Frozen scope

The DUT is the Linux host with `--three-phase --source-registers --meter-services`.
It has root EP0, aggregate EP1 and phase EP3/4/5, with simulated Wi-Fi and source
registers. It excludes the optional diagnostic On/Off endpoint. Phase energy is
not synthesized by dividing aggregate energy. The manufacturer-specific source
cluster remains present, but its semantics have no CSA test case.

[Observed standard-cluster inventory](csa01-profile.json) records all 27 standard
server instances, revisions, features, attributes and command lists from a live
wildcard read. Descriptor.ClientList additionally contains OTA Provider `0x0029`
on EP0 and is empty on the application endpoints. There are also the
manufacturer-specific server on EP1 and the existing partial OTA client/runtime.
The current Descriptor advertises Root Node
and Electrical Sensor; it does not advertise a complete Electrical Utility Meter.

| Endpoint | Advertised type/revision | Measurement scope |
| --- | --- | --- |
| 0 | Root Node `0x0016`, revision 5 | Commissioning, management, diagnostics, time and OTA |
| 1 | Electrical Sensor `0x0510`, revision 1 | Aggregate EPM, cumulative import/export EEM; source registers and meter services |
| 3, 4, 5 | Electrical Sensor `0x0510`, revision 1 | L1, L2, L3 EPM; no fabricated per-phase energy |

The [complete matrix](csa01-matrix.json) enumerates the installed TH catalog,
including explicitly inapplicable clusters/transports/roles. Separate entries
cover EPM/Power Topology on all four measuring endpoints and endpoint-local PICS
checks. Exact underscore and hyphen case IDs are retained: a CLI alias must not
accidentally select a manual procedure as well as its Python counterpart.

## Test identity and evidence

- CSA TH `v2.15.1+summer2026`, SDK metadata commit
  `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`.
  Installed coordinator `3b14c06`, backend
  `4cb5753ffb6915850fbf02b1dfbbcd382945ede2`. The pre-existing local backend
  patch changes only the SDK checkout mount path for the lab account; it changes
  no test assertion. Source hashes in the matrix identify the installed scripts.
- DUT GCC 13.3.0 on Linux; official Mbed TLS 3.6.0 at
  `2ca6c285a0dd3f33982dd57299012dacab1ff206`.
- DUT executable SHA-256:
  `a4381c79ac55cd078f2ee079b135907f70af2e1ccdab4ce85ba0527b119c9c0e`.
  All 197 C/H files in its source snapshot match the current checkout after
  normalizing line endings. This campaign reuses that binary; it does not claim
  a new compiler/sanitizer run for documentation and Python-tool changes.
- The framework initially loads its default 1.6 model, then conformance tests
  select **1.6.1** from the DUT's `SpecificationVersion=0x01060100`. Both model
  selections appear in the logs; the initial line alone is not the tested version.
- Fresh disposable state and commissioning per case. Network cases run serially.
  The preparation adapter answers only the three known commissioning prompts.
  Other operator requests stop the case and remain visible as blocked coverage.
- The JSON result includes the actual execution PICS, configuration, case/step
  states and run ID. CLI exit status is not used as a PASS oracle. Matrix entries
  retain the actual PICS/result hashes and skipped-step counts.
- Full TH JSON, official logs, DUT state/logs, catalog and SDK scripts remain in
  ignored lab evidence. Public files contain our capability/results index and
  hashes, not CSA documents, copied test procedures, credentials or private paths.

The first nine root cases used the initial complete cluster PICS; subsequent
projects add explicit core-role declarations. No failed capability was disabled.
Application endpoint PICS are local to the selected endpoint, rather than carrying
the root's server flags. Each run's retained PICS is authoritative.
The final PICS also explicitly declare the observed OTA Provider client on EP0,
including QueryImage, ApplyUpdateRequest and NotifyUpdateApplied. Final PICS
include its limited Controller role; they still exclude Commissioner and general
Read/Write/Subscribe client behavior. SC 4.4 stays in manual coverage: its example
uses a BINFO Read client, which is absent. Resolve that procedure's applicability
for the OTA-only initiator with CSA rather than silently excluding discovery.
Final PICS checks cover every endpoint; this does not turn the blocked OTA transfer/apply
campaign into completed coverage.

The whole-test watchdog is 1500 s for long scenarios; the external launcher
allows 1800 s and waits for the previous DUT to exit before starting the next.
These are execution envelopes, not altered commissioning/reporting timers.
The initial CADMIN 1.3 run hit the SDK's shorter default watchdog; the initial
1.5 attempt did not start its DUT during launcher recovery. Both first results
are retained when repeating with the corrected lab lifecycle/configuration.
CADMIN 1.3's second run passes the 180-second window-closure check, then times
out waiting for RevokeCommissioning in step 12. Its FAIL remains an active
protocol/lifecycle investigation, no longer just a whole-test watchdog failure.
QR/manual-code discovery uses separate projects with payloads generated by the
official chip-tool for the fixture's actual discriminator and development IDs.

Certification-disallowed conformance bypasses are explicitly false:
`ignore_in_progress_test_event_only_disallowed_for_certification`,
`allow_provisional_test_event_only_disallowed_for_certification`, and
`allow_unsupported_described_conformance`. `PICS_SDK_CI_ONLY` is false. The lab
still uses development attestation credentials and TH development mode; these
facts are not a claim of production certification readiness.

## Interpreting coverage

`PASS` means the official case reports success, with its recorded skipped steps;
it does not certify unsupported optional behavior. `FAIL` is an unmodified TH
failure, pending implementation/specification triage. `BLOCKED` means a missing
fixture, required operator action or execution prerequisite. `MANUAL` identifies
unexecuted operator procedures. `NA` has a capability/role reason. None of those
last three categories is counted as PASS. Python and YAML versions remain
separate catalog entries, not independent implementations of the DUT.

Known fixture gaps:

- Three-phase mode rejects `--test-event-key`; dynamic EPM and cumulative EEM
  trigger cases cannot borrow results from the old aggregate-only profile.
  MTRID 3.1 likewise stops on TestEventTriggersEnabled=false; it needs the
  metering-identification change/reset trigger, not only energy simulation.
- OTA needs its provider, image, authentication and apply/reboot fixture enabled
  together. The frozen meter host has not been configured for that campaign.
- Reset/physical indication/radio changes, packet inspection and onboarding
  artifact checks need explicit actions/evidence, not automatic affirmative replies.
- Development DAC/CD and a single simulated DUT cannot establish production
  attestation provenance or uniqueness between manufactured devices.
- The MP04a RemoveFabric timeout with concurrent subscriptions remains a separate
  independent-controller regression. Successful single-DUT CSA cases do not close it.

## Reproduction

Export the installed TH catalog/metadata privately and take a live profile
inventory. On the authorized TH machine, `TH_SDK_TESTS` below refers to its
`backend/test_collections/matter/sdk_tests` directory. Preserve the installed
versions; do not replace these sources with a newer public SDK during indexing.

```sh
mkdir -p build/csa01
th-cli available-tests --json > build/csa01/catalog.json
cp "$TH_SDK_TESTS/python_tests_info.json" build/csa01/
cp -R "$TH_SDK_TESTS/sdk_checkout/python_testing" build/csa01/
cp -R "$TH_SDK_TESTS/sdk_checkout/yaml_tests" build/csa01/
```

Keep those inputs private and ignored. Generate endpoint projects from a private
exported base project:

```sh
python tools/matter/th/full_profile_project.py \
  --base build/csa01/base.json --profile doc/oss/csa01-profile.json \
  --endpoint 0 --discriminator 3910 --output build/csa01/project-0.json
th-cli project import -f build/csa01/project-0.json
# Repeat for endpoint 1, 3, 4, 5 using distinct discriminators/projects.
```

Start a fresh host for each case, with its own state and private credential
directory. Execute the exact installed case ID through the TH CLI Python
environment (the ordinary runner leaves manual prompts to the operator):

```sh
python tools/matter/th/run_exact.py --project-id PROJECT_ID \
  --tests-list TC_IDM_10_2 --title CSA01-ep0-TC_IDM_10_2 --no-color
th-cli test-run-execution --id RUN_ID --json
th-cli test-run-execution log --id RUN_ID --output-file build/csa01/run.log
python tools/matter/th/csa_matrix.py --inputs build/csa01 \
  --profile doc/oss/csa01-profile.json --output doc/oss/csa01-matrix.json \
  --queue build/csa01/remaining.json
```

The indexer expects `catalog.json`, `python_tests_info.json`, the private SDK
source layout, and `runs/CSA01-epN-CASE.json` with the full TH execution response.
Preparation logs with the same basename retain operator-block markers. The
queue is an index of outstanding automated entries, not an unattended reset or
test-approval mechanism. Preserve first failures when rerunning a corrected
fixture; do not overwrite them with a later successful result.

## Initial triage and normative checks

The raw FAIL state remains in the matrix even when the probable cause is a lab
precondition or a test/specification mismatch. Such a failure is not automatically
waived, and is not automatically evidence of a cryptographic defect.

The hypotheses in this table are from the first pass. [CSA02](csa02-validation.md)
supersedes its RevokeCommissioning-over-PASE response suggestion: Core 11.19.8.3
explicitly says not to expect that response. CSA02 also distinguishes an exact
duplicate RCAC in CGEN 2.2 from loss of a newly installed root, and identifies the
host's sparse-table exit separately from session retirement.

| Area | Evidence from this pass | Required follow-up |
| --- | --- | --- |
| Composition | IDM 10.5 rejects OTA Requestor on EP0 and Identify/Meter Identification on EP1 as extra clusters for the advertised types | Reconcile the complete Descriptor composition with Device Library 2.3 and the metering device types. Do not add a device type without its mandatory dependencies. |
| Fail-safe | CGEN 2.2 still expects two trusted roots and reads one | Trace pending/committed roots and rollback against the exact CSA steps. |
| Revocation | OPCREDS 3.4 and CADMIN 1.10 fail at RevokeCommissioning over PASE; CADMIN 1.3's corrected-fixture run reaches the same command timeout in step 12 | Preserve the response exchange until delivery/teardown is complete; retain the MP04a concurrent RemoveFabric regression. |
| Fabric removal | OPCREDS 3.2 times out on the second removal through the surviving controller; CADMIN 1.15 times out when the surviving controller reads after another fabric removes itself | Check that retiring one fabric preserves unrelated sessions and exchanges. |
| Repeated commissioning | OPCREDS 3.1 reaches step 73, then ArmFailSafe through the newly established PASE times out | Trace session/resource reuse after earlier fail-safe and fabric operations; do not reduce the official scenario. |
| PASE/fabrics | CADMIN 1.9 does not observe the expected rejection after repeated wrong passcodes; 1.19 returns a different error at fabric exhaustion | Verify rate limiting, session reclamation and resource-exhaustion status on the wire. |
| Reporting | CADMIN 1.25 misses expected reports; IDM 4.3 observes about 4.05 s between reports where the floor is 5 s | Check notification scheduling and empty-report interval accounting without changing the test's timing assertions. |
| Resource pressure | RR 1.1 times out while establishing the multi-client subscriptions in steps 4/5 | Trace actual session, exchange, ACL and subscription lifetimes against CapabilityMinima; increasing arrays alone is not an acceptance result. |
| Read validation | IDM 2.2 succeeds where the script requires InvalidAction | Inspect the rejected request shape and Core Interaction Model requirements. |
| Diagnostics | DGGEN 2.5 reads zero sent-IM counters both before and after activity | Wire diagnostics counters to actual runtime activity rather than constant simulation values. |
| Clock snapshot | DGGEN 2.4 rejects a null PosixTimeMs | Check TimeSnapshot against the host clock and the advertised Time Synchronization behavior. |
| Discovery | SC 4.1 does not find the long-discriminator subtype; operational discovery SC 4.3 and QR/manual-code discovery pass | Capture the exact query/response path. The earlier controller-selection fix does not establish complete DNS-SD conformance. |
| Invalid CASE input | SC 3.4 receives a timeout instead of the expected invalid-parameter error | Inspect the secure-channel rejection/status exchange against the specification. |
| Development identity | IDM 10.1 rejects a manufacturer-specific prefix using test VID; IDM 13.1 rejects the development vendor default | Keep these failures visible until testing with an appropriate assigned identity. Do not substitute an invented production VID. |
| ACL | ACL 2.4 and 2.6 reproduce the earlier ProxyView/ConstraintError expectation failures | Retain both results; resolve against the selected specification and CSA rather than changing the expected values. |
| Wi-Fi | CNET 4.1/4.4 find no connected simulated network; 4.9 lacks an effective SSID; 4.11 lacks the second AP PIXIT | Complete the on-network simulation/TH fixture before claiming Wi-Fi acceptance. No real radio was tested. |
| Attestation | DA 1.2 rejects test VID; DA 1.7 requires two DUTs | Production identity/uniqueness checks remain blocked by development credentials and the single-device fixture. Do not enable permissive flags to label them certified. |
| Setup-code uniqueness | SC 7.1 requires onboarding payloads and two factory-state DUTs for its production scenario | Prepare independent identities and payloads; successful single-DUT DD 1.16/1.17 discovery does not establish production uniqueness. |

Two discrepancies require particularly careful review:

- **BINFO 2.2:** Core 1.6.1 11.1.6 lists Leave as optional, and this profile declares
  `BINFO.S.E02=0`. The installed script treats any nonempty ReadEvent result as
  an event, then dereferences `Data.fabricIndex`; it fails on a status result
  whose `Data` is `None`. Its own no-event branch permits the undeclared event.
  This is a candidate test handling discrepancy, not evidence that Leave is
  mandatory. Retain FAIL pending CSA/test correction or an explicit resolution.
- **GRPKEY 2.1:** Core 2.11.1.2 conditions legacy group-table minima on device
  types with Groups support; 11.2.6.3 bounds the lists by MaxGroupsPerFabric.
  This profile has no Groups endpoint and reports zero groups. The implementation
  returns ResourceExhausted for a nonempty GroupKeyMap, while the script expects
  the write/readback to succeed. Resolve applicability with CSA before either
  adding group support or declaring this failure waived.

## Validation boundaries

In addition to the official runs, executed:

```sh
python -m py_compile tools/matter/th/full_profile_project.py tools/matter/th/csa_matrix.py
python tools/matter/check_test_map.py
git diff --check
```

The inventory check reports 226 mapped files, 84 native definitions, 59 core
sources and 75 closed public headers; it is not a claim that those native tests
were rerun. Matrix generation checks complete exact-case evidence. Additional
data checks verify unique matrix keys, all five endpoint PICS scopes and absence
of unknown top-level PICS gate names. The two Python tools prepare private projects
and index results; the profile/matrix/report preserve the acceptance baseline.
README, status and roadmap link that evidence and identify the next coherent pass.

This stage changes acceptance tooling/documentation only. It does not repeat
unrelated native/platform builds or relabel their results as CSA evidence.
No Google Test Suite, hardware radio, production provisioning, new memory-safety
campaign or embedded integration is covered by CSA01. The next implementation
pass must be selected from the observed failures and mandatory coverage gaps.
