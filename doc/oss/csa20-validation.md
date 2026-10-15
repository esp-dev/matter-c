# CSA20: QueryImageResponse acceptance and the announcement timing floor

2026-10-15. CSA19 was committed first as **`3f81625`**. Scope: the existing
BDX-only x86 OTA Requestor profile and unchanged TC-SU-2.2 manual procedure.
No device type, PICS, public C API, credentials, image format or storage schema
was changed. The external official CHIP provider remains source-unmodified.

## Standard first, then independent evidence

Core 1.6.1 **11.20.3.2** requires at least 120 seconds between queries. Busy
also requires the provider's DelayedActionTime; that delay starts at the response
(**11.20.6.5.2**). Same/older versions or an unusable ImageURI must return to
awaiting the next opportunity, without starting the offered transfer. The BDX
URI constraints in that command require the provider's 16-character uppercase
Node ID and a nonempty absolute path. These requirements, not SDK behavior,
define this acceptance.

The installed **TC-SU-2.2**, SDK YAML Tests / FirstManualSuite, contains seven
manual verification steps. YAML SHA-256:
`78aaa7f26d39324e4c19678bca2e081b1823cd60f8b698a101501b2621b96ecc`.
It is not an automatic Python TC_SU_2_2 test. The optional HTTPS step is outside
the declared BDX-only profile and the YAML itself describes it as out of scope.

## Defect reproduced and fixed

The accepted CSA18/CSA19 binary queried again after **119,862 ms** when an
announcement followed Busy / 60 seconds. A separate probe reproduced **119,858
ms** using correlated realtime/monotonic samples. The clock offset between the
first and last sample changed by about 0.001 ms; the maximum sampled range was
below 0.7 ms. This was not a VM clock correction.

`start()` schedules an asynchronous Invoke that may first establish CASE.
The old stored query floor started before that handshake. Although the Busy
retry deadline itself waited 120 seconds after completion, a repeated
AnnounceOTAProvider replaced it with the earlier stored floor, admitting an
actual query too soon. Busy / 150 seconds in CSA19 did not expose this because
the provider delay dominated the 120-second floor.

`matter_ota_query.c` now retains the conservative 120-second floor from Invoke
completion, alongside the provider delay. It survives announcements and provider
selection changes. Downloads are still governed by their own provider delay;
the query floor does not delay an already accepted image transfer. No clock
callback, background task, allocation, buffer or global state was added.

The new `test_ota_query.c` regression simulates 500 ms of asynchronous setup,
Busy / 60 seconds and a repeated announcement. It fails against the unchanged
old query implementation (`query:87`, exit 1) and passes with the fix. The
existing provider-switch test now reflects the conservative completion anchor.

## Completed manual TH procedure

**Run 443 PASSED**, with seven passed steps (including evidence upload) and one
N/A. The coding agent reviewed the independent wire checks, entered the
corresponding manual assessments and uploaded a compact
log containing decoded response summaries, commands, OTA records and original
artifact hashes. The original tests/PICS were not changed and TH results were
not patched into the database. This is agent-operated manual acceptance, not
automatic CSA assertions, certification or hardware acceptance.

| Step | Actual response and evidence |
|---|---|
| 1 | UpdateAvailable / version 2, valid BDX location; provider receives final BlockAckEOF, then signed simulation install/restart/NotifyUpdateApplied and fresh CASE version 2 / BootReason 5. |
| 2 | Busy / delay 60; next query after 120239 ms, measured from the preceding query; full update then completes. |
| 3 | NotAvailable; no second query or download over 120.224 seconds; fresh CASE still reports version 1 / PowerOn. |
| 4 | Busy / delay 180; next query 180247 ms after the response; full update then completes. |
| 5 | N/A: OTA HTTPS is not declared/supported by this profile. |
| 6 | Both actual version 1 and version 0 offers are sent with otherwise usable BDX locations. Both return Idle without BDX/install; version 1 is retained. |
| 7 | Actual `bdx://0000000000000001` offer, missing file path, is rejected before BDX/install; version 1 is retained. |

The pinned provider ignores CLI delay 60 for NotAvailable and omits that optional
field; this is permitted by the standard. This campaign proves its 120-second
floor, not the behavior with an explicitly supplied NotAvailable delay. Negative
version/URI runs wait for the processed Idle decision, challenge the floor with
another announcement and observe three seconds before fresh CASE readback;
they do not establish behavior at every future query opportunity.

The single matrix row moves **BLOCKED to MANUAL, manual result PASS**. Latest
counts: **97 PASS, 14 FAIL, 13 BLOCKED, 34 MANUAL, 704 NA**. MANUAL includes two
completed procedures and the other inherited manual work; automatic PASS coverage
does not increase. All other rows, including CSA19, are inherited, not rerun.
See [result delta and identities](csa20-results.json).

## Tools and memory acceptance

The official provider uses CHIP v1.6.1.0
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7`, with JSON tracing and payload hex
compiled in. The independent Python reader checks the actual secure IM response
path and decodes Status, delay, URI and version. Provider flags alone are not
accepted as proof. `json:log` is reconstructed from its 256-byte Automation log
chunks. It avoids an upstream file-trace OpenFile/create_directories failure,
confirmed with a short strace probe. No SDK patch was made.

All seven final wire scenarios ran under Memcheck: **10 requestor boots,
315,962 allocations/frees, zero errors/leaks and no suppressions**. A separate
ASan/UBSan/LSan complete update/restart also passes, with empty stderr and clean
exits on both boots. Both builds pass 11/11 focused CTests. Normal/sanitized C
and provider build logs contain no compiler warnings.

Executed commands include normal and sanitized CMake builds; 11 focused CTests
in each variant (OTA query/apply/requestor/update, allocation variants, dispatch
and runtime); the failing old-code control; seven public runner modes with
`--require-trace --valgrind`; separate sanitized `--mode update --require-trace`;
the unchanged manual TH case; Python syntax/CLI and inventory checks; and
`git diff --check`. Reproduction commands and prerequisites are in the
[OTA host contract](../ota-host.md). The full unrelated native/CSA campaign,
Windows execution, physical firmware/bootloader, radio, production credentials,
and Google/Apple Home were not tested here. Simulated restart uses the same
executable and an application-specific signed test payload.

Raw attempts, clock samples, SDK trace diagnostics, logs, state, images and keys
stay only in ignored laboratory directories. Failed early fixture/trace attempts
and both old-binary timing failures are retained separately from final acceptance.
Final C/H source manifests and binary hashes are recorded; early runner versions
are retained, and the final accepted runner's description corrects CSA19's section
number for optional Location to **11.20.6.5.1**, without changing that optionality.

Changed files and purpose:

- `main/apps/matter/clusters/matter_ota_query.c`: retain the correct query floor.
- `tools/matter/tests/test_ota_query.c`: failing-old-code timing regression.
- `tools/matter/tests/test_ota_chip_provider.py`: actual response oracles and cases.
- `doc/ota-host.md`: fixture commands, prerequisites and limits.
- `doc/oss/test-map.md`: register the additional regression coverage.
- `doc/oss/csa20-validation.md` and `doc/oss/csa20-results.json`: results and hashes.
- `doc/oss/status.md` and `doc/roadmap.md`: current acceptance and next task.
- `README.md`: make the new acceptance report discoverable.

After acceptance, owned requestor/provider processes are gone, UDP test ports
are free and TH is idle. Existing user fabrics were unused.

**Next: CSA21 — TC-SU-2.3, applicable OTA image-transfer procedures and failure paths.**
