# CSA02: commissioning and fabric lifecycle

This pass addresses failures from the frozen CSA01 x86 profile. The CSA01 matrix
is retained as the baseline; `csa02-results.json` records subsequent attempts and
the latest results for the selected cases. Inherited results are not new runs.
The profile, development credentials, PICS and official test assertions remain
unchanged. This is implementation acceptance, not certification.

## Corrections

**Sparse fabric table in the host.** `TC_OPCREDS_3_2` removes the second of three
fabrics and then uses the surviving controller to remove the third.
`TC_CADMIN_1_15` removes a fabric through its own controller, then reads through
another controller. Both exposed a host exit, not merely a dead session:
`Meter services process failed`. The clock-floor scan used the number of live
fabrics as an array bound. Removal leaves holes in that array, so the scan tried
to parse an empty certificate and omitted a later live slot. It now scans the
fixed table capacity and skips entries without a fabric index. Certificate
parsing failures on occupied slots still fail; they are not ignored.

**Fail-safe cleanup waiting for an unavailable ACK.** In `TC_CADMIN_1_3`, a
repeated commissioning attempt rejects an existing fabric. CHIP then sends
`ArmFailSafe(0)`, receives its response, and evicts PASE before sending the
standalone ACK. Its log explicitly records failure to send that ACK. The old
dispatcher kept the expiry response/session alive until peer delivery or a
deadline, preventing rollback from finishing and gating the next CASE
TimedRequest. A temporary trace confirmed pending PASE retirement and gated
CASE work at that point.

The dispatcher now preserves the expiry response only through its **local UDP
completion**. It then retires the session and cancels remaining transport work,
without requiring the peer ACK. Rollback still waits for session-context and
borrowed-buffer cleanup, as required by Core 11.10.7.2.2. No new IM authority is
granted to the session while its response is pending. This also frees admission
for a later PASE. A send failure and the existing finite deadline retain their
cleanup paths. Self-RemoveFabric response handling is unchanged.

Files changed for these corrections:

- `tools/matter/host/matter_node.c`: scan occupied fabric slots when advancing
  the host clock floor.
- `main/apps/matter/runtime/matter_dispatch.c` and `.h`: distinguish local send
  completion from peer acknowledgement during fail-safe retirement; document
  the drain-before-rollback contract.
- `tools/matter/tests/test_dispatch.c`: pending local send, completion without
  ACK, error/deadline, PASE and affected CASE fabric, and unrelated fabric
  isolation.
- `tools/matter/tests/test_fabric.c`: an identical committed root succeeds
  without adding another TrustedRootCertificates entry during a new fail-safe.

The public API signatures, storage format, certificate validation and resource
capacities do not change.

## Test/specification discrepancies retained as FAIL

The normative references below are from the locally supplied Matter Core R1.6.1,
CSA document 23-27349, September 16, 2026. No official test was patched and no
failure was waived.

- **CGEN 2.2, step 6:** the installed test assumes `IssueNOCChain` produces a
  different root. Diagnostic runs instead showed a 400-byte pending certificate
  exactly equal to the already installed certificate (`memcmp` equality). The
  pending root was present; no attribute/chunk was lost. Core 11.18.6.13 requires
  success **without changing the list** for an exact byte-for-byte duplicate.
  Adding a synthetic duplicate to satisfy the count assertion would violate that
  rule. Different-root installation and rollback are exercised by OPCREDS 3.1;
  the focused regression protects the duplicate case. The full CGEN 2.2 scenario
  remains unaccepted pending a test/fixture or CSA resolution.
- **OPCREDS 3.4 and CADMIN 1.10:** their failing calls await a response to
  RevokeCommissioning over PASE. The note in Core 11.19.8.3 says the caller must
  not expect a response because the command terminates PASE. This must be
  distinguished from CADMIN 1.3's TimedRequest timeout over surviving CASE.
  Preserve the official FAILs and resolve them with CSA; do not extend PASE
  authority to manufacture a passing response.

The initial CSA01 suggestion to preserve a RevokeCommissioning response over
PASE is superseded by this normative check.

## Evidence and validation

The final source completed all seven selected official cases:

| Official case | Run ID | Result | Remaining failure |
| --- | --- | --- | --- |
| TC_CADMIN_1_3 | 251 | PASS | None; includes 180-second window expiry and subsequent CASE |
| TC_OPCREDS_3_1 | 252 | PASS | None; root/NOC rollback and subsequent PASE |
| TC_OPCREDS_3_2 | 253 | PASS | None; remove an intermediate fabric and continue |
| TC_CADMIN_1_15 | 254 | PASS | None; self-removal preserves another controller |
| TC_CGEN_2_2 | 255 | FAIL | Step 6: expects two roots after installing an identical root |
| TC_OPCREDS_3_4 | 256 | FAIL | Step 31: awaits RevokeCommissioning response over PASE |
| TC_CADMIN_1_10 | 257 | FAIL | Step 9: awaits RevokeCommissioning response over PASE |

[Result delta](csa02-results.json) retains all **23 official attempts**, including
intermediate failures. Only the seven `source_stage: final` runs (251-257) update
the baseline. The combined matrix is **77 PASS, 28 FAIL, 21 BLOCKED, 32 MANUAL
and 704 NA**. This is not a new run of the whole catalog: unselected results are
inherited from CSA01.

Exploratory run 243 stopped earlier at WindowAlreadyOpen after the test observed
WindowNotOpen and tried to open a new window without the full expiry wait. This
reporting/timing observation remains recorded; the final CADMIN 1.3 run followed
the full 180-second path. Intermediate attempts using an abandoned cleanup
variant are not evidence for the final implementation.

Private raw evidence is kept under ignored `build/csa02/` and in the isolated
lab, including official logs, raw execution JSON, PICS hashes, build logs and
source identities. No credentials or raw lab captures are exported here.

The installed TH/SDK baseline is the same as [CSA01](csa01-validation.md):
TH v2.15.1+summer2026, SDK `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`,
GCC 13.3.0 and official mbedTLS 3.6.0. A source manifest checks every tracked
C/H file against the lab copy. Exploratory builds and intermediate attempts are
retained separately; only final-source runs update the acceptance result.

Final SHA-256 identities:

| Artifact | SHA-256 |
| --- | --- |
| Manifest of 350 tracked C/H files, matched against lab | `74cf71a6e42968c5f91a5a8eb9e7db588be3b4c39bfc9045ec79e1f28c38e087` |
| Official-test matter-node | `ea6f6038aa6aa9527a817d1bc7564d440fc330f1afd8032039850a3ac13ec382` |
| Memcheck runtime-pair-host | `05c81465285d97335937fdc593c67d9c87fc3adff706678db1bac54858eade78` |
| Sanitized runtime-pair-host | `dad2d4fa8bd1186951e15ed7173b531458937140dc6ed656b4a29f8eff304ed1` |

Validation commands and outcomes:

- Fresh Linux CMake build with GCC `-Wall -Wextra -Werror`: PASS. No temporary
  diagnostic instrumentation remains in the final executable.
- `ctest --test-dir build/final --output-on-failure -R
  '^(test_dispatch|test_fabric|test_root|test_root_alloc|test_time_host)$'`:
  **5/5 PASS**. The same selection in `build/sanitize`: **5/5 PASS** with
  ASan/UBSan/LSan enabled.
- `test_discovery_startup_linux.py --mode memcheck` with the final pair host:
  **PASS**, A then B. Browser starts before both runtimes; real chip-tool performs
  commissioning, reads, subscriptions, commands and fabric removal. Both
  instances are deleted and the process exits normally. Valgrind 3.22.0 reports
  **0 errors, 0 bytes in 0 blocks at exit**, 48,513 allocations and frees, no
  suppressions; full leak checking and origin tracking enabled.
- The same complete scenario with `--mode sanitize --reverse`: **PASS**, B then
  A, separate ASan/UBSan/LSan executable with `detect_leaks=1:halt_on_error=1` and
  `UBSAN_OPTIONS=halt_on_error=1`; normal deletion and exit without diagnostics.
- `python tools/matter/check_test_map.py` and `git diff --check`: PASS.

The full pair scenarios did not reproduce MP04a's intermittent final-fabric
Invoke-response timeout. Its cause has not been established; these two passing
runs do not close that historical issue or prove that the present fixes address
it. Memcheck and sanitizers cover the executed paths, not all possible inputs.

No Windows recheck, Google Test Suite, physical radio/device or firmware
integration is covered by this pass. Remaining CSA01 composition, reporting,
diagnostics, discovery, resource-pressure and fixture gaps remain open. The
three selected official FAILs require test/fixture or CSA resolution; no such
resolution or waiver has been obtained.

**Next: CSA03 — Descriptor and endpoint composition against Device Library**,
starting with official IDM 10.5 and endpoint-local PICS/composition failures.
