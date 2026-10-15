# CSA19: OTA provider, image and restart fixture

2026-10-15. CSA18 was committed first as **`dad6cb0`**. This step adds a Linux
laboratory runner and its documentation. The 353 C/H files still match the
accepted CSA18 source manifest; the C binaries are reused with verified hashes.
No C API, PICS, official test, attestation policy or persistent schema changed.

Changed files and purpose:

- `tools/matter/tests/test_ota_chip_provider.py`: reproducible independent OTA
  scenario with fresh state, signed image, Busy timing and two-boot memory modes.
- `doc/ota-host.md`: prerequisites, commands and simulation/TH boundaries.
- `doc/oss/csa19-validation.md` and `doc/oss/csa19-results.json`: acceptance,
  unsuccessful attempts, identities, evidence hashes and remaining limits.
- `doc/oss/status.md` and `doc/roadmap.md`: current classification and next task.
- `doc/oss/test-map.json` and `doc/oss/test-map.md`: register the optional runner,
  its helper dependencies and its distinction from native CTest.
- `README.md`: make the OTA laboratory instructions discoverable.

## Official procedure and result

The installed case is **TC-SU-2.1**, collection SDK YAML Tests, suite
FirstManualSuite. There is no automatic Python TC_SU_2_1 in this distribution.
The YAML's three `disabled: true` steps classify it as manual: TH converts each
to a verification prompt and adds a log-upload step. They are not skipped.

**Run442 is PASSED: three manual verification steps plus evidence upload.**
The coding agent reviewed the independent driver checks and captured peer logs;
the CLI adapter entered those assessments and uploaded the actual 178,969-byte
laboratory log. TH did not independently assert the packet values or timing.
This is a completed manual procedure, not automated CSA PASS or certification.

| Manual step | Captured evidence |
|---|---|
| 1: QueryImage fields | VID 65521, PID 32769, SoftwareVersion 1 and HardwareVersion 1 match independent Basic Information reads. ProtocolsSupported contains BDX Synchronous 0; RequestorCanConsent is false. |
| 2: Busy | One QueryImage over a real **120.209-second** observation, including a repeated announcement during the wait. No virtual clock or shortened delay. |
| 3: AnnounceOTAProvider | Another explicit announcement selects the same provider for the next query. Provider log timestamps show **150.196 seconds** between queries, respecting its requested 150-second Busy delay. |

The first Busy QueryImage supplies both the field check and the two-minute
observation. Location is omitted: Core 1.6.1 11.20.6.6.1 makes it optional;
if supplied, it must match Basic Information. The manual wording is interpreted
with that normative optionality. This does not establish country-dependent
provider behavior. The controller and both devices use a disposable fabric.

Run441 retains the earlier **CANCELLED** TH attempt: all three verification
prompts passed, but th-cli's separate file-upload handler waited for interactive
input. The CLI-only adapter was corrected and the unchanged manual case rerun;
no result was patched into the TH database. Source YAML SHA-256 remains
`0f19904fd0b1e23b7da2c6c4ca6038d7043bbc1af91bea6db00b1872ff856081`.

The matrix moves this single row **BLOCKED → MANUAL, manual result PASS**.
Automatic PASS coverage is not increased: **97 PASS, 14 FAIL, 14 BLOCKED,
33 MANUAL, 704 NA**. The MANUAL category now includes this completed procedure;
it must not be read as 33 executed manual cases. All other entries are inherited.
See the [machine-readable delta and hashes](csa19-results.json).

## Provider and supplementary full update

The official CHIP `chip-ota-provider-app` is built from v1.6.1.0 commit
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7`, with GN/Ninja, Debug/Clang and
BLE disabled. Build output is outside its SDK checkout; the checkout stays clean.
The provider build emitted no compiler warnings. SDK code is not copied into
this repository. The provider binary SHA-256 is
`36cfd8c96bb9084ec5d6d39c12e0597a64f3279c7f82b0c2f4c2f4a745b2fa4c`.

The new `test_ota_chip_provider.py` commissions provider and requestor with
attestation verification enabled. The provider ACL grants only requestor node 1
Operate on endpoint 0 / OTA Provider, retaining the commissioner's Administer
entry. A commissioned fabric alone does not authorize QueryImage.

Each scenario generates a fresh 16,585-byte Matter OTA image for software
version 2, containing a deterministic 16,387-byte body and a P-256-signed host
simulation manifest. The signing private key is never serialized. The image,
public verification key and all credentials/journals/logs stay in ignored lab
directories. Independent OpenSSL-backed Python cryptography signs the image;
the existing C/Mbed TLS backend verifies it.

The supplementary complete cycle checks BDX download, exact whole-image hash,
authentication and simulated installation, process exit for reboot, restored
version 2, NotifyUpdateApplied, and a fresh CASE read of version/BootReason 5
(SoftwareUpdateCompleted). Provider logs also confirm BlockAckEOF, completed
transfer, ApplyUpdateRequest and NotifyUpdateApplied in all three final modes.
These checks exceed TC-SU-2.1's QueryImage scope; they do not pass later OTA
cases on its behalf. The same executable is restarted; this is not a firmware
image installation, rollback test or production bootloader acceptance.

## Executed checks

| Execution | Result |
|---|---|
| Final `--mode busy-update` | PASS, 12 checks, real Busy interval and full update/restart |
| Normal binary, `--mode update --valgrind` | PASS, 10 checks across both boots |
| Separate sanitized binary, `--mode update` | PASS, 10 checks across both boots |
| Memcheck first boot | 35,532 allocations/frees; 0 errors, 0 bytes at exit, no suppressions |
| Memcheck second boot | 19,533 allocations/frees; 0 errors, 0 bytes at exit, no suppressions |
| ASan/UBSan/LSan | Both boot stderr logs empty, clean exits; separate from Memcheck |
| Packaging inventory | PASS: 230 mapped files, 85 native definitions, 59 core sources, 75 closed public headers |
| Python syntax and Linux CLI help | PASS |

The first three preflight attempts are retained with their hashes: collision
with chip-tool's default UDP port; missing provider ACL; and a colored-log
parser incorrectly reporting the BDX protocol absent. They are fixture failures,
not evidence of C protocol defects. The next preflight and first Busy cycle
passed. Final Busy, Memcheck and sanitized runs use the identical final driver.

Commands executed include GN generation/Ninja for the official provider,
the public Python runner with all three argument combinations above, the
unchanged manual TC-SU-2.1 through th-cli, `python -m py_compile` and
`python tools/matter/check_test_map.py`. Full arguments, original attempts,
raw logs and the attached TH evidence remain under ignored `build/csa19/`
and the corresponding private laboratory directory. Reproduction commands
and dependencies are in the [OTA fixture contract](../ota-host.md).

Native C builds/CTest and the two-instance campaign were not repeated because
no C code changed; their CSA18 results are inherited, not new results here.
The Windows Python CLI help check found the optional `cryptography` dependency
absent; Linux help and all laboratory executions succeeded with it installed.
No Windows node, physical device, radio, Home application, executable firmware
update or production attestation was tested. Memory instrumentation covers the
C requestor, not the separate CHIP provider/controller. No public trust keys,
captured credentials or SDK test distribution were added to Git.

After acceptance, owned provider/requestor/controller processes are gone,
their UDP test ports are free and TH is idle. Existing user fabrics were unused.

**Next: CSA20 — TC-SU-2.2, the applicable QueryImageResponse scenarios,
including Busy/NotAvailable timing and invalid URI or non-newer version rejection.**
