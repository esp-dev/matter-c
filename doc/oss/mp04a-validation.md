# MP04a - simultaneous startup discovery, 2026-10-13

The observed wrong-node selection is in the pinned controller's legacy
`pairing onnetwork-long` path. The two DUTs' PTR, SRV and TXT records are coherent.
The pair acceptance oracle now uses the existing discriminator-checking
`pairing code` path of the same unmodified chip-tool binary. No library C code,
wire format, public API or advertisement timing was changed.

## Reproduction and cause

Baseline: two complete `runtime-pair-host --meter-services` instances in one
process/thread, same interface, distinct service names/hostnames and UDP ports.
A advertises D=3846/port5541, B D=1234/port5542. Discovery was active before the
DUT started, with no announcement-settling delay. Captures use ordinary multicast
UDP sockets, without raw-socket privileges.

In `baseline-B`, the controller queried `_L1234._sub._matterc._udp.local.`.
A's unsolicited announcement arrived first and correctly contained D=3846,
SRV port5541 and its own `_L3846` PTR (no `_L1234` PTR). chip-tool immediately
logged `Discovered Device: ...:5541` and commissioned A. B's correct D=1234/
port5542 announcement followed about 10 ms later. A matching earlier baseline
request for A succeeded. A later plain `legacy-BA` full run also succeeded when
B was selected first: the legacy failure depends on announcement ordering.

With `pairing code`, the same binary logs rejection of the other discriminator,
then an exact match and PASE to the intended port. The final four QR-path runs
all logged this rejection, selected both intended ports and completed both
commissionings with attestation verification. All captured DUT records retained
the expected subtype/instance/port relationships.

Source cross-check: the locally inspected CHIP revision
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7` dispatches MinMDNS commissioning
results while any commissionable browse is active. `PairingCommand::OnDiscoveredDevice`
checks commissioning mode but not the requested discriminator;
`SetUpCodePairer::NodeMatchesCurrentFilter` checks the setup payload discriminator.
This source checkout is not claimed to be the exact binary's source revision;
the packet/controller logs establish the behavior of the tested executable.

Controller: snap revision363, version `6170af84+snap`, amd64, SHA-256
`7203652c18c2773274d738506fce137598e1478b28502259e8751c7d9b30b459`.
The executable and official CSA assertions were not patched.
Normative reference inspected locally: Matter Core 1.6.1 sections 4.3.1,
4.3.1.1, 4.3.1.3 and 4.3.1.5 for instance/host names, subtypes and TXT D.

## Acceptance results and the separate open failure

The new runner waits for the actual controller subtype query, then starts both
DUTs together. It does not wait for PUBLISHED or sleep for announcements to settle.
The full pair oracle retains exact-port assertions, wildcard inventory checks,
CASE subscriptions, independent On/Off and Identify/UTC state, deleting A with
Identify active, continued B operation and both final RemoveFabric responses.

| Run | Discovery, both commissionings and wire correlation | Complete pair scenario |
| --- | --- | --- |
| `memcheck-BA` | PASS, ports5542 then5541 | PASS, six oracle checks, exit0 |
| `memcheck-AB` | PASS, ports5541 then5542 | FAIL later: A RemoveFabric response timeout |
| `sanitize-BA` | PASS, ports5542 then5541 | PASS, six oracle checks, exit0 |
| `sanitize-AB` | PASS, ports5541 then5542 | PASS, six oracle checks, exit0 |

The failing Memcheck run reached independent Identify/UTC checks. The controller
sent RemoveFabric to A, received a StandaloneAck acknowledging its request, then
timed out waiting for the Invoke response while B continued reporting. The cause
of this later failure is not established by the discovery capture. It remains
open for the first CSA matrix pass; the run was not repeated until green and
is not counted as a full-pair PASS. The failed runner's raw result remains FAIL;
its packet correlation was checked separately during evidence review.

Memcheck reported zero errors and zero bytes/blocks at exit in both runs:
48593 allocations/frees for BA, 48501 for AB. Both separate ASan/UBSan/LSan
scenarios exited0 without findings. These are local full-host checks, not CSA
test results. The four historical CSA failures remain open as well.

The old `onnetwork-long` command is still timing-sensitive with this pinned
controller. MP04a fixes the acceptance path; it does not claim a repaired upstream
binary, universal controller compatibility, a full CSA pass or certification.

## Files and reproducibility

| Changed files | Purpose |
| --- | --- |
| `tools/matter/tests/chip_tool_three_phase.py` | QR generation via CHIP, validated discovery path, both commissioning orders, retained exact-port checks, explicit legacy diagnostic option |
| `tools/matter/tests/test_discovery_startup_linux.py` | Active-browse startup runner, independent DNS correlation, private evidence and child cleanup |
| `doc/meter-services.md` | Runnable commands and controller-path limitation |
| `doc/oss/test-map.json`, `doc/oss/test-map.md` | Register the additional external runner (226 mapped files) |
| `doc/roadmap.md`, `doc/oss/status.md` | Iterative CSA-first plan, deferred tariffs and open RemoveFabric finding |
| `doc/oss/mp04-validation.md`, this report | Preserve historical evidence and link the investigation outcome |

Run the [documented startup command](../meter-services.md#acceptance-commands)
with `--mode memcheck` both with and without `--reverse`, then separately with
`--mode sanitize` and the sanitizer executable in both orders. The diagnostic
`--legacy-discovery` option preserves exact-port assertions; wrong selection
fails the scenario rather than being accepted as expected behavior.

Additional commands executed successfully:

```sh
python -m py_compile tools/matter/tests/chip_tool_three_phase.py tools/matter/tests/test_discovery_startup_linux.py
python tools/matter/check_test_map.py
git diff --check
```

The unchanged normal and sanitizer C executables were built during MP04 from
the `ff00f26` implementation; no new C compilation or full native CTest campaign
was needed for these Python/documentation changes. No Windows, Google, hardware
or fresh official CSA tests were run in MP04a. Raw captures and logs are retained
in ignored `build/mp04a/` and the isolated lab; credentials/state are not exported
into Git. No publication or commit was performed in this stage.

Next task: CSA01 - freeze the current profile/PICS, enumerate the full applicable
CSA matrix and run the first pass, including the four historical failures and
the separate RemoveFabric regression. Tariffs remain deferred.
