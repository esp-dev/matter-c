# CSA73: frozen Memory39 integration and regression

**Acceptance PASS in the executed scope:99/99 previously PASS automatic positions remain PASS.**

The [integration plan](csa73-integration-plan.md) freezes baseline `e75885b`,
Memory39 source `6c9835a986ec869c5d49f2d380f0818e307bf78d` and merged candidate
`ff3a732`. Forty committed changes merged without conflicts. The working Memory40
changes and later source commits are excluded. The separate source checkout was
only read; no reset, clean, branch switch, commit or publication occurred there.

## What was integrated

Transactions/TX packets, live events, immutable report snapshots, stable result
blocks and event selectors now allocate for actual work. Storage/Fabric staging,
PASE/CASE/resumption, crypto, cluster encoders and OTA workspaces use bounded
phase ownership. Retained RX is serviced before a new inbox, and stale ACKs
cannot starve own-fabric removal replies. The merge also brings the optional C6 lab, instrumentation,
regression tools and their documented historical results. Current core C/header
inputs match the frozen source exactly. No additional native repair was needed.

Application-owned scheduling and per-instance lifecycle remain in place; the
normal library has no test fault hooks. Compiled capacities, advertised per-fabric
subscription budget, profile/PICS, persistent schemas and official test assertions
were retained. The existing pair oracle has an explicit metered-switch inventory
flag from the imported branch; this corrects fixture selection without dropping
its expected cluster/attribute checks.

## Fresh regression

| Lane | Outcome | Coverage |
| --- | --- | --- |
| Windows GCC16.2.0 UCRT MinGW |112/112 CTest | Host/desktop compile, OOM/lifecycle, storage and relocated consumer |
| Linux normal |109/109 CTest | Complete default native inventory and packaging |
| Linux ASan/UBSan/LSan |109/109 CTest | Separate instrumented build, leak detection/halt-on-error |
| Full two-runtime lifecycle |6 groups in each variant | Independent three-phase nodes, CASE, reports, Wi-Fi rollback/commit and removal replies |
| Native wire fault/recovery |6 cases in each variant | Five fabrics, fifteen CASE sessions/subscriptions, full Reads, OOM, ACK ordering, reconnect and zero-live drain |
| Linux UDP/IPv6 |14 cases in each variant | MTU/extensions, checksum/length, fragments, empty packets, interface filter and recovery |
| Signed simulated OTA |PASS in each variant | BDX bytes/EOF, token/version, Apply/Notify, restart and new-version CASE readback |
| Offline measurement decoders |25/25 | Heap-map and report-block corruption checks |

Normal full-runtime, wire, UDP and requestor scenarios ran under Memcheck. Their
completed native lifetimes have zero reported memory errors and zero exit
bytes/blocks. Sanitizer scenarios were separate, never run under Valgrind.
Both Linux and Windows builds have no compiler warning/error diagnostics.
Wire fixtures require real owner stop/drain; forced termination is not accepted.
Original/corrected-peer single-lost-ACK controls retain their distinct expected
outcomes, strict wrong-role rejection and survival of all existing CASE sessions.
Intentional OOM/loss failures remain distinct from healthy-operation errors.

IPv6 used the existing fixed loopback-only injector capability. The receiver
remained unprivileged; no capability, service, interface or firewall change was
made. There was no physical-device build/flash/acceptance by this stage.

## Original CSA automatic PASS-set comparison

| Group | Fresh PASS positions |
| --- | --- |
| commissioning | 21 |
| composition | 13 |
| interaction-security | 33 |
| measurements | 18 |
| resource-long | 2 |
| setup-codes | 3 |
| yaml | 9 |

The first98 positions reuse the frozen original CSA58 fixtures, including its
corrected actual QR and explicit simulated Wi-Fi in-test parameter. The last
position repeats unmodified TC_DA_1_7 with two actual isolated instances and
distinct laboratory DAC keys, following CSA70. This is development identity
acceptance, not production PAA/DCL or manufacturing qualification.

Each original case uses a fresh process/store, real reset handling and its full
observation period. TC_RR_1_1 retains its full resource-test wait and optional
local SessionID check. No timeout was shortened and no unknown prompt received
a synthetic PASS. All original native lifetimes exit0 with empty stderr.

All99 exact case/endpoint/collection identities match the baseline automatic
PASS set. Original TH verdicts, step states, log/result hashes and source hashes
are in [the receipt](csa73-results.json). Not-applicable steps remain excluded
from successful checks. This is one complete regression sweep, not an endurance
campaign or a new155-position full-matrix result.

## Evidence identity and cleanup

All862 exported tracked files match their Git-archive hashes after execution.
Both native builds use pinned official Mbed TLS3.6.0. Original76 SDK source and
metadata files plus the shared helper fingerprints remain unchanged. The TH
repository revision identifies TH, not an independently verified SDK binding
checkout. The pre-existing sdk_container support modification is retained and
fingerprinted; no pristine-harness claim is made.

Private lab paths, source exports, process identities, credentials, controller
stores, detailed traces and raw logs remain ignored. Temporary laboratory PAA
files are removed and TH finishes idle. Existing paired Windows nodes/profiles
and the source memory worktree were not changed by this integration.

Executed command forms (private machine-specific paths omitted):

```text
cmake -S <frozen-source> -B <build> -DCMAKE_BUILD_TYPE=Debug ...
cmake --build <build> -j 3
ctest --test-dir <linux-build> --output-on-failure -E runtime_wire
ctest --test-dir build/csa73/windows --output-on-failure
python tools/matter/tests/chip_tool_three_phase.py ... --source-registers --meter-services
python tools/matter/tests/runtime_wire.py ... --memcheck
python tools/matter/tests/test_ota_chip_provider.py ... --mode update --events --local-query --require-trace --apply-binding --bdx-profile
python examples/esp32-runtime/tests/heap_audit_decode_test.py
python examples/esp32-runtime/tests/report_blocks_decode_test.py
python tools/matter/check_test_map.py
python tools/matter/csa_campaign.py
python tools/matter/csa_review_packet.py
git diff --check
```

Normal Memcheck and separate sanitizer commands/scenario outputs are recorded
independently. Default CTest excludes optional wire/raw-packet cases; those were
explicitly executed in the additional lanes above. No Google/Apple UI, physical
firmware,128KiB RAM-fit or product certification claim follows from these results.

Counts remain **123 PASS/27 FAIL/5 prerequisites**. The99 automatic PASS outcomes
now have fresh regression evidence;24 manual PASS outcomes remain historical.
The27 FAIL and5 prerequisites retain their CSA72 gates and were not relabelled
or resolved by this regression. The owner-deferred multi-hour DGGEN case was
not restarted. No information was sent to CSA and no push was performed.

Next: review a separately frozen Memory40 integration and its affected Read
lifetime/report regressions, while continuing the existing CSA72 clarification
and laboratory-prerequisite work.
