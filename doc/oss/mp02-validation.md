# MP02 validation, 2026-10-12

Scope: the opt-in x86 three-phase Electrical Sensor profile, not certification
of a complete Electrical Utility Meter. Official upstream mbedTLS 3.6.0 is
unchanged. Firmware, production credentials and already paired user nodes were
not modified. See [profile/API/storage contract](../three-phase.md).

## Executed protocol acceptance

CSA Test Harness v2.15.1+summer2026, pinned SDK tests, separate imported PICS
projects for endpoints 0/1/3/4/5, fresh commissioning per run, strict operational
certificate validity and development PAA verification enabled:

| Official case | Endpoints | Result |
| --- | --- | --- |
| TC_DESC_2_1 | 0, whole-node composition | PASS |
| TC_PWRTL_2_1 | 1, 3, 4, 5 | 4 PASS |
| TC_EPM_2_1 | 1, 3, 4, 5 | 4 PASS |
| TC_EEM_2_1 | 1 | PASS |

Total **10/10 PASS**. This is a focused matrix. Unsupported optional attributes
remain NOT_APPLICABLE in the original tests, not manually waived assertions.
The generator `tools/matter/th/three_phase_project.py` records the changed EPM
attributes, POLY distinction, Descriptor tags and EEM reset capability. Existing
TH projects were not overwritten. Test implementation/expected results were not
patched; the existing runner selected exact case IDs and acknowledged only the
prepared commissioning prompts.

SHA256 of the executed SDK scripts (provenance, not copied specification text):

| Script | SHA256 |
| --- | --- |
| TC_DeviceBasicComposition.py | `0cd71ea50ded3dc78a12092cd844b4d843a2b256a00020f4c1f555305ae0fc22` |
| TC_PWRTL_2_1.py | `b46f22cc9abad866a5e6a0bdc67e73d004677b04865f315dcd5ae7c1dd1e5ade` |
| TC_EPM_2_1.py | `1b129d609a4b95413b7061a769ff77f5b2d5720e5f0e2ceb5156c923106b9951` |
| TC_EEM_2_1.py | `91fd1f80e7b5f5677beb76b0686daefd8ee3096ec79baa5e1dfa86ef68ad22bd` |

The additional unmodified chip-tool controller is driven by
`tools/matter/tests/chip_tool_three_phase.py`. Its oracle checks the complete
Descriptor/AttributeList inventory, tags, Accuracy measurement types, signed
units, chunked wildcard Read, Descriptor DataVersionFilter, full mixed
attribute/event Subscribe prime, subsequent EPM/EEM changes, L3 null/recovery,
event/value correlation and UnsupportedCluster for phase EEM. All these checks
passed on Linux; a second run used the saved controller credentials and DUT
state after graceful restart, without recommissioning. The final saved registers
12345760099/123480992 mWh were the first values after restart, and the next event
number advanced from 152 to 163 (reserved durable high-water gap). A first attempted
restart overlapped the original process and failed the state lock; that attempt
is not counted as restart acceptance.

## Native and memory checks

- Linux Debug: full default CTest 76/76 PASS, followed by 2/2 focused Root tests
  after adding the native `test_root_alloc` variant (77 unique current tests).
- Separate Linux ASan/UBSan/LSan: full default CTest 76/76 PASS, then those same
  2/2 Root tests, no sanitizer findings.
- Windows MinGW GCC 15.2.0: host build and focused Root/store/Read/Subscribe
  CTest 5/5 PASS, including the allocation variant. Windows is not a substitute
  for the Linux network acceptance.
- Single full Linux host under Memcheck: commissioning, Read, Subscribe, negative
  phase-EEM access and graceful shutdown passed; zero errors and zero bytes at
  exit (26066 allocations/frees). Separate instrumented full-host controller
  scenario passed with a clean shutdown and no sanitizer report.
- OOM tests now explicitly fail each allocation of tagged Descriptor, multi-EPM
  and register-EEM constructors; they check atomic failure, cleanup and recovery.
  Value tests include nonzero first register, restart, incompatible checkpoint
  mode, unavailable direction, zero, negative PF, invalid future sample, stale
  data, decreasing register, explicit replacement and failed durable commit.

- Two complete three-phase nodes in one process/thread: both commissioning
  operations, full inventories, CASE subscriptions, independent On/Off state,
  B surviving removal of A, and both last-fabric responses PASS. Memcheck:
  48289 allocations/frees, zero errors/bytes at exit. Separate ASan/UBSan/LSan
  run: same four controller checks PASS, controller/node exit 0, no findings.
- Partial startup (second UDP port occupied): expected exit 1, both allocated
  instances cleaned up, Memcheck zero errors/bytes (4342 allocations/frees).
  Legacy discovery-only host startup/shutdown: exit 0, zero errors/bytes.

The pair fixture now gives virtual devices distinct DNS host identifiers on
their shared NIC, and the oracle asserts the discovered UDP port. Previously,
the controller selected port 5542 while asked for the first discriminator;
the subsequent pairing timed out. That failed attempt is retained, not counted
as PASS. Shared DNS-host identity across two DUTs remains outside this result.
Acceptance also exposed a full-profile wildcard result limit (256 -> 320),
NULL cleanup of uncreated phase clusters and pair sampling during reset; those
were corrected and the final uninstrumented source was retested.

## Reproduction and changed files

```sh
cmake --build build/gcc -j 3
ctest --test-dir build/gcc --output-on-failure
cmake -S . -B build/sanitize -DMATTER_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/sanitize -j 3
ctest --test-dir build/sanitize --output-on-failure
ctest --test-dir build/gcc --output-on-failure -R test_root
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_three_phase.py tools/matter/th/three_phase_project.py
```

Memcheck uses `--leak-check=full --show-leak-kinds=all
--errors-for-leak-kinds=all --track-origins=yes --error-exitcode=99`. ASan is run
separately, with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`. See the profile document for controller commands.
Each output/state directory is new; a restart deliberately reuses only its
previous node state and copied controller credentials.

| Files (relative to repository) | Purpose |
| --- | --- |
| `main/apps/matter/clusters/matter_root.c/.h` | Tagged Descriptor, parent/children, additional device types and ACL type lookup |
| `main/apps/matter/clusters/matter_epm.c/.h` | Configurable AC scalars, Accuracy, per-value availability and versioning |
| `main/apps/matter/clusters/matter_eem.c/.h` | Explicit physical-register mode, reset metadata and independent availability |
| `main/apps/matter/storage/matter_store_tlv.c/.h`, `runtime/matter_store_host.c` | Schema 7 and register-mode persistence/invariants |
| `main/apps/matter/model/matter_im_read.h` | Capacity for full three-phase profile plus existing switch |
| `tools/matter/host/matter_node.c` | Opt-in host composition and deterministic source |
| `tools/matter/tests/runtime_pair_host.c` | Two complete profiles, reset-aware sampling and partial-start cleanup |
| `tools/matter/tests/test_root.c`, `test_store.c`, `test_update_store.h` | New behavior/error paths and schema migration regression |
| `tools/matter/tests/chip_tool_three_phase.py` | Independent wire-level profile and two-instance oracle |
| `tools/matter/th/three_phase_project.py` | Reproducible endpoint-specific PICS project imports |
| `cmake/test-cases.json`, `doc/oss/test-map.json` | Native allocation test and controller inventory |
| `README.md`, `doc/three-phase.md`, `doc/oss/status.md`, `doc/oss/validation.md`, this report | Usage, contracts, results and limitations |

Raw CSA logs, controller logs, state, local lab scripts and build reports are
kept under ignored `build/mp02/` and in the isolated VM test directory. They are
not public artifacts and are not evidence of a complete certification campaign.

## Limits and next task

No physical meter/ESP32 integration, real-meter accuracy, UI display acceptance,
tariff registers, manufacturer-specific extension, reactive-energy profile or
full Utility Meter device type was tested. Missing source identity, quadrant
semantics and source conversion belong to the future adapter. Partial-source
EEM event behavior and known reset timestamps need separate work; this host
provides complete import/export pairs. No MSan/TSan or new fuzz campaign was run.
The four previously documented CSA failures remain open.

Next task: MP03 — preserve the remaining source meter registers in a separately
namespaced manufacturer-specific cluster, using the same callback/snapshot
contract on x86, before implementing the remaining Utility Meter roles.
