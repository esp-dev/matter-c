# MP03 validation — 2026-10-12

Scope: the opt-in x86 meter-source extension and integration with the existing
three-phase profile. [Schema, key map and callback contract](../meter-source.md).
This is not certification of the private schema or the complete Matter stack.
Upstream mbedTLS, credentials, firmware and active user nodes were unchanged.
Earlier MP02 changes are still in the working tree; this step did not commit or
publish either stage.

## Executed checks

| Check | Result |
| --- | --- |
| Linux GCC Debug full build and CTest | 79/79 PASS |
| Separate Linux ASan/UBSan/LSan full build and CTest | 79/79 PASS |
| Final core edits: source/source-allocation tests and inventory | 3/3 PASS in each Linux build |
| Windows MinGW GCC 15.2.0 final host/pair build, Root/source/source-allocation/inventory | 4/4 PASS |
| Independent chip-tool, complete host, normal run | 10/10 checks PASS |
| Final complete host under Memcheck | 10/10 checks PASS, controller/node exit 0, zero errors and zero bytes at exit; 26305 allocations/frees |
| Final complete host, separate ASan/UBSan/LSan | Same 10/10 checks PASS, controller/node exit 0, no findings |
| Two complete source-enabled instances in one process/thread under Memcheck | 4/4 scenario checks PASS, both fabrics removed with responses, exit 0; zero errors/bytes, 48357 allocations/frees |
| Same pair scenario with separate ASan/UBSan/LSan | 4/4 PASS, controller/node exit 0, no findings |
| Partial start: occupied second UDP port | Expected exit 1, zero Memcheck errors/bytes; 4347 allocations/frees |
| Official CSA TH v2.15.1+summer2026, TC_DESC_2_1 with the MS cluster attached | 1/1 PASS, zero errors/failures/skips |
| Inventory / Python syntax / diff whitespace | PASS, 222 mapped files, 81 native definitions, 56 core sources, 72 public headers |

The full native suites ran before the last scale-format/unknown-unit adjustments;
the focused final core tests cover those edits. Final controller/memory runs used
the final implementation, including standard EPM/EEM availability propagation.
The unmodified SDK controller performed attestation, CASE and actual IM traffic.
Checks verify wildcard/chunked inventory, every custom group and stable keys,
units and source axes, coherent list sequence/version across chunks, missing T2,
unknown volume unit/time, offline/stale/recovery, dynamic readings and standard
EPM/EEM null/recovery. Further checks reject writes, an unrelated vendor namespace
and reads denied by a temporarily restricted disposable-fabric ACL; ACL restored.
The pair oracle additionally verifies the selected discovery ports and survival
of B's subscription and source reads after A's deletion.

Native error-path checks include two constructor OOM points, copied config,
independent instances, duplicate keys and invalid namespace, nonzero/zero values,
partial availability, staleness, future/regressing timestamps/sequence,
same-sequence mutation, bad UTF-8/oversized metadata, numeric bounds, callback
failure, generation change, source-sequence consistency, and source unit/time helpers
including NaN/Infinity/overflow. Maximum channel/metadata sizes were exercised.

The first controller oracle attempt failed in its generic log parser, not in
the DUT: blank DMG lines and multi-value scalar-array lines were not handled.
That parser was corrected against the retained log, then full scenarios ran.
Earlier successful intermediate runs are not substituted for the final ones.

The focused official CSA run reused the existing Root Descriptor PICS (project 3)
and the unmodified `TC_DeviceBasicComposition.py` / `TC_DESC_2_1` case. It checked
the composition and Descriptor, including phase TagLists, on a fresh disposable
node with the MS cluster attached. The raw summary records Executed 1, Passed 1,
Failed 0, Error 0, Skipped 0; the node then stopped with result 0. This does not
validate the private reading schema: those values were checked by the separate
chip-tool oracle. No test assertions or expected results were changed for PASS.

## Files and rationale

| Files | Why changed |
| --- | --- |
| `main/apps/matter/clusters/matter_meter_source.c/.h` | New reusable MS source cluster: owned snapshots, configured keys/vendor, six groups, validation and bounded encoding |
| `tools/matter/host/matter_source_sim.c/.h` | Example mapping of 61 source channels and synthetic availability/provenance |
| `tools/matter/host/matter_node.c` | Explicit option, EP1 attachment, source lifetime and standard measurement availability |
| `tools/matter/tests/runtime_pair_host.c` | Two opt-in source instances and cleanup of their simulator state |
| `tools/matter/tests/test_meter_source.c` | Boundary, lifecycle, allocation and atomic-publication tests |
| `tools/matter/tests/chip_tool_meter_source.py` | Independent decoded-TLV controller oracle, chunk assembly and negative access checks |
| `tools/matter/tests/chip_tool_three_phase.py` | Optional MS inventory/pair checks; existing MP02 paths retained |
| `cmake/sources.json`, `cmake/test-cases.json`, `doc/oss/test-map.json` | Build/install the new module and register its tests without losing existing cases |
| `README.md`, `doc/meter-source.md`, `doc/oss/status.md`, this report | Usage, schema, results and remaining work |

On Linux x86_64 Debug, GDB reports `sizeof(Source)=22672` and
`sizeof(Matter_Source_Sim_T)=3224` bytes, plus the common cluster registration
allocation. This is about 25.3 KiB of new context/simulator data per enabled
profile, not total node RAM. The two encoded arenas are intentionally bounded;
refresh/read allocate nothing. Existing IM snapshot budgets were not increased.
The disabled profile does not allocate the simulator or source cluster.

## Commands and evidence

```sh
cmake -S . -B build/gcc -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=<upstream-checkout>
cmake --build build/gcc -j 3
ctest --test-dir build/gcc --output-on-failure
cmake -S . -B build/sanitize -DCMAKE_BUILD_TYPE=Debug -DMATTER_SANITIZE=ON -DMATTER_MBEDTLS_DIR=<upstream-checkout>
cmake --build build/sanitize -j 3
ctest --test-dir build/sanitize --output-on-failure
ctest --test-dir build/gcc --output-on-failure -R 'test_meter_source|inventory'
ctest --test-dir build/sanitize --output-on-failure -R 'test_meter_source|inventory'
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_meter_source.py tools/matter/tests/chip_tool_three_phase.py
git diff --check
```

Full-host Memcheck uses `--leak-check=full --show-leak-kinds=all
--errors-for-leak-kinds=all --track-origins=yes --error-exitcode=99`. The separate
instrumented run sets `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`. The external oracle commands are in the schema
document. Every commissioning run used a fresh state/controller directory;
the harness terminated its own node with SIGTERM and checked graceful exit.
Pair teardown used RemoveFabric, with an explicit port-conflict startup case.
Build/controller/CSA logs and lab launch scripts are retained in ignored
`build/mp03/` and the isolated Linux lab directory; no credentials/state are
added to Git. Final build warning checks are part of the retained evidence.

## Limits and next task

No physical source adapter, ESP32, production VID, metrological accuracy, UI
presentation, MSan/TSan or new fuzz campaign was tested. The schema requires
application knowledge of source units, field provenance and reset/identity.
Snapshots are immutable per list during chunking, not across independent IM
attributes; clients must correlate version/generation/sequence. Only existing
EEM totals are durable in the example; other synthetic data restarts with the
simulator. The four historical CSA failures remain open. MS is not a substitute
for required standard clusters when declaring Electrical Utility Meter.

Next task: MP04 — Identify, Meter Identification and Time Synchronization on
x86, preparing the Meter Reference Point composition before tariff support.
