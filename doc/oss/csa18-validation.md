# CSA18: targeted three-phase energy test inputs

2026-10-15. Scope: dynamic EPM/EEM acceptance of the existing Linux x86
three-phase profile. No device type, PICS, official assertion, cryptographic
policy, storage schema or public core API was changed. CSA17 and its preceding
reports were committed first as `f93f46d`.

## Previous analysis and baseline

CSA01 explicitly blocked EPM2.2 on EP1/3/4/5 and EEM2.2/2.3 on EP1 because
the three-phase host did not provide their energy TestEventTrigger fixture.
The earlier aggregate-only fixture did not cover this profile. CSA17 added
the MTRID fixture, but still rejected the energy events on the three-phase host.
This is an unimplemented laboratory input, separate from the already reviewed
test/specification discrepancies in ACL, commissioning, group keys and identity.

Unchanged official TC_EPM_2_2 on the CSA17 binary reproduces the missing route
in **run434**: commissioning and TestEventTriggersEnabled pass, then step3
receives INVALID_COMMAND (133). A fresh state and the explicit public enable
key are used; no user-paired state is touched.

The normative command boundary is Core 1.6.1 11.12.7.1: the existing diagnostics
path validates the key, and unsupported events remain INVALID_COMMAND. The
1kW/3kW values, sampling intervals and event numbers are the installed official
EPM/EEM PIXIT fixture contract, not extra production measurement requirements.
Their original scripts and hashes are retained in the result delta.

## Change and behavior

- `matter_node.c` routes energy events to EP1 or the addressed EP3/4/5 simulator.
  Endpoint0 retains the legacy alias for EP1. Other targets/codes fail before
  any measurement changes. The explicit opt-in laboratory key is still required.
- `matter_energy_sim.c/.h` retain the legacy initializer and add configurable
  normal source rates. Aggregate registers integrate elapsed monotonic time;
  STOP switches back to normal rates without restoring an earlier counter.
- Active phase inputs provide changing power and voltage, independent of the
  normal source's intentional outage cycle. STOP resumes normal readings and
  availability. The fixture affects only the selected EPM input. It does not
  model physical power flow, divide aggregate energy or create phase EEM.
- `runtime_pair_host.c` enables the same per-node source state when the test
  key is supplied. There is no global state, new heap allocation or large
  automatic buffer. All fake modes and the key remain volatile.
- `test_energy_sim.c` covers source rates and generator/STOP counter continuity.
  `chip_tool_three_phase.py --meter-triggers` additionally verifies every EPM
  target on both nodes, invalid targets/codes, changing voltage, peer/phase
  isolation, export growth and counter continuity after STOP. Readback uses the
  independent controller connection introduced in the CSA17 review.

The default profile without the key is unchanged. The legacy aggregate fixture
still uses its original rates. Existing MTRID, Wi-Fi, discovery, subscriptions,
multi-instance teardown and last-fabric response checks remain in the full pair
scenario; none were replaced by the new checks.

## Executed results

| Official case | Endpoint | Run | Result | Passed / N/A step records |
| --- | --- | --- | --- | --- |
| TC_EPM_2_2, baseline | 1 | 434 | FAIL | Missing energy trigger route |
| TC_EPM_2_2 | 1 | 435 | PASS | 10 / 4 |
| TC_EPM_2_2 | 3 | 436 | PASS | 12 / 2 |
| TC_EPM_2_2 | 4 | 437 | PASS | 12 / 2 |
| TC_EPM_2_2 | 5 | 438 | PASS | 12 / 2 |
| TC_EEM_2_2 | 1 | 439 | PASS | 10 / 0 |
| TC_EEM_2_3 | 1 | 440 | PASS | 10 / 0 |

All six final cases use unchanged official assertions. ActiveCurrent is not
declared, so its optional branches stay N/A. Aggregate Voltage is also not
declared; phase Voltage branches execute, including the different-value check.
No omitted step is counted as passed.

Normal and separate ASan/UBSan/LSan CTest runs each pass **9/9**:
`test_energy_sim`, `test_root`, `test_root_alloc`, `test_diagnostics`,
`test_meter_services`, `test_meter_services_alloc`, `test_runtime`,
`test_runtime_alloc` and `test_store`. Final normal/sanitized build logs contain
no compiler `warning:` or `error:`. A preliminary build-driver attempt requested
nonexistent CMake target names; correcting that driver required no source repair.

Full two-runtime Memcheck passes, with **65,667 allocations / 65,667 frees,
0 bytes in 0 blocks at exit, 0 errors and no suppressions**. The separate full
ASan/UBSan/LSan run also passes with reverse commissioning order. Both execute
the same eleven pair-oracle checkpoints, including energy isolation and the
pre-existing MTRID/Wi-Fi/teardown scenarios.

Latest matrix: **97 PASS, 14 FAIL, 15 BLOCKED, 32 MANUAL, 704 NA**, still 862
catalog/endpoint entries. Exactly six previously blocked rows become PASS;
unaffected official results are inherited, not rerun. Matrix reconstruction
preserves distinct manual/Python catalog entries even where their normalized
case names match. This is not full-profile acceptance or certification.

## Reproduce and evidence

Private orchestration, credentials and raw logs remain under ignored `build/`.
The committed result delta contains hashes and summaries, not laboratory secrets:

```text
python build/csa18/lab.py prepare
python build/csa18/lab.py official baseline 1 TC_EPM_2_2
python build/csa18/lab.py build
python build/csa18/lab.py official final 1 TC_EPM_2_2
# Repeat EPM2.2 for endpoints 3,4,5, then EEM2.2/2.3 for endpoint1.
python build/csa18/remote.py dut python3 /home/codex/matter-csa18/memory_run.py
python build/csa18/collect.py
python tools/matter/check_test_map.py
python -m py_compile tools/matter/tests/chip_tool_three_phase.py
git diff --check
```

Fresh output names/directories are required for a new campaign; do not overwrite
the preserved runs. The runner supplies only the public energy PIXIT enable key
temporarily and restores each TH project configuration afterwards. Unknown
operator prompts abort instead of receiving fabricated confirmations. Network
campaigns execute sequentially. The source manifest matches all 353 C/H files;
normal/sanitized node and pair-host binary identities and controller hashes are
recorded in [csa18-results.json](csa18-results.json).

Native Windows, physical firmware, manual Google/Apple Home and a complete
repeat of the remaining CSA suite were not executed. Existing 14 failures and
other fixture blockers remain; no PICS exception or CSA waiver was obtained.
After collection TH was idle, no CSA18 DUT process remained, and the owned
UDP test ports 5541/5542/5551 were free. No commit or push of CSA18 was made.

**Next: CSA19 — configure an OTA provider/image/restart fixture and run the
first applicable TC_SU_2_1 case on a disposable host.**
