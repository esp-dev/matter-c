# CSA07: discovery on repeated commissioning

## Reproduced defect and attribution boundary

A rapid close/reopen of a commissioning window can permanently stop the host's
commissionable mDNS publication. `advertisements()` previously decided whether
to finish withdrawal solely by comparing the requested mode/discriminator with
the advertised values. When the window returned to the old values before the
asynchronous goodbye sequence completed, the comparison became equal. The old
module finished stopping, but the host never replaced it with a new publication.

This was reproduced through **real CASE commands on the unchanged CSA06 binary**:
open an enhanced window, observe its announcement, revoke it, then immediately
open another enhanced window with the same discriminator. The revoke/reopen
command sequence took 378 ms. Capture shows the old advertisement's two goodbye
packets and no renewed positive announcement during the following eight-second
observation. The native deterministic regression also fails on the old host at
the assertion that the reopened window is published.

The original TC_ACL_2_8 run 289 from CSA06 has no packet capture. Nine unchanged
official baseline repetitions in CSA07 all passed. The controlled reproduction
therefore establishes a host defect consistent with that symptom, **not proof
that it caused run 289**. Keep the historical failure and attribution uncertainty;
do not reinterpret it as a passed run or a confirmed controller defect.

## Fix and specification

`tools/matter/host/matter_node.c` now remembers that withdrawal is in progress
and drains it even if the desired mode/discriminator returns to its old values.
After draining, it publishes the current requested state. Window observation
is separate from the record still being withdrawn, with state owned by each
Node. The application still drives every step; no threads, sleeps, retries in
the library, global registries or public API changes were introduced.

A second correction follows Core 1.6.1 section 4.3.1: every entry into
commissioning requires a newly selected random 64-bit DNS-SD instance name,
which remains stable while that window stays open. Previously the host reused
its boot name for every window. The new host rotates only after old record
references are released, using the existing OS entropy function. Entropy failure
follows the host's error/cleanup path instead of reusing an old identity. Boot
initialization records the initial observed mode so it does not rotate again
merely on the first event-loop iteration.

After the fix, the same CASE revoke/reopen sequence took 342 ms and passed:
withdrawal finished, a different instance completed probing, and the new
enhanced window was announced. The official run 301 capture also contains four
distinct enhanced-window instance names for its four new windows. Captures are
multicast mDNS over IPv4/IPv6; they do not purport to capture every unicast packet.

## Official acceptance

| Case / source | Run IDs | Result |
| --- | --- | --- |
| TC_ACL_2_8, unchanged CSA06 binary | 292-300 | 9 PASS; historical timeout not reproduced |
| TC_ACL_2_8, corrected host | 301, 302, 303 | 3 PASS, modern and legacy multi-fabric scenarios |
| TC_CADMIN_1_25, corrected host | 304 | PASS, related multi-admin/window regression |

Test Harness v2.15.1+summer2026 and SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`. The two actual official script hashes
match CSA01. No official script, assertion, discriminator selection or PICS was
modified. Every run starts with a fresh isolated DUT state; the pinned execution
PICS hash is `ac5938f6f10a8df788347ca006935dfa466e1f5fc3a777a53f11b910cef71c5f`.
The test's existing recursive-rerun marker/optional log-step skips remain; this
is not a zero-skipped-step claim.

[All attempts and wire evidence hashes](csa07-results.json) preserve the nine
baseline results, four final results and separate non-CSA before/after wire
reproduction. The cumulative latest-status matrix remains **81 PASS, 24 FAIL,
21 BLOCKED, 32 MANUAL, 704 NA**. These cases already had a latest PASS before
CSA07; unselected rows were not rerun, and the two CSA06 test/specification
discrepancies remain unresolved.

## Regression coverage and validation

`test_node_discovery.c` executes the real host composition and core mDNS
lifecycle against a deferred backend with a one-second withdrawal. It covers
rapid and delayed reopen with the same discriminator, a fresh name per window,
name stability while open, an unaffected second Node, entropy failure and
drained teardown. The large Node fixtures and backend bindings use checked heap
allocations. CMake and the test map register this regression. The inventory now
contains 228 mapped files and 85 native definitions; default registered totals
are 83 on Linux and 86 on Windows, not counts of tests rerun in this step.

Six focused CTest cases pass normally and separately with ASan/UBSan/LSan:
`test_node_discovery`, `test_mdns`, `test_discovery`, `test_discovery_alloc`,
`test_runtime`, `test_runtime_alloc`. GCC 13.3.0, official mbedTLS 3.6.0 at
`2ca6c285a0dd3f33982dd57299012dacab1ff206`; successful build logs have no compiler
warnings. The initial private target list named a nonexistent test; it was
corrected before the successful complete builds and focused runs.

The full two-instance Linux controller scenario passes under Valgrind 3.22.0
Memcheck (A then B) and separately ASan/UBSan/LSan (B then A). Both include
browsing before startup, verified development attestation, CASE reads and
subscriptions, independent application callbacks and selective teardown/final
fabric responses. Memcheck reports **0 errors, 0 bytes in 0 blocks at exit**,
48,551 allocations and frees, with no suppressed errors. The separate sanitizer
scenario exits cleanly. These checks are not additional CSA PASS entries.

| Artifact | SHA-256 |
| --- | --- |
| Source manifest, all 353 C/H files matched | `59b8a59723a53ac8257226af6a944744c4ecfa645225a314794a060324cf5885` |
| Baseline matter-node | `3d9a196ed4623175e82881901af28985408a40d11c2727e8a01231dd7d12db36` |
| Final matter-node | `091cd7434c723e32a7dd044b9ce24788b9b8f2240a1cb37f2fe8a80813cd5e12` |
| Memcheck runtime-pair-host | `eb1b3e8c3a0e41da737d0080ccf72552a4e52dc2fe40dac2afe5d27eb1148768` |
| Sanitized runtime-pair-host | `0261a80a7df8d9c27c83c6e7414291ab5f25818edf93d27b3a82cd2e87e28b20` |

Representative executed commands, with private fixture paths replaced:

```sh
cmake -S . -B build/final -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls
cmake --build build/final -j 3 --target matter-node runtime-pair-host test_node_discovery test_mdns test_discovery test_discovery_alloc test_runtime test_runtime_alloc
ctest --test-dir build/final --output-on-failure -R '^(test_node_discovery|test_mdns|test_discovery|test_discovery_alloc|test_runtime|test_runtime_alloc)$'
# Repeat in build/sanitize with -DMATTER_SANITIZE=ON.
# Full pair with explicit executable, controller, PAA, credentials, interface, output:
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode memcheck
# python tools/matter/tests/test_discovery_startup_linux.py ... --mode sanitize --reverse
python tools/matter/check_test_map.py
git diff --check
```

The controlled wire reproduction uses one persistent chip-tool interactive
controller and a disposable already-commissioned node. First open an enhanced
window and wait for its positive mDNS announcement. Then run revoke and reopen
immediately, reusing the discriminator; observe both goodbyes and renewed PTR,
SRV and TXT records. Commands inside that same interactive controller:

```text
pairing open-commissioning-window 1 1 180 1000 777
administratorcommissioning revoke-commissioning 1 0 --timedInteractionTimeoutMs 1000
pairing open-commissioning-window 1 1 180 1000 777
```

Use a DUT port distinct from chip-tool's own listeners. The first lab setup
collided with a controller listener before commissioning; that setup failure is
not the reproduced discovery defect. Privileged capture was unavailable to the
lab account, so the reproduction used unprivileged multicast listeners. Raw
logs, captures, controller state, fixture paths and scripts remain private in
ignored build data/the lab. No Windows, hardware, Google Test Suite, full CSA
catalog or production attestation acceptance is implied.

**Next: CSA08 - General Diagnostics**, starting with TC_DGGEN_2_4/2_5. Continue
watching repeated commissioning in subsequent official runs; retain run 289's
unproven attribution rather than claiming that one timing defect explains every
discovery timeout. Timer consolidation, tariff work and optimization stay later
in the roadmap.
