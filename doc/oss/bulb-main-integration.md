# Bulb and CSA75 main integration, 2026-10-25

The existing main working copy contained CSA74/75 work on top of `56f9053`.
It was preserved as `6ab4e1a`, then `work/bulb-integration` at `21859f9` was
merged into main as `ad7a272`. This includes Memory40-43, native ESP OTA,
shared lighting/groups/scenes and the subsequent Wi-Fi/MRP/regulatory repairs.
The bulb submodule follows the combined main history, rather than losing the
later CSA work when selecting the lighting branch.

All 27 CSA74/75 files are retained. The ordered sequence of all 3034 added and
removed lines in `56f9053..6ab4e1a` is identical to `21859f9..ad7a272`.
Originally untracked reports and `matter_compat.h` were included in the snapshot.
The single textual conflict was in runtime authorization: preserve both the
bounded accepted-Revoke reply exception and the group-cleanup admission gate.
No unrelated reformatting or protocol repair was introduced for this merge.

CSA compatibility exceptions remain OFF by default. The normative initial
60-second PASE fail-safe repair applies to both profiles. Existing CSA75
historical outcomes are unchanged; see [the profile contract](csa75-compatibility.md).

## Executed regression

The tested source is `ad7a272d194c7c358e06bf1b0ecdab5a0632a775`.
The [numeric receipt](bulb-main-integration.json) records its archive digest,
individual checks, build hashes and limitations. Later report-only commits do
not change the tested executable source.

| Profile | CTest normal | Separate ASan/UBSan/LSan | Full two-runtime lifecycle |
| --- | --- | --- | --- |
| Strict | 119/119 | 119/119 | Memcheck and separately sanitizers pass |
| CSA75 umbrella ON | 119/119 | 119/119 | Memcheck and separately sanitizers pass |

Each CTest set includes 117 native definitions, inventory and installed-consumer
checks. Eighteen focused fixtures per profile pass Memcheck, covering runtime,
allocation failures, OTA notification, lighting/groups/scenes/groupcast,
reception, Wi-Fi retry, dispatcher, Root/fail-safe, Fabric encoding, ACL and
storage. Completed Memcheck fixtures report zero errors and zero live blocks.
The existing two-runtime meter scenario uses stock chip-tool and requires both
instances to stop, drain and delete; it is not a physical two-bulb test.

The full-load `after` wire case also passes in four separate runs:

| Profile | Memcheck | Separate ASan/UBSan/LSan |
| --- | --- | --- |
| Strict | PASS, 384.17s | PASS, 291.44s |
| CSA75 umbrella ON | PASS, 388.10s | PASS, 298.39s |

Each run exercises five fabrics, fifteen protected CASE sessions and fifteen
subscriptions, concurrent Reads, RX reordering, three one-shot OOM positions,
one missing-ACK negative control with session survival and load recovery,
explicit close/reconnect, ACK before and after local TX completion, and stop
while an accepted TX completion is held. All finish with zero tracked core
allocations/bytes; Memcheck additionally reports zero errors and zero heap blocks
at exit. These counters describe the host fixture, not total C6/SDK heap.
Only this faulted `after` case was repeated for the merge; the historical six-case
wire matrix is not claimed as a new result. Expected fault subscription
timeouts and the interrupted stop-time Read are not healthy-operation failures.

One extra direct storage invocation initially omitted its required arguments
and aborted before any allocation. The corrected save invocation passes in
both profiles. The original four-phase seed/load committed/pending storage
runner passes in all four CTest configurations. The failed laboratory receipt
is retained rather than counted as a passing test.

The bulb application's host CTest is 2/2 and its bridge parser is 2/2. Both
ESP-IDF6.1 C6 develop/release version7 builds complete without compiler warnings,
using the pinned submodule and strict defaults. Signed application sizes are
1314816 and 1249280 bytes respectively. These images were not flashed.

## Boundaries and next task

No original TH/CSA campaign, physical C6 acceptance, Apple/Google Home test or
new heap/fragmentation/stack measurement was performed for this merge.
COM23/COM24, AP configuration and device identities were not modified.
Historical release6 firmware artifacts remain byte-identical; their physical
results do not become results for the merged source. No push was performed.

Next: physical C6 acceptance of the merged image, including startup without
DHCPv4, lease expiry and DHCP recovery while controlling and subscribing over
IPv6. This also remains distinct from a certification result.

Representative commands (isolated build/state directories for each profile):

```sh
cmake -S . -B <normal> -G Ninja -DCMAKE_BUILD_TYPE=Debug -DMATTER_CSA_COMPAT=OFF
cmake --build <normal> -j 4
ctest --test-dir <normal> -j 2 -E '^runtime_wire_' --output-on-failure
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=99 <fixture>
cmake -S . -B <sanitized> -G Ninja -DMATTER_SANITIZE=ON -DMATTER_CSA_COMPAT=OFF -DCMAKE_C_FLAGS=-fno-pie -DCMAKE_EXE_LINKER_FLAGS=-no-pie
ctest --test-dir <sanitized> -j 2 -E '^runtime_wire_' --output-on-failure
```

The second configuration pair selects `MATTER_CSA_COMPAT=ON`. Sanitizer runs
enable leak detection and halt on ASan/UBSan errors. Memcheck and sanitizers
are never combined in one process. Operator-supplied pinned dependencies and
disposable development identities remain outside public reports.
