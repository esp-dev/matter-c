# CSA24a: configurable subscription capacity

Scope: provision subscription resources from the immutable advertised per-node
budget, retain bounded ownership and repeat automatic Python TC_SU_2_5 without
changing the official test or its assertions. The preceding state is committed
as `3125c5f`; CSA24's three-subscription run449 remains historical FAIL evidence.

## Implementation

`Matter_Root_Config_T.capabilities.subscriptions` is the single source of truth.
The additive `matter_root_capabilities()` API copies the immutable declaration
used by Basic Information. Dispatcher construction reads it, validates both
Core's 3..10000 range and the compiled shared transport budget, and allocates
the derived transaction table with checked `calloc`. Runtime construction also
rejects an unsupported budget before platform initialization. There is no new
parallel limit field, global quota or persistent setting schema.

The former inline 52-entry transaction array is replaced by an owned table
whose length follows the instance configuration. Its addresses remain stable
through callbacks, asynchronous UDP/MRP operations and teardown. This is one
bounded reservation at construction, not per-message reallocation or unlimited
growth. Subscribe handlers retain their existing allocation on demand. On table
OOM the already allocated dispatcher context is freed; successful stop/drain
precedes table deletion. Every traversal, including ACK completion, retirement,
outbound OTA, diagnostics and stop/delete, uses the configured table length.

Per-fabric admission and subscription reservation use the selected count.
Closing handlers still consume their execution slots until drain. The additional
replacement slot permits KeepSubscriptions=false at full capacity, scoped to
the authenticated fabric/node; other fabrics retain their own guarantee.
Non-subscription partitions and response-drain capacity are preserved.

For five fabrics plus optional PASE, table length is `6 * budget + 34`: budget
3 requires 52 slots; budget 8 requires 82. A 128-slot transport build permits
budgets through 15 (124 slots), not the entire Core range. The default 56-slot
build and default application budget remain unchanged. Larger unsupported
configurations fail rather than falsely advertising a guarantee.

The host adds `--subscriptions-per-fabric N`. This acceptance explicitly selects
8 and uses `-DMATTER_TRANSPORT_CAPACITY=128`. The lower exchange/RX/ACK/MRP tables
remain controlled by the shared build-time transport ceiling; this step does
not claim to remove all statically sized core tables. Changing a live node's
budget requires stop/drain and reconstruction, retaining its state path.

On the Linux x86-64 build the dispatcher object is 8520 bytes, a transaction is
1568 bytes and a connection is 144 bytes. Thus the separately allocated table
is 81536 bytes for budget 3 or 128576 bytes for budget 8, excluding allocator,
transport, IM handlers and the rest of the application. These are structure
sizes, not total RAM or peak process residency.

## Verification

The existing dispatcher test now checks budgets 3/4/8 where supported, guards
for invalid/transport-exceeding counts, a full fabric's refusal without changing
existing reservations, admission on another fabric, scoped replacement and
failure of the second constructor allocation. Previous routing, retirement,
ACK/MRP and cleanup cases remain. Pointer-sized memset operations were changed
to clear the allocated length. Root and runtime tests retain their allocation
variants. Thirteen focused native CTests pass in the 128-slot normal build and
separately under ASan/UBSan/LSan. The default 56-slot compatibility build passes
the dispatcher and runtime tests, including refusal of larger unsupported budgets.

The independent CHIP OTA runner accepts the explicit budget and decodes
CapabilityMinima.SubscriptionsPerFabric before update. It keeps real query/apply
delays, signature/token/version checks, simulated restart, fresh CASE and Notify.
The full scenario passes 22 checks under Memcheck and separately ASan/UBSan/LSan,
with two clean boots each. Memcheck reports 55267 matched allocations/frees,
zero errors and zero live bytes; both sanitizer stderr files are empty. Actual
Await/60 retry intervals are 120199 ms and 120175 ms respectively. These native
and laboratory results do not substitute for automatic CSA PASS.

## Official run450: fourth subscription accepted, remaining FAIL

The unchanged Python TC_SU_2_5 (SHA-256
`91b241ce0be6291c45cf74d731c7d130a986b1ae6e26d1d9c8814cca11321fdb`)
passes both Await/provider-loss scenarios and establishes the fourth live
subscription. It no longer fails with RESOURCE_EXHAUSTED at line 382.
The full case still **FAILS** in step 5 at line 433: the provider reports action
0/request count 0, while the test expects Discontinue/action 2 after downloading.

The wire report sequence explains why it checks too early. Progress reports are
null through 03:27:00.797 UTC, then 0 at 03:27:01.026 and 1 at 03:27:01.290.
At 03:27:01.448 the test declares download complete; it has received no later
null. At 03:27:01.552 it reads provider status before any ApplyUpdateRequest.
The failed assertion triggers provider termination while download is ongoing.
Thus the later download failure is not evidence that downloading had completed.

The installed helper `await_all_expected_report_matches()` re-evaluates the
entire report history every 100 ms (lines 470..489). The case's predicate keeps
`progress_seen` across evaluations. After seeing 1 it accepts an earlier null
on the next scan, reversing the intended temporal meaning. A minimal reproduction
extracts the original method and original predicate by Python AST, supplies only
`[null, 0, 1]`, and observes false completion in about 0.11 s. Neither installed
source is edited. The helper hash remains
`038e99c144a66640375d483ae9e5a8fc5fbf6421d3b44129f6b1a5f7551be322`.
This is reproduced harness behavior, **not a CSA-confirmed test correction**.
No suppression of legitimate null values, false progress, weakened assertion or
automatic PASS override is introduced in the stack or fixture.

Five harness steps pass (including setup/log handling), one fails. Cumulative
counts remain **97 PASS, 15 FAIL, 9 BLOCKED, 37 MANUAL, 704 NA**. The separate
manual YAML acceptance from CSA23 is retained. Other rows are inherited, not
rerun for the new eight-subscription configuration; resource-dependent cases
need campaign revalidation for that profile. The fixture node was stopped after
TH returned idle. See the [result and evidence hashes](csa24a-results.json).

## Reproduction

```sh
cmake -S . -B build/normal -DCMAKE_BUILD_TYPE=Debug -DMATTER_MBEDTLS_DIR=/path/to/mbedtls -DMATTER_TRANSPORT_CAPACITY=128
cmake --build build/normal -j 3 --target matter-node test_dispatch test_root test_root_alloc test_bdx test_bdx_alloc test_ota_query test_ota_query_alloc test_ota_apply test_ota_apply_alloc test_ota_update test_ota_update_alloc test_runtime test_runtime_alloc
ctest --test-dir build/normal --output-on-failure -R '^test_(dispatch|root(_alloc)?|bdx(_alloc)?|ota_(query|apply|update)(_alloc)?|runtime(_alloc)?)$'

python tools/matter/tests/test_ota_chip_provider.py \
  --exe build/normal/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa --credentials /path/to/credentials \
  --interface 2 --subscriptions-per-fabric 8 --mode apply-await-60 \
  --valgrind --output build/csa24a-memcheck
```

Use a separate `-DMATTER_SANITIZE=ON` build for the same CTests and full scenario,
without `--valgrind` and with a fresh output directory. The unchanged automatic
TH case runs against a separate node/state on the TH Linux host. Its wrapper
only maps the actual downloaded file into the official file check and executes
the original CHIP provider. Existing laboratory attestation keys stay on that
host; no private keys or user-paired state are exported. The readiness launcher
answers commissioning prompts only. Provider IPC, assertions, PICS and the
source image from CSA24 are unchanged.

No physical firmware/bootloader, Windows execution of this snapshot, ecosystem
UI acceptance or certification is claimed. User-paired Windows nodes are unchanged.

Next: **CSA24b — prepare a CSA report for the replayed progress predicate and
agree a correction/accepted test version before repeating automatic acceptance**.
Do not change the device's legitimate progress semantics to work around it.
