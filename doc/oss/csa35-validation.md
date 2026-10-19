# CSA35: PH and Extended Discovery policy

CSA34 was committed as **`978de1f`**. Its confirmed missing-PH failure is fixed.
The original discovery cases pass with explicitly updated PICS:

| Original test | Execution | Result |
| --- | --- | --- |
| TC_SC_4_1 | Automatic TH run469 | PASS: 21 passed, 9 not applicable |
| TC_SC_4_3 | Automatic TH run470 | PASS: 15 passed |
| TC-DD-2.1 | Operator-reviewed manual TH run471 | PASS: 11 passed, 15 not applicable |

No official test/support source or assertion was modified. The manual case uses
retained real x86/controller/wire observations; TH records the operator review.
Its newly applicable PH and Extended Discovery steps are actually checked.
The original CSA34 FAIL remains in the [previous record](csa34-results.json).
See [identities, PICS delta and receipts](csa35-results.json).

## Implementation and application ownership

`matter_discovery_commissionable_with_hint` adds an application-supplied PH bitmap
to the owned record. It copies the value and makes no OS, scheduler or device-method
assumption. Existing function signatures remain available. The legacy builder
emits PH=0 in CM=0, claiming no method; a real application must supply truthful
hints through the explicit constructor. Hints requiring PI need a custom record
including that field. Allocation failure and uint32 decimal capacity are covered.

The credential-backed reference host supplies **PH=1** for a new/uncommissioned
node: restarting it opens its basic window. After commissioning it supplies
**PH=4**, the Administrator method, including while closed or in an enhanced
window. Neither hint requires PI under Core1.6.1 Table5. The generic library does
not invent application instructions or a manufacturer URL.

The host implements Core **4.3.1.2** customer control with:

| Option | Meaning |
| --- | --- |
| omitted | 900 seconds of CM=0 advertising |
| `--extended-discovery-seconds 0` | Disable CM=0 advertising |
| `--extended-discovery-seconds N` | N seconds, numeric range 0..4294967295 |
| `--extended-discovery-seconds unlimited` | Explicit unlimited CM=0 advertising |

The 900-second default replaces the previous implicit unlimited behavior. This
is reference-host policy, not a mandatory exact duration imposed on consumers.
Each entry into CM=0, including a restored commissioned boot, starts one Node
monotonic deadline. Queries do not refresh it. Expiry/disable drains and deletes
only the commissionable publisher; operational publishers, UDP and CASE stay
usable. An authenticated open-window command publishes a fresh instance even
when Extended Discovery is disabled. No background task, shared global timer or
new persistent format is introduced. Policy is supplied through process arguments;
there is no new desktop policy preference. GUI readiness can use an operational
publisher when commissionable advertising is intentionally absent.

Only the discovery capability delta changes in PICS: EXTENDED_DISCOVERY and
TXT_KEY_PH are enabled; unsupported Wi-Fi PAF, optional VP/DT/DN/RI/PI and vendor/
device-type subtypes are explicitly disabled. The before/after hashes and ten
new declarations are retained. No new top-level matrix case becomes applicable
from this delta. Other earlier PICS declarations remain for a separate review.

## Verification

Three complete policy scenarios (unlimited, disabled and eight-second limit)
run first under **Memcheck**, then separately under **ASan/UBSan/LSan**. All six
pass: **209 functional checks and 26 recorded PH assertions**. Repeated PH packet
observations are not separate CSA cases. The scenarios verify unsolicited
announcements, all selected-interface IPv6 addresses, PTR/SRV/TXT, discriminator
subtypes, mode-dependent _CM, actual unfiltered chip-tool discovery, attestation,
CommissioningComplete, live CASE after withdrawal, operational discovery and
enhanced-window reopening with a new instance.

Two additional restored-state boots with Extended Discovery disabled accept a
**fresh full CASE session**, pass nine checks and stop cleanly. Across the four
accepted Memcheck processes there are **83,076 allocations and 83,076 frees**,
zero errors and zero live bytes. All eight host stderr files are empty.

Five native CTests pass per Linux build: discovery, allocation failure, delayed/
rapid reopen and policy lifecycle, runtime and runtime allocation regressions.
The installed consumer passes. Five invalid/missing CLI values return status2.
Windows builds the node and desktop; its three affected discovery CTests pass.
Recorded Linux and Windows build logs contain no compiler warnings. No existing
paired Windows process was restarted or replaced.

The first short-timeout fixture incorrectly accepted the quiet probing interval
as completed expiry, then failed its pre-expiry observation. The fixture now
observes through the requested elapsed duration before accepting silence. Eight
seconds permit real probing under Memcheck; the host timer is not scaled or
shortened. All six final scenarios use one accepted driver hash. No runtime
change followed this fixture correction; the failed attempt is retained privately.

The default 900-second expiry was **not waited out in real time**. Its mechanism
has deterministic native deadline/lifecycle coverage and actual eight-second
wire coverage. This is not physical radio, Home UI, multiple physical interfaces,
embedded RAM-fit or certification acceptance. The full matrix was not rerun.
Native GUI readiness was compiled; no fresh manual GUI test is claimed.

TH is idle, disposable processes are stopped and the temporary public PAA is
removed. Raw packets, controller credentials, state and lab configuration remain
outside Git. CSA30 stays deferred; CSA32's separate text discrepancy remains open.

## Reproduction and accounting

```sh
cmake --build /path/to/normal --target matter-node test_discovery test_discovery_alloc test_node_discovery test_runtime test_runtime_alloc
ctest --test-dir /path/to/normal --output-on-failure -R '^(test_discovery|test_discovery_alloc|test_node_discovery|test_runtime|test_runtime_alloc)$'
python tools/matter/tests/test_commissionable_announcement_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --payload-exe /path/to/C-payload-utility --paa /path/to/development-paa \
  --credentials /path/to/development-credentials --interface 2 \
  --extended-discovery-seconds 8 --output /path/to/fresh-private-output --valgrind
# Repeat for 0 and unlimited, then separately with a sanitizer node without Valgrind.
python tools/matter/check_test_map.py
git diff --check
```

The TC-DD-2.1 row stays category MANUAL and changes its manual outcome FAIL to
PASS. Automatic discovery rechecks were already cumulative PASS rows. Totals
remain **97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA**; MANUAL now contains
**12 PASS, 1 FAIL and 27 without an outcome**. Unaffected evidence is inherited.

Next: **CSA36 — audit MCORE.DD.COMM_DISCOVERY and TC-SC-4.7 applicability** against
actual Commissioner Discovery/UDC support before selecting the next manual
execution. Commissionable and Commissioner discovery are distinct capabilities.
