# CSA27: OTA Requestor attributes

CSA26 was committed as **`5e8fe96`**. CSA27 executes the installed, unchanged
**TC_SU_4_1**, then independently checks two-fabric OTA attributes and restart.
No C/H implementation, public API, protocol response, timer or PICS changed.
See the [machine record](csa27-results.json) for source and evidence hashes.

## Official result

**TC_SU_4_1 FAIL, TH run456, step5.** Steps0 through4 pass, including the
second fabric's commissioning and independent default-provider readback.
The TH records seven passed entries including its start/log wrappers, one failed
entry and three pending entries. Steps6 through8 were not executed in this run.

Step5 writes two providers on fabric1. The actual SDK response is:

```text
clear list       -> Success
append provider4 -> Success
append provider1 -> ConstraintError (0x87)
```

The installed test checks `resp[0].Status == Status.ConstraintError` at line310.
It therefore fails on the successful clear operation even though the final
operation reports the expected constraint violation. The first-fabric provider4
readback and subsequent assertions are not reached by the official test.
Independent acceptance below checks those actual values explicitly.

The Python source SHA-256 remains
`644dde23f969393db842b84190978144a9279b02fa17e3d1e5ba4e0514811061`;
its shared helper remains
`9e9b2af9fcca6b039da12273b89560bd55121ec11fdb72de0f4973499318615b`.
PICS is unchanged. No official script, test selection predicate or assertion was
patched; no local-corrected official run is claimed. This status-vector mismatch
is a candidate for CSA/test-maintainer review, not a CSA-approved correction.

Only TC_SU_4_1 changes from BLOCKED to FAIL. The cumulative matrix becomes
**97 PASS, 17 FAIL, 5 BLOCKED, 39 MANUAL, 704 NA** (862 rows). All other rows
are inherited; local acceptance does not change their classification.

## Normative analysis

Matter Core R1.6.1 **11.20.7.5**, DefaultOTAProviders, permits at most one provider
per fabric and requires ConstraintError for an update that introduces another.
Core **10.6.4.3.1** describes list writes as a clear/replace followed by ordered
item additions and warns that a failed list write can leave partial changes.
The all-items-in-one-array alternative is reserved for the specified Access
Control attributes; it is not the required encoding for this OTA attribute.

Core **8.7.3.3** processes data fields in order and produces status information
for successful changes and constraint violations. **8.7.3.4** includes each
generated AttributeStatusIB in WriteResponses. Returning only the last error,
reordering it ahead of the successful clear, or changing earlier successes into
errors would discard or misrepresent executed operations. No such workaround
was introduced into the shared IM Write implementation.

The existing cluster stores one provider per fabric, ignores a supplied wire
FabricIndex in favor of the authenticated accessing fabric, rejects a second
append, and preserves other fabrics. AnnounceOTAProvider does not overwrite
stored defaults. The new independent scenario checks these on the wire, rather
than assuming them from a successful Write return code.

## Executed local acceptance

The new [chip-tool scenario](../../tools/matter/tests/test_ota_attributes_chip.py)
uses fresh disposable controller and node storage. Two independent development
roots commission the same node. Every command is a separate, unmodified
chip-tool process, exercising discovery and operational session setup.

- Empty defaults on each newly commissioned fabric; writes bind to the
  authenticated fabric despite a different supplied FabricIndex.
- Independent providers1/3 and fabric indices; the second fabric cannot change
  the first fabric's value.
- Two-provider replacement produces the complete **[0, 0, 135]** status vector,
  leaves provider4 on fabric1, and preserves provider3 on fabric2.
- Clearing fabric2 gives Success and an empty readback; fabric1 retains provider4.
- UpdatePossible is true, UpdateState is a defined enum value, and progress is
  null when no download exists.
- A valid announcement succeeds without replacing the configured default.
- After a clean stop/restart, fresh CASE reads on both fabrics retain provider4
  and the cleared second list respectively.

The full scenario passes **29 checks under Memcheck**, then separately **27
checks with ASan/UBSan/LSan**. Each run boots the host twice. Memcheck totals
**190974 matched allocations/frees, zero errors and zero live bytes**; there are
no suppressions. All four host stderr files are empty. These memory results
apply to the C host, not the independent CHIP controller processes.

Two parser guards (attribute kind and declared list count) were tightened after
the full runs. The final parser was replayed against **34 actual captures** from
both runs, without repeating the network scenarios. Eight negative controls are
rejected: wrong provider, fabric or endpoint, missing field, wrong count,
missing target report, missing constraint error and misplaced constraint error.
This is local acceptance, not the remaining official assertions or certification.

Both binaries are reused from CSA26 after verifying that all **360 compiled
C/H source hashes** match the current repository. No rebuild or new CTest
campaign was necessary for this test-only addition. Earlier CSA26 CTest/build
results remain historical, not rerun claims.

## Reproduction and files

Run the original TC_SU_4_1 from the installed SDK Python Tests collection with
endpoint0, the unchanged current PICS and a fresh on-network node. A separate
provider executable/image is not used by this attribute-only test. The isolated
project retains the previous fixture parameters, which do not alter the case.

For independent acceptance, use the same development attestation credentials
and an existing public verification key for the simulated OTA sink:

```sh
python tools/matter/tests/test_ota_attributes_chip.py \
  --exe /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/paa --credentials /path/to/credentials \
  --ota-key /path/to/public.sec1 --interface 2 \
  --output /path/to/fresh-memcheck-directory --valgrind
# Repeat with the sanitizer binary and another fresh directory, without --valgrind.
python -m py_compile tools/matter/tests/test_ota_attributes_chip.py
python tools/matter/check_test_map.py
git diff --check
```

The optional runner owns its node processes and uses its own controller stores;
logs, credentials and persistent state stay outside Git. Its node uses port5581
and discriminator3913 by default, and opens an enhanced window with
discriminator3914 for the second fabric. Run this fixture serially.

Changed files are limited to the new optional Python scenario, its inventory
entries, this report/result JSON, README, status and roadmap. The inventory now
contains **236 mapped files**, while **87 native definitions, 59 core sources
and 75 public headers** remain unchanged.

## Limits and next task

The TH and shared helper sources remain unchanged, TH is idle and test ports
are released. The separate SDK checkout remains clean. User-paired Windows
nodes were not restarted or modified. No physical firmware, Windows rebuild,
ecosystem UI acceptance, OTA installation or 128 kB RAM fit was tested here.
On-demand allocation remains a later stage.

**Next: CSA28 — original automatic TC_SU_2_2**, QueryImageResponse scenarios.
CSA20 covers its manual counterpart; the automatic row remains BLOCKED in the
matrix. Preserve the TC_SU_4_1 response-vector evidence for CSA review.
