# CSA03: Descriptor and endpoint composition

This pass starts from commit `f8e9e19` (CSA01 matrix and CSA02 lifecycle fixes).
It corrects declared device types against the locally supplied Matter Device
Library R1.6.1 (CSA document 23-27351, September 16, 2026). It does not add tariff
processing, alter measurement values, or claim certification.

## Failure and correction

CSA01 run 126, TC_IDM_10_5, reported three extra server clusters: Identify and
Meter Identification on EP1, and OTA Software Update Requestor on EP0.
Descriptor declared only Electrical Sensor on EP1 and only Root Node on EP0.
The clusters worked individually but their device-type composition was incomplete.

- `main/apps/matter/runtime/matter_runtime.c`: every started runtime already
  exposes the OTA Requestor server and OTA Provider client. It now also declares
  OTA Requestor `0x0012` rev1, as Device Library 2.3 requires. This declaration
  was incorrectly conditional on a configured image sink and update journal.
  UpdatePossible, protocol selection and application/install gates are unchanged;
  an unavailable OTA backend is not made available by this metadata correction.
- `tools/matter/host/matter_node.c`: opt-in `--meter-services` now declares
  Electrical Utility Meter `0x0511` and its Meter Reference Point base `0x0512`,
  both rev1, alongside Electrical Sensor. Their mandatory Identify, Meter
  Identification and Root Time Synchronization servers already exist. The host
  advances ConfigurationVersion by ten for the changed Descriptor metadata.
- `tools/matter/tests/test_runtime.c`: both independent runtimes must declare
  OTA Requestor even without application OTA sinks.
- `tools/matter/tests/chip_tool_three_phase.py`: the controller acceptance checks
  the complete device-type sets and ClientList on every endpoint, including
  absence of aggregate-only roles on phases. Existing power, energy, event,
  source-register and independent-instance checks remain enabled.
- Runtime, meter-services and three-phase documentation describe the corrected
  composition and its limits. Historical CSA01/CSA02 evidence is preserved.

No public API signatures, storage format, capacities, default measurement values,
cluster IDs, credentials or certificate checks change.

## Normative scope of the meter composition

Device Library 14.9 defines Electrical Utility Meter with Meter Identification
and makes it a superset of Meter Reference Point. Section 14.6 adds Identify;
both require TimeSyncCond on Root. Base requirements include Descriptor. EP1
has no client application cluster, so Base Simple-and-Client Binding does not
apply. Electrical Sensor still supplies the measurement/Power Topology role.

The optional `ElectricalEnergy` condition in 14.6.3.1 describes a reference point
representing an electrical tariff. This profile provides identity and measurements,
not a tariff, so that condition is not selected. The conditional Electrical Meter
or Electrical Energy Tariff child requirement in 14.6.6 is therefore inapplicable.
This is an identity-only Utility Meter composition. It must not be presented as
billing, tariff, Commodity Metering or price support. Existing source T1/T2
registers remain manufacturer-specific raw registers, not tariff schedules.

| Endpoint | DeviceTypeList | Relevant composition |
| --- | --- | --- |
| 0 | Root Node `0x0016` rev5; OTA Requestor `0x0012` rev1 | Existing root servers, Time Synchronization; OTA Provider client `0x0029` |
| 1 | Electrical Sensor `0x0510`, Electrical Utility Meter `0x0511`, Meter Reference Point `0x0512`, all rev1 | Descriptor, EPM, EEM, Power Topology, Identify, Meter Identification, optional source registers |
| 3, 4, 5 | Electrical Sensor `0x0510` rev1 | Descriptor, EPM, Power Topology; independent phase tags |

The official profile still has endpoints 0/1/3/4/5. Root PartsList contains all
four descendants, EP1 contains phases 3/4/5, and phase PartsLists are empty.
The optional experimental On/Off endpoint is only in the independent pair fixture,
not this official profile. It is not claimed to satisfy its device-type requirements.

## Official acceptance

The 13 final official runs report **12 PASS and 1 FAIL**:

| Official case | Endpoint selection | Run ID(s) | Result |
| --- | --- | --- | --- |
| TC_IDM_10_5, device-type cluster composition | Whole node | 258 | PASS (previously FAIL) |
| TC_IDM_10_2, element conformance | Whole node | 259 | PASS |
| TC_IDM_10_3, revisions | Whole node | 260 | PASS |
| TC_IDM_10_6, application device-type supersets | Whole node | 261 | PASS |
| TC_DESC_2_1 / TC_DESC_2_2 / TC_DESC_2_3 | Whole node | 262 / 263 / 264 | PASS |
| TC_IDM_10_1, global elements and identifiers | Whole node | 265 | FAIL: test vendor prefix |
| TC_IDM_10_4, endpoint-local PICS | 0 / 1 / 3 / 4 / 5 | 266 / 267 / 268 / 269 / 270 | PASS |

[Result delta](csa03-results.json) records run IDs, source/evidence/PICS hashes
and step states. Every execution PICS hash matches the final CSA01 PICS for its
endpoint. The cumulative matrix becomes **78 PASS, 27 FAIL, 21 BLOCKED, 32 MANUAL
and 704 NA**; only these 13 entries were rechecked. The baseline and previous
CSA02 delta are hash-linked rather than overwritten.

The installed TH/SDK and endpoint-local PICS are unchanged from CSA01/CSA02:
TH v2.15.1+summer2026, SDK `e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`.
Conformance bypass flags and PICS_SDK_CI_ONLY remain false. Official test sources
and assertions are unmodified. Whole-node composition tests examine the entire
Descriptor tree; IDM 10.4 is additionally selected for each of the five endpoints.

### Remaining production-identity boundary

TC_IDM_10_1 checks MEI vendor prefixes with certification rules. The source cluster
uses a test VID, `0xFFF1`, and a valid manufacturer-specific suffix. The test masks
the suffix in its error display (`0xfff10000`); that display does not mean the
actual cluster suffix is zero. Core 7.21.2.1 permits test prefixes for development,
while this official non-CI check rejects them for products. Keep the result FAIL;
do not borrow an unrelated production VID or enable PICS_SDK_CI_ONLY to hide it.
A downstream product needs its allocated VID and corresponding identity/credentials.

## Native and memory-safety acceptance

GCC 13.3.0, official mbedTLS 3.6.0 at
`2ca6c285a0dd3f33982dd57299012dacab1ff206`. Separate fresh normal and sanitized
CMake builds use `-Wall -Wextra -Werror`; neither reports compiler warnings.
The lab's 350 tracked C/H files match the current source manifest.

| Artifact | SHA-256 |
| --- | --- |
| Source manifest | `c9b005e2f71ec74d4bbd7cfb7f8f953af28bc43b40e8537dd155561aae52298d` |
| Official-test matter-node | `071e4229f416b73084529d31888a84643438a2b3888f93e99765997a86fc1ce8` |
| Memcheck runtime-pair-host | `01be07fa3e426edcbe1769e5906ffeae1d43f406e8848678ffad1cb8d8fb202e` |
| Sanitized runtime-pair-host | `a92813cdca4633e94879b90fbb2dbc8a1735f9dead89d30ce9d3f83e79374b3e` |

- `ctest --test-dir build/final --output-on-failure -R
  '^(test_runtime|test_runtime_alloc|test_root|test_meter_services)$'`: **4/4 PASS**.
  The same selection in `build/sanitize`: **4/4 PASS**, ASan/UBSan/LSan.
  Runtime allocation failure injection remains enabled in its dedicated test.
- `test_discovery_startup_linux.py --mode memcheck`: **PASS**, A then B;
  Valgrind 3.22.0, full leaks/origins, **0 errors, 0 bytes in 0 blocks at exit**,
  48,557 allocations and frees, no suppressed errors.
- The same full pair scenario with `--mode sanitize --reverse`: **PASS**, B then
  A. ASan/UBSan/LSan halt on errors and leak checking is enabled; no diagnostics.
  Both runs commission two complete instances, validate Descriptor over CASE,
  preserve the other instance's measurements/subscriptions/clock/Identify through
  deletion, receive both final-fabric responses and exit after deleting both.
- `python tools/matter/check_test_map.py`: PASS (226 mapped files, 84 native
  definitions, 59 core sources, 75 headers); `git diff --check`: PASS.

The historical intermittent MP04a final-fabric timeout did not reproduce in
these runs; this metadata change is not claimed to fix its unknown cause.
Private raw evidence stays under ignored `build/csa03/` and the isolated lab.
No Windows, physical device, Google Test Suite, production OTA or full catalog
recheck is implied. Unselected matrix rows retain earlier results.

**Next: CSA04 — subscription report timing**, starting with TC_IDM_4_3 and
TC_CADMIN_1_25, without relaxing their interval or notification assertions.
