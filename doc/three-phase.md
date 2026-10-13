# MP02: three-phase measurement profile

The x86 host has an opt-in `--three-phase` profile. The default profile and
legacy EPM/EEM constructors retain their measurement semantics. The application
owns the event loop and supplies coherent snapshots; the library does not
read hardware, start tasks or derive missing phase measurements.

## Topology and measurements

| Endpoint | Device type | Descriptor | Measurements |
| --- | --- | --- | --- |
| 0 | Root Node, existing utility roles | PartsList includes every non-root endpoint | Existing commissioning/runtime clusters |
| 1 | Electrical Sensor 0x0510 rev1 | Tag AC; children 3, 4, 5 | EPM: active/reactive/apparent power, power factor. EEM: cumulative import/export registers |
| 3 | Electrical Sensor 0x0510 rev1 | Tag ACPhase1 | EPM: voltage, active/reactive power, RMS current |
| 4 | Electrical Sensor 0x0510 rev1 | Tag ACPhase2 | Same independent phase measurements |
| 5 | Electrical Sensor 0x0510 rev1 | Tag ACPhase3 | Same independent phase measurements |
| 2, optional | Existing On/Off UI demo | Enabled only with `--test-switch` | Existing experimental switch |

Standard tags have MfgCode=null and namespace 0x0a: tags 1/2/3/4 respectively.
Each measurement endpoint has Power Topology TREE (FeatureMap=2). Aggregate
EPM has ALTC|POLY (6), phases ALTC (2). Each configured scalar has an Accuracy
entry; EPM revision is 3. EEM revision 2 has IMPE|EXPE|CUME (7).
There is **no EEM on phases**, no energy divided by three and no inferred phase
energy. With `--meter-services`, EP1 additionally declares the identity-only
Electrical Utility Meter and its Meter Reference Point base; see the precise
[composition and conditional requirements](meter-services.md). Electrical Meter
and tariff device types remain absent. UI presentation by Google/Apple is not
guaranteed by this data model.

The deterministic host source includes simultaneous import on L1 and export on
L2, negative reactive power/current, and unavailable L3 during seconds 15..19 of
each 20-second cycle. Values are synthetic, not a meter accuracy claim. Units:
mW/mVAR/mVA, mV, mA, PF times 10000; EEM uses mWh. The first source sample contains
12345678000 mWh import (12345.678 kWh) and 123450000 mWh export (123.45 kWh).
Later readings increase independently. Source samples are already scaled;
there is no implicit conversion or division in the cluster.

## Library interfaces

- `matter_root_add_tagged_endpoint` copies up to six standard tags and advertises
  Descriptor TAGLIST/AttributeList accordingly. `matter_root_set_parent` rejects
  missing endpoints, cycles and self-parenting. Root lists all parts; other
  parents list direct children. `matter_root_add_device_type_at` adds an
  implemented type without losing the original type or ACL type matching.
- `matter_epm_new_multi` copies the scalar configuration. The snapshot's values
  and availability bits follow that configuration's order. One invalid scalar
  becomes null without invalidating the others; callback errors, stale data or
  a future timestamp invalidate the snapshot. Scalar changes update DataVersion.
- `matter_eem_new_registers` publishes the source register immediately, including
  a nonzero first reading. The original `matter_eem_new` still starts cumulative
  energy from its initial baseline. The two modes cannot silently reuse an
  initialized checkpoint. Decreases require an explicitly increased source
  generation, representing a confirmed reset/replacement, not a reconnect.
- Register snapshots can mark import/export unavailable independently. A missing
  direction is null, not zero. Durable storage precedes publication. Complete
  pairs produce CumulativeEnergyMeasured with the same values/timestamps as the
  attributes. Partial pairs currently update attributes without emitting an
  incomplete event; formal acceptance of partial-source event behavior remains
  outside the complete-pair simulator's CSA result.
- CumulativeEnergyReset exposes unknown system reset times as null. Host boot
  time is not substituted for the external meter's last zero. Known external
  reset timestamps are not yet supplied by this API.

Storage schema 7 adds explicit EEM mode and known-direction bits. Schemas 1..6
are read and upgraded, preserving the legacy mode. An old binary cannot read a
schema-7 state. Use a separate file when changing profiles; keep the original
state. Appended DTO fields require rebuilding consumers with matching headers;
initialize sample/checkpoint structs to zero. DTO layout is not the disk format.

All cluster state and report tables are heap owned per instance. On Linux x86_64
Debug, EPM context is 5496 bytes per cluster, also for the legacy constructor.
The Read/Subscribe result limit is 320: the full profile with the optional switch
exceeded 256. This adds 7168 bytes per Read handler and 4608 per Subscribe handler
on this ABI. These are structure sizes/deltas, not total node RAM requirements.

## Run and reproduce

Use disposable development credentials and a new state path:

```sh
mkdir -p build/three-phase
build/cmake/matter-node --interface <IPv6-interface-index> --port 5547 \
  --discriminator 3847 --seconds 120 --credentials <development-credentials-dir> \
  --state build/three-phase/state.bin --three-phase
python tools/matter/tests/chip_tool_three_phase.py --chip-tool <chip-tool> \
  --paa <trusted-development-PAA-dir> --output build/three-phase/check \
  --discriminator 3847
```

After a graceful restart with the same state, use a new output directory and
`--restart-storage build/three-phase/check/controller/storage`. Do not overlap
the two processes. Controller output and credentials remain in ignored build/.

For two nodes in one process/thread, run `runtime-pair-host` with its existing
interface/credentials/two-state arguments and append `--three-phase`. The oracle
accepts `--discriminator 3846 --pair-discriminator 1234`. It checks independent
subscriptions and state, then removes each fabric and checks teardown.
The pair fixture assigns distinct DNS host identifiers to its virtual devices
while retaining the same real interface/address. The oracle checks the selected
ports as well as commissioning success.

Create endpoint-specific PICS without modifying an existing TH project:

```sh
th-cli project export --id <baseline-project> --output-file build/th-base.json
python tools/matter/th/three_phase_project.py --base build/th-base.json \
  --output build/th-ep1.json --endpoint 1 --discriminator 3901
th-cli project import --file build/th-ep1.json
```

Repeat for endpoints 0, 3, 4, 5 with matching DUT discriminators. This is a lab
capability declaration, not a certification PICS for a finished product.
See [MP02 validation](oss/mp02-validation.md) for executed checks and limitations.
