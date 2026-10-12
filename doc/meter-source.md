# MP03: manufacturer-specific meter source extension

This is an application schema, **not a CSA standard cluster**. It preserves
source distinctions that cannot be expressed losslessly by the current standard
EPM/EEM profile. The portable `clusters/matter_meter_source.h` constructor returns
the common `Matter_Cluster_T`; the application supplies callbacks and immutable
channel descriptors. No product headers, operating system, meter parser or
hardware calls are part of the cluster.

## Namespace and discovery

Cluster ID is `(vendor << 16) | cluster_suffix`. The constructor accepts vendor
1..0xFFF4 and suffix 0xFC00..0xFFFE, following Core 1.6.1 §7.21.2.1–2. A numerical
range check does not assign a vendor ID. Use the vendor's assigned namespace for
a product. The example uses test VID 0xFFF1 and suffix 0xFC01: **0xFFF1FC01**.
Attributes have scoped IDs 0..5, with no invented standard IDs. All structures
below are defined by this extension; none instantiates a foreign cluster's
private/extended structure (Core §7.21.3).

Attach on EP1 with `matter_root_attach_cluster_at`. Descriptor ServerList then
advertises it. Revision=1, FeatureMap=0, empty accepted/generated command lists,
AttributeList={0..5, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD}. All attributes are
read-only and require View through normal IM authorization/ACL. No commands,
events or writes. This does not change the Electrical Sensor device type or
claim the incomplete Utility Meter roles.

## Revision 1 wire schema

| Attribute | Type | Meaning |
| --- | --- | --- |
| 0 MeterMetadata | list of MetadataEntry | Ten application-defined text fields, each nullable |
| 1 SourceState | structure | Quality, raw source status, timing, tariff register, scale and link flags |
| 2 RegisterReadings | list of Reading | Active/reactive energy registers and their distinct axes |
| 3 DirectionalPowerReadings | list of Reading | Source powers, current, voltage, power factor |
| 4 DemandRegisters | list of Reading | Independent maxima; not a sum of tariff maxima |
| 5 VolumeChannels | list of VolumeReading | Separate source channels, never electrical energy |

Context tags in each `Reading`:

| Tag | Name/type | Meaning |
| --- | --- | --- |
| 0 | Key, uint16 | Stable unique key **within its attribute**, configured by application |
| 1 | Quantity, uint8 | Application quantity code; example mapping below |
| 2 | Phase, uint8 | 0 aggregate/unspecified, 1/2/3 phases |
| 3 | Tariff, uint8 | 0 total/unallocated, otherwise source tariff register |
| 4 | Direction, uint8 | 0 unspecified, 1 positive/import, 2 negative/export |
| 5 | Quadrant, uint8 | 0 unspecified, 1 inductive, 2 capacitive; combine with direction |
| 6 | Unit, uint8 | 0 unknown source unit; 1 Wh, 2 varh, 3 W, 4 var, 5 VA, 6 V, 7 A, 8 ratio, 9 m³, 10 litre |
| 7 | DecimalExponent, int8 | Value × 10^exponent, -6..6 |
| 8 | Value, nullable int64 | Independently available reading, limited to ±2^62 |
| 9 | Origin, uint8 | 0 unknown, 1 measured, 2 derived, 3 synthetic |
| 20 | Generation, uint64 | Source identity/reset generation supplied by the adapter |
| 21 | Sequence, uint64 | Source snapshot sequence, distinct from Matter EventNumber |
| 22 | Timestamp, nullable uint32 | Measurement time, seconds since 2000; not host receipt time |

VolumeReading additionally defines tags 10 ID (nullable UTF-8), 11 channel time
(nullable uint32, Matter epoch), 12 raw source type (nullable uint32). Unknown
unit remains explicitly unknown: the numeric source register is retained but
must not be relabelled m³ or converted into EEM. Volume keys are 0..3.

MetadataEntry has tags 0 Key (0..9), 1 Value (nullable UTF-8, <=100 bytes), plus
20/21/22 as above. Metadata is a list so long valid fields can be chunked between
entries. No truncation, no borrowed pointers, no implicit NUL terminator.

SourceState has tags 0 Quality (0 unavailable, 1 fresh, 2 stale, 3 invalid),
1 raw Status (uint32), 2 source SampledMilliseconds (uint64, monotonic domain
shared with refresh), 3 expected IntervalMilliseconds (uint64), 4 nullable
ActiveTariffRegister (uint8; input 0 means unknown), 5 nullable conversion
mantissa (positive int64 <=2^62), 6/7 nullable external-link encryption and
authentication booleans, 8 nullable conversion exponent (-18..18), and 20/21/22.
The factor is `mantissa * 10^exponent`, **information only**: values have already
been scaled. Flags describe the external meter link, not the Matter session.
Keys, passwords and authentication material are not fields of this schema.

## Example mapping and x86 source

`tools/matter/host/matter_source_sim.c` defines 61 channels. Applications can
provide a different explicit mapping; changing a deployed key's meaning needs
a versioned schema, not reuse of an old key with new semantics.

| Group/keys | Mapping |
| --- | --- |
| Registers 0..5 | Active + total/T1/T2, then - total/T1/T2, mWh |
| Registers 6..11 | Reactive + total/T1/T2, then - total/T1/T2, mvarh |
| Registers 12..23 | Import inductive, import capacitive, export inductive, export capacitive; each total/T1/T2, mvarh |
| Directional 0..7 | Active + total/L1/L2/L3, then - total/L1/L2/L3, mW |
| Directional 8..15 | Reactive + total/L1/L2/L3, then - total/L1/L2/L3, mvar |
| Directional 16 | Apparent power modulus, mVA; no guessed direction |
| Directional 17..19 | L1/L2/L3 voltage, mV |
| Directional 20..22 | L1/L2/L3 current modulus, mA |
| Directional 23..25 | Derived signed L1/L2/L3 current, mA; origin=derived |
| Directional 26 | Aggregate PF, ratio ×10^-4 |
| Demand 0..5 | Positive total/T1/T2, then negative total/T1/T2, mW |
| Volume 0..3 | Independent IDs, timestamps, raw types and cumulative values |

Quantity codes in this example: 1 active, 2 reactive, 3 apparent, 4 voltage,
5 current modulus, 6 signed current, 7 PF, 8 volume. Metadata keys 0..9:
external ID, model, identification, protocol, protocol version, interface,
type prefix, type vendor, source type code as decimal text, identity provenance.
These describe the external source; Basic Information still describes the node.

The synthetic source keeps T1/T2 and total independent, including a missing
import T2 during seconds 8..11 of each 24-second cycle. Source is offline at
18..19, stale at 20..21, then recovers. Standard EPM/EEM also become null during
source loss/staleness; EEM's durable checkpoint is retained. Source current and
power directions remain separate. No energy is divided between phases.
The source UTC values are deterministic test values, not a claim about real time.
Registers copied from EEM resume from its store; other demonstration registers,
metadata and sequence are volatile. The cluster itself is a view of supplied
data, not a new persistent meter or an accumulator.

## Snapshot and lifetime contract

The application prepares data before the nonblocking callback. Configuration is
copied, membership is fixed, <=64 channels total and <=32 in one list. A snapshot
uses configuration order. `available=false` produces null; zero is a value.
The module validates, encodes and switches the full publication atomically,
without allocations during refresh/read. Callback, invalid UTF-8, numeric or
time errors invalidate live values, retain last accepted source identity and
return PORT_ERROR; the caller must still consume report readiness. Staleness is
age >= max_age_ms. Owner clock cannot move backwards. Source generation,
sequence and sampled time cannot regress within the instance; an unchanged
generation/sequence must describe identical data. Generation authority belongs
to the adapter, not reconnects or parser restarts.

Each IM list snapshot is copied before chunking; its values, generation and
sequence are stable across chunks. The existing IM contract is **not atomic
across different attributes/clusters**. Clients correlate DataVersion and
Generation/Sequence, and retry if they need one cross-attribute observation.
The extension does not introduce a global lock or pin the application event loop.

Large snapshots, encoded buffers and validation workspaces are per-instance heap
state. The host allocates the simulator only when the option is enabled. No
shared mutable buffers or tasks. The callback user must outlive cluster deletion.
Unit helpers check finite/range before conversion and use half-away-from-zero
rounding. `matter_meter_source_scale` accepts the **base-unit** value; for source
kWh to mWh convert kWh to Wh once, then use exponent -3. Already scaled integers
should bypass double. `matter_meter_source_epoch` rejects out-of-range Unix time.

## Run and acceptance

```sh
build/cmake/matter-node --interface <index> --credentials <development-dir> \
  --state build/source-test/state.bin --port 5547 --discriminator 3847 \
  --seconds 120 --three-phase --source-registers
python tools/matter/tests/chip_tool_meter_source.py --chip-tool <chip-tool> \
  --paa <trusted-development-PAA-dir> --output build/source-test/check
ctest --test-dir build/cmake --output-on-failure -R test_meter_source
```

Create the state directory first; use a disposable node/fabric. The oracle
temporarily restricts then restores its own fabric ACL. Unmodified chip-tool
uses its generic DMG TLV logger because it has no named decoder for this schema.
The oracle reconstructs list chunks, validates every group, exercises live
source loss/recovery and rejects namespace/read-only/ACL violations. The pair
fixture accepts `--source-registers` (implies its three-phase option); use the
three-phase controller's `--pair-discriminator ... --source-registers` mode.

The option is additive and requires `--three-phase`; existing defaults remain.
It does not change the persistence schema or expose a UI automatically. Firmware
integration, actual meter provenance/units, vendor assignment and product-facing
presentation remain separate work. See [executed MP03 validation](oss/mp03-validation.md).
