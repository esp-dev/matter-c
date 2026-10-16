# Separate cumulative import/export on the minimal sensor

`--power-sensor-only --sensor-energy` adds Electrical Energy Measurement
(`0x0091`, revision 2) to endpoint 1 alongside Descriptor, EPM and Power Topology.
There is still no On/Off or other application endpoint. Without the extra flag,
the minimal power-only profile retains its no-EEM composition.

Application Cluster 1.6.1 sections 2.12.6.2/3 define distinct cumulative import
and export attributes. Wire units are mWh, not text or a configurable UI unit.
The synthetic source starts at 12345000 mWh imported (12.345 kWh) and 2345000
mWh exported (2.345 kWh). EPM stays +123000 mW. Import integrates that consumption
using the existing checked simulator; export remains historical with zero
current export. This preserves coherence between the power and register source.

EEM uses the existing physical-register view, FeatureMap 7 (import/export/cumulative)
and CumulativeEnergyMeasured event. Both directions share a coherent timestamp
and source generation. The existing fabric-independent EEM checkpoint in the
node's store serializes both registers; initialized state restores their raw
values instead of reapplying the demonstration baseline. New state is seeded
once. Accepted checkpoints persist before publication. Simulation fractions and
the tail since the last accepted checkpoint are not promised across a crash;
this is not a physical metrology source. No new storage format/library API is
introduced. ConfigurationVersion changes for the optional cluster addition.

## Validation route

```sh
python tools/matter/tests/test_plug_energy_chip.py \
  --exe build/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/credentials \
  --interface 2 --output build/sensor-energy-memcheck \
  --sensor-only --sensor-energy --memcheck
```

Repeat separately against the sanitizer build without Memcheck. The runner
checks verified attestation, exact two-endpoint inventory/no On/Off, both initial
registers, +123 W, mixed EPM/EEM attributes and EEM events, import growth,
unchanged export, restart/fresh CASE, retained registers and last-fabric removal.
The energy flag alone is rejected. The existing seven focused native tests
remain the build checks; no new CTest definition is added.

Actual results and source/binary identities are recorded in
[sensor-energy-results.json](sensor-energy-results.json). This is local host
interoperability, not new CSA acceptance; the existing matrix and next CSA24
task remain unchanged.

## Apple Home boundary

The user confirmed the preceding pure-EPM node shows a value under `Energia`.
That earlier snapshot contained no EEM. This change provides cumulative energy
attributes to the already paired sensor and retains its state. The user reports
only `123 T` after the update. They then removed and successfully re-added the
sensor and again report only `123 T`, with no separate import/export fields.
The initially reported reconnection failure was subsequently resolved by the
user; no reset or replacement of its store was performed in that investigation.

A read-only inspection using the production TLV decoder confirms the current
stored state has two fabrics, no pending/journal transaction, initialized EEM,
12356265 mWh imported and 2345000 mWh exported. This confirms live simulated
register storage, not a live wire read by the Apple controller. No keys or
certificate contents were printed. The independent CHIP Read/Subscribe results
above remain separate evidence of on-wire EEM operation.

The observed UI exposes power but not the two cumulative values in this tested
profile/iOS version. It does not establish universal lack of EEM support or the
exact cause: no Apple request-path trace was captured. The library cannot set
the controller's display label or unit string.

## Executed outcome

Full CHIP scenarios pass under Memcheck (two boots, 35,439 matched
allocations/frees, zero errors and zero live bytes) and separately with
ASan/UBSan/LSan (two clean boots, empty diagnostic stderr). Seven focused
CTests pass on Windows, Linux and separate Linux sanitizers. Final focused
build logs contain no compiler warnings. Source C/H hashes still match the
tested snapshot.

The Windows minimal sensor was updated in place after state/binary backups,
with its two fabrics retained. The same executable path, firewall scope and
pairing identity remain. Other two processes were not restarted. All three
were healthy with empty diagnostic stderr 57 seconds after the update.
