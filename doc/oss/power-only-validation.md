# Separate power-only sensor

`matter-node --test-power-only` adds endpoint 6 with Electrical Sensor
(`0x0510`, revision 1) and exactly these server clusters:

| Cluster | ID | Role |
| --- | --- | --- |
| Descriptor | 0x001D | Type, server list and empty child list |
| Electrical Power Measurement | 0x0090 | AC ActivePower, 123000 mW = 123 W |
| Power Topology | 0x009C | Standalone topology, independent of the socket |

There is no On/Off or EEM on this endpoint. The synthetic source is constant,
marked not measured, refreshed once per second through the existing EPM
callback and owner loop. It neither borrows the socket state nor creates an
energy register. No persistence, timer, thread or protocol API is added.
Node owns both clusters and the sample; partial construction and shutdown
use existing cluster cleanup. Endpoints 0..5 keep their previous meanings.
The opt-in profile advances ConfigurationVersion by 200 to announce the model
change. Without the flag the previous model and ConfigurationVersion remain.

Matter Device Library 1.6.1 section 2.6 permits EPM without EEM and requires
Power Topology. Root's mandatory services remain present. This experiment
does not establish that Apple Home supports a separate sensor tile.

## Validation

The existing disposable full-profile CHIP runner adds `--power-only`:

```sh
python tools/matter/tests/test_plug_energy_chip.py \
  --exe build/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/credentials \
  --interface 2 --output build/power-only-memcheck --power-only --memcheck
```

Run separately with a `MATTER_SANITIZE=ON` executable, without `--memcheck`.
The oracle checks exact inventory, attested commissioning, CASE Read and
Subscribe priming, 123 W before/after socket On/Off and after a fresh CASE
following restart. It also retains the full socket energy, event, persistence
and last-fabric-removal checks. This tests the host with both optional endpoints,
not an Apple controller or the minimal power-only command line in isolation.

Results and source/binary identities are recorded in
[power-only-results.json](power-only-results.json). Seven focused CTests
(`test_energy_sim`, `test_root`, `test_switch_sim`, Read/Subscribe and their
allocation variants) pass on Windows, Linux and separate Linux sanitizers.
The complete scenario passes under Memcheck over two host boots: 35,935
matched allocations/frees, zero errors and zero live bytes at exit. Its
separate ASan/UBSan/LSan run also passes both boots with empty diagnostic
stderr. Final focused build logs contain no compiler warnings.
This is not a full CSA campaign; the existing matrix and next CSA24 task remain.

The Windows household node is restarted using its existing paired state and
network binding, with the new flag alongside the metered socket. Local launcher,
backups, identities and logs remain ignored. After closing/reopening Apple Home
and checking the room/sensor view, the user reports only the existing socket;
the separate 123 W sensor is not visible. The original node was not removed
or recommissioned.

A second instance of the same tested profile was then started with isolated
state, a different port, unique discovery identity and fresh pairing payload.
The original process remained running. The user successfully added this new
instance to Apple Home and again reports only On/Off with power 600 and unit
`T`, without the separate 123 W sensor. The new log confirms two fabric
advertisements, an On command on endpoint 2 and the endpoint-6 startup marker;
diagnostic stderr remains empty. Both instances remain running.

This fresh-pairing reproduction makes a stale model of the original paired
node insufficient to explain the result. The observed 600 belongs to the
control socket, while the independent sensor reports 123 W over CHIP. This
does not prove universal Apple support/rejection of Electrical Sensor: no
controller path trace was recorded, and a minimal node without the control
socket/other meter endpoints was not tested. UI handling versus another
Apple-specific interoperability issue remains unresolved.

Changed implementation is confined to the host composition/CLI. Existing
inventory and CHIP runner gain an optional mode; library APIs are unchanged.
