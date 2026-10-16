# Root plus a power sensor only

`matter-node --power-sensor-only` creates exactly two endpoints:

```text
0: Root Node and its required node services
1: Electrical Sensor (0x0510 rev1)
   Descriptor (0x001D)
   Electrical Power Measurement (0x0090): AC, ActivePower 123000 mW = 123 W
   Power Topology (0x009C)
```

There is no On/Off, EEM, meter register view or phase endpoint anywhere in this
profile. Device Library 1.6.1 section 2.6 permits EPM without EEM and requires
Power Topology. Required Root networking, security, commissioning, diagnostics
and OTA Requestor declarations remain. The source is synthetic and marked not
measured. No new library API, task, timer or storage format is introduced.

The new CLI mode rejects switch, extra-sensor, phase, source-register,
meter-services and test-trigger combinations. The earlier `--test-power-only`
mode still adds endpoint 6 beside existing measurements; it is a different
experiment. The common host factory creates either sensor. Null cleanup guards
cover omitted aggregate EPM/EEM/topology clusters. Existing modes retain their
previous behavior and configuration versions.

## Coexistence correction

The first Windows start reproduced a discovery failure in both earlier paired
instances. They logged `Discovery state transition failed` and exited. Their
stores were preserved; both were restarted with the unchanged prior executable
and existing state. No unpair/reset or firmware change was performed.

The host previously derived every simulated node's mDNS host name from the
same physical MAC. The minimal mode now derives a per-process local host label
from random data and uses it consistently for commissionable and operational
discovery. The real interface MAC and IP addresses are unchanged. Other modes
keep the physical-MAC host label. This isolates the new simulation's host name;
the precise conflicting packet from the initial failure was not captured.

## Acceptance and limits

The existing external runner adds `--sensor-only`:

```sh
python tools/matter/tests/test_plug_energy_chip.py \
  --exe build/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/credentials \
  --interface 2 --output build/sensor-only-memcheck --sensor-only --memcheck
```

Repeat against a separate `MATTER_SANITIZE=ON` host, without Memcheck. The
oracle checks verified development attestation, exact full-tree inventory,
123 W Read and Subscribe priming, restart/fresh CASE, last-fabric removal and
five conflicting CLI profiles. Full scenarios pass under Memcheck and separately
ASan/UBSan/LSan after the discovery-label change. Seven focused CTests pass on
Windows and in both Linux builds. This is not a full native or CSA rerun.
Source/binary identities, actual memory totals and logs are summarized in
[sensor-only-results.json](sensor-only-results.json).

The Windows test uses its own executable, port, state and pairing payload.
Its logs and QR remain ignored by Git. After fresh pairing, the user confirms
a value visible under `Energia` in Apple Home. This snapshot has only EPM,
so that value represents power, not a cumulative energy register. The UI
observation is separate from protocol acceptance and the earlier full-profile
test where only the control socket was visible.
The existing CSA matrix is unchanged; next remains CSA24 automatic TC_SU_2_5.

The final Memcheck scenarios have 35,146 matched allocations/frees over two
host boots, zero errors and zero live bytes. Separate sanitizer diagnostics
are empty. All three Windows processes were observed alive without stderr
84 seconds after the corrected minimal-node start; its firewall scope was
verified. This finite observation is not a long-duration stability guarantee.
