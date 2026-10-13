# Meter services on x86 (MP04)

Opt-in prerequisites for a future Meter Reference Point composition, targeting
Matter 1.6.1. This does not yet declare Meter Reference Point, Electrical Meter
or Electrical Utility Meter device types: their other required clusters and
child-endpoint composition must be implemented first. Existing Electrical Sensor
endpoints, phase tags and EEM source-register behavior remain unchanged.

```sh
build/cmake/matter-node --interface <index> --credentials <private-directory> \
  --state <separate-state-file> --three-phase --source-registers --meter-services
```

`--source-registers` is optional for a single node. `--meter-services` requires
`--three-phase` and credentials. CMake supplies the UTC build floor (honoring
`SOURCE_DATE_EPOCH`). Legacy direct compiler runners need an explicit
`MATTER_HOST_BUILD_UNIX` definition before enabling this new option. The default
profile is unchanged. Use a separate lab state/controller store.

## Declared servers

| Endpoint | Server | Implemented scope |
| --- | --- | --- |
| 0 | Time Synchronization `0x0038`, rev2 | UTCTime, Granularity, TimeSource, SetUTCTime, TimeFailure; FeatureMap=0 |
| 1 | Identify `0x0003`, rev6 | IdentifyTime, IdentifyType, Identify command; no TriggerEffect |
| 1 | Meter Identification `0x0B06`, rev1 | MeterType, PointOfDelivery, MeterSerialNumber, ProtocolVersion; no PowerThreshold feature |

Each provides the standard global attribute/command lists. IdentifyTime writes
require Operate; Identify commands require Manage. SetUTCTime requires
Administer. Measurement identity and clock attributes are read-only (View).
Unknown identity fields are nullable, not fabricated. The x86 example uses
Generic meter type, serial `SIM-0001`, protocol `1.0`, and null PointOfDelivery.
These describe the synthetic source, not the node's Basic Information identity.
IdentifyType=None accurately reflects the lack of physical indication on x86;
the presentation callback records start/stop in the log.

IdentifyTime decreases on monotonic one-second boundaries. Reads see the current
value, but normal countdown ticks do not cause reports. Explicit command/write
(including the same value) and expiry update DataVersion and reporting.

## Reusable callback contracts

The three constructors return `Matter_Cluster_T`; implementation state is opaque,
heap-owned and independent per instance. Headers expose configuration/ports only.
Constructors do not call application callbacks. Destroy after detaching/deleting
the owning Root and after draining IM; event log and callback contexts outlive
their clusters. Callback execution is on the owner's thread and must not reenter.

- `matter_identify_new`: application presentation callback receives duration or
  zero on stop/expiry/deletion. Pump `matter_cluster_process`/deadline.
- `matter_meter_identification_new`: snapshot callback supplies copied UTF-8
  metadata (64-byte maximum per string). Call refresh before IM. Invalid data or
  callback failure publishes unavailable fields; no stale identity is retained.
- `matter_time_sync_new`: Root EP0 only; nonblocking sample/set/synchronize ports.
  Pump before IM and notify the runtime on reportable version changes. The
  backend owns actual UTC, drift assessment and durable Last Known Good (LKG).
  Unknown UTC is null with NoTimeGranularity/None. Failed acquisition generates
  TimeFailure with at most one event per hour; acquisition retries hourly while
  unknown. No Time Zone, NTP client/server or Trusted Time Source feature is claimed.

SetUTCTime validates its fields, lowers the requested precision one level
(minimum Minutes for a known time) and sets source Admin. Granularity=0 updates
LKG but leaves live UTC unknown. A backend policy rejection produces
TimeNotAccepted; storage errors produce Failure. The backend must commit LKG
before publishing a new clock and preserve the old state on failure.

## Host clock and storage

The host uses a separate monotonic UTC anchor per node. SetUTCTime does not
change the operating-system clock or another node. OS UTC seeds initial time;
subsequent precision degrades using a documented simulation assumption of
100 ppm oscillator error. This is not hardware accuracy validation or an NTP
implementation. Certificate validation and attestation timestamps use the same
instance clock, with LKG fallback when live UTC is unknown.

The new `<state>.clock` sidecar contains only a versioned 16-byte LKG record:
`MCUTC001` plus unsigned little-endian Matter epoch microseconds. The existing
atomic file adapter provides exclusive locking and staged replacement. LKG is
raise-only, covering build time, accepted SetUTCTime and operational certificate (NOC/ICAC/RCAC)
NotBefore floors and commissioning time; periodic updates are monthly. Restarts load LKG but reacquire
live UTC rather than treating an old saved clock as current. Preserve the
sidecar with node state. This does not implement downstream provisioning.

## Interaction Model compatibility

`Matter_Im_Value_T.report_on_version_change` is an opt-in reporting policy for
countdown/continuous time values. Reads remain current and ACL checks still run;
subscription updates suppress that attribute until DataVersion changes. Other
providers retain their previous behavior with the default false value.
The field extends a public C struct: rebuild library and consumers together;
there is no stable binary ABI promise for this experimental package.

## Acceptance commands

```sh
python tools/matter/tests/chip_tool_meter_services.py \
  --chip-tool <chip-tool> --paa <development-paa-directory> --output <new-output>
# Pair fixture includes three-phase, source registers and a test switch:
build/cmake/cmake/tests/runtime-pair-host <index> <credentials> <state-a> <state-b> --meter-services
python tools/matter/tests/chip_tool_three_phase.py \
  --chip-tool <chip-tool> --paa <development-paa-directory> --output <new-output> \
  --discriminator 3846 --pair-discriminator 1234 --source-registers --meter-services
python tools/matter/th/meter_services_project.py --base <private-TH-export.json> \
  --output <new-project.json> --endpoint 0 --discriminator 3910
```

Prepare another TH project for endpoint1, then explicitly import the generated
projects. The helper does not modify a running TH or existing projects. Neither
credentials nor lab exports belong in Git. Independent chip-tool checks are
separate from official CSA results; see [MP04 evidence](oss/mp04-validation.md).

The pair oracle commissions with a QR payload generated by the unmodified
chip-tool, so returned discovery results are checked against the requested
discriminator. `--pair-reverse` commissions B before A while preserving their
node/port identities. `--pair-legacy-discovery` is only for reproducing the pinned
`onnetwork-long` startup selection defect; it is not the acceptance default.

To test discovery while both full runtimes are starting, use the Linux runner
instead of manually launching the pair (do not run network scenarios concurrently):

```sh
python tools/matter/tests/test_discovery_startup_linux.py \
  --exe <normal-build>/cmake/tests/runtime-pair-host \
  --chip-tool <chip-tool> --paa <development-paa-directory> \
  --credentials <development-credentials> --interface <index> \
  --output <new-private-output> --mode memcheck --reverse
```

Repeat without `--reverse`, then separately with `--mode sanitize` and the
ASan/UBSan/LSan build. The runner starts the DUT only after observing the real
subtype query; there is no startup-settling sleep. It records discovery packets
and validates PTR/SRV/TXT correlation in addition to the full CASE/IM pair checks.
Use a dedicated interface with ports 5541/5542 free. No raw-socket privileges are
needed. Outputs include private controller/node state and LAN discovery data;
retain them outside Git. This is independent acceptance, not an official CSA case.
