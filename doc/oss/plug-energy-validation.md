# Metered socket interoperability

This is an opt-in host simulation, not a CSA result or a complete plug profile.
The existing CSA23 matrix remains 97 PASS, 14 FAIL, 10 BLOCKED, 37 MANUAL and
704 NA. No official test was rerun for this change. Next remains CSA24:
automatic TC_SU_2_5, provider IPC, subscriptions and interruption.

## Model and units

With `--test-switch`, endpoint 2 contains:

```text
Node
  Endpoint 2: On/Off Plug-in Unit (0x010A) + Electrical Sensor (0x0510)
    Descriptor                 0x001D  DeviceTypeList/ServerList
    On/Off                     0x0006  simulated output
    Electrical Power Measurement 0x0090  AC, ActivePower
    Electrical Energy Measurement 0x0091  import/export/cumulative
    Power Topology             0x009C  node topology
```

Matter Device Library 1.6.1 sections 2.6 and 5.1 define these device types.
Electrical Sensor requires Power Topology and at least one of EPM/EEM.
The existing On/Off demo still lacks mandatory Identify, Groups, Scenes and
the complete OnOffLighting behavior: adding measurements does not complete
its plug conformance. Existing Root/aggregate/phase/source endpoints remain.
No aggregate or phase energy is reassigned to the socket.

Application Cluster 1.6.1 section 2.13.6.9 defines ActivePower as signed mW:
On reports **600000 mW = 600 W**, Off reports 0. The protocol transmits a numeric
attribute, not a localized unit string. EEM uses mWh; import integrates the
previous state up to each transition, preserving sub-mWh fractions. Export is
zero. Both accuracy configurations mark this as synthetic, not measured data.

With `--state`, the atomic `.plug-energy` sidecar contains a small versioned
TLV structure: schema 1, imported mWh and fractional mW-ms remainder.
It is separate from the fabric store. Graceful stop checkpoints the final
fraction; restart restores import and starts off without counting downtime.
Without state it is volatile. Crash loss is bounded by the last successful
checkpoint, not guaranteed to be zero. Corrupt/unreadable/oversized sidecars
abort startup rather than resetting a counter. Keep these files private.

## Resource failure and fix

The first independent full-tree CHIP Read reproduced ResourceExhausted with
the former 320-result table. Its failed artifacts are retained locally; the
test was not narrowed to hide the failure. Read/Subscribe now lazily grow
their owned result arrays, capped at 512. This is an application ceiling,
not a normative Matter maximum. Read's chunk plan is allocated from output
capacity. Transport, snapshots, selectors and per-value limits are unchanged.

## Executed checks

Windows and Linux normal builds each pass these seven focused CTests:
`test_energy_sim`, `test_root`, `test_switch_sim`, `test_im_read`,
`test_im_subscribe`, `test_im_read_alloc`, `test_im_subscribe_alloc`.
The separate Linux ASan/UBSan/LSan build passes the same seven. Final focused
compiler logs contain no compiler warnings. This is not a full CTest rerun.

The unmodified CHIP controller scenario passes under Memcheck, then separately
with ASan/UBSan/LSan, on disposable nodes:

1. Verified development attestation and commissioning.
2. Exact full-tree attribute inventory, including existing meter endpoints.
3. Mixed EPM/EEM attribute/event subscription on endpoint 2.
4. On reports 600000 mW and import grows; Off reports 0 and import pauses.
5. Export remains zero; cumulative events contain both directions on endpoint 2.
6. Graceful restart, fresh CASE and exact retained import (836 mWh in Memcheck,
   746 mWh under sanitizers); power is zero after restart.
7. Last-fabric RemoveFabric response and clean host exit.

Four malformed sidecars were also tested under each memory-tool build:
truncated TLV, wrong schema, out-of-range fractional remainder and oversize.
All eight runs reject startup, preserve the file and leave no published node.
Six Memcheck boots in total (two successful lifecycle boots and four rejected
startups) have 52,917 matched allocations/frees, zero errors and zero live bytes
at exit. Separate sanitizer
executions have empty diagnostic stderr. Native allocation tests inject initial
and growth failures, chunk-plan allocation failure and 512/513 result bounds.

The machine-readable [evidence](plug-energy-results.json) records source and
binary identities, result hashes and memory totals. Raw credentials, controller
stores, addresses, packet captures and local paths remain outside Git.

Example external invocation, with private paths supplied by the operator:

```sh
python tools/matter/tests/test_plug_energy_chip.py \
  --exe build/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/credentials \
  --interface 2 --output build/plug-memcheck --memcheck
# Repeat separately with --exe build/sanitize/matter-node and no --memcheck.
```

## Manual UI observation and limits

The paired Windows node retained its fabrics. The user initially observed
offline, then online with On/Off and a numeric power field changing from 0
to 600. On iOS **27.0.1** the user reports the unit as the Latin `T`, not `W`.
The label's cause is unresolved; neither the Matter attribute nor our callback
sends that string. Cumulative energy visibility in Apple Home is unconfirmed.
No assertion is made about Google UI, thermostat UI, physical hardware,
production bootloader behavior or CSA certification.

Apple's linked [electricity usage guide](https://support.apple.com/en-euro/guide/iphone/iphb93a7973e/ios)
describes utility-account usage/rates from participating U.S. providers. It does
not establish this Matter socket's UI contract. The observed 600 power field
is recorded separately from that guide and from protocol test acceptance.

Implementation: `matter_node.c` composes the socket and storage adapter;
`matter_im_read.[ch]` and `matter_im_subscribe.c` own the growing result tables.
The new CHIP runner and updated inventory helper validate the added model;
energy/Read/Subscribe native suites cover integration and allocation failures.
