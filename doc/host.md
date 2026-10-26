# Linux and Windows development hosts

Run commands from the repository root unless another directory is stated.

The host executables are optional application adapters around the portable C
library. They own networking, storage, scheduling and simulated measurement
sources. Production firmware supplies its own platform ports.

## Native Windows desktop

The English-language Windows [native C desktop](desktop.md) builds as `matter-desktop.exe`:
one executable manages independent power-sensor windows, commissioning QR/status
and a release-triggered −10…+10 kW slider. Per-user state retains each node's
identity/pairing. Runtime dependencies are Windows/UCRT only; development
credentials remain external. See [acceptance](oss/desktop-validation.md).
REST HTTP(S) integrations are planned, not implemented.

## Measurement and switch profiles

The optional [three-phase profile](three-phase.md) adds tagged aggregate/L1/L2/L3
endpoints and EEM source-register semantics: run the host with `--three-phase`
and a separate state file. The default host profile is preserved.
Add `--source-registers` for the [manufacturer-specific source view](meter-source.md):
tariff/quadrant/demand registers, directional values, metadata and volume channels.

`--test-switch` adds a simulated metered socket on endpoint 2: On/Off plus
Electrical Sensor, Power Topology, EPM and EEM. It reports 600 W while on and
0 W while off, with its own cumulative import register and zero export.
With `--state`, a separate `.plug-energy` TLV sidecar retains that register
and its fractional remainder. It starts off after restart. This UI experiment
is an incomplete plug device profile, not certified hardware; see
[validation and UI limitations](oss/plug-energy-validation.md).

For a separate power-only UI experiment, add `--test-power-only`. Endpoint 6
is an Electrical Sensor with Descriptor, EPM and Power Topology, reporting
a fixed synthetic 123 W independently of the socket. It has neither On/Off
nor EEM. Existing endpoint numbers and the profile without this flag remain
unchanged. See [acceptance and UI limits](oss/power-only-validation.md).

Use `--power-sensor-only` for a minimal node: required Root services on endpoint
0 and one Electrical Sensor on endpoint 1, with Descriptor/EPM/Power Topology
and synthetic 123 W. There is no On/Off or EEM anywhere. This mode excludes
the other measurement/switch/test-trigger profiles and uses a separate mDNS
host label so it can coexist with other simulated nodes on the same interface.
See [minimal sensor acceptance](oss/sensor-only-validation.md).

`--power-sensor-only --sensor-energy` also exposes EEM on endpoint 1:
separate cumulative import/export registers and the cumulative measurement
event. Initial simulated registers are 12.345 kWh imported and 2.345 kWh
exported. The constant +123 W increases import; export is historical and
unchanged. With `--state`, accepted register checkpoints survive restart through
the existing store. Display and unit selection remain the controller's choice.
See [energy-register acceptance](oss/sensor-energy-validation.md).

## OTA laboratory

The optional [OTA host laboratory](ota-host.md) uses an unmodified CHIP
provider to exercise QueryImage, Busy timing, BDX, a signed simulation image,
restart and NotifyUpdateApplied. Its memory-tool modes cover both boots.
The fixture does not install executable firmware or certify a bootloader.

## CLI, credentials and discovery

The CMake executable is `build/cmake/matter-node` (with `.exe` on Windows).
Legacy builders keep `build/matter-host/linux-gcc/matter-node` or
`build/matter-host/gcc/matter-node.exe`. An unknown option prints usage and exits 2.
The application owns its event loop; network interface, credential directory and
persistent state are explicit parameters. Keep generated credentials/state in
ignored `build/`, and never use public fixture keys as device credentials.

For the credential-backed runtime host, Extended Discovery (CM=0) defaults to
900 seconds per closed-mode entry/boot. Add `--extended-discovery-seconds 0` to
disable it, a numeric seconds value to bound it, or `unlimited` to opt into
indefinite advertising. This setting withdraws only commissionable DNS-SD;
operational discovery, CASE and authenticated new commissioning windows stay
available. It is a process option, not a stored GUI preference. Host PH is 1
before commissioning and 4 for a commissioned administrator. See
[policy, API and acceptance limits](oss/csa35-validation.md).

The host defaults to VendorName `Matter C` and ProductName `Matter C host simulation`.
Override them at compilation, for example:

```sh
cmake -S . -B build/cmake -DMATTER_HOST_VENDOR_NAME="Example" -DMATTER_HOST_PRODUCT_NAME="Example energy meter"
```

The legacy builders accept `--vendor-name` / `--product-name` (Python) and
`-VendorName` / `-ProductName` (PowerShell). Both strings must contain 1..32 UTF-8
bytes; NUL, line breaks and semicolons are unsupported. Direct C compilation can
define `MATTER_HOST_VENDOR_NAME` and `MATTER_HOST_PRODUCT_NAME` as string literals.
VID/PID and credential matching are unchanged. For custom branding, give the same
expected strings to `chip_tool_acceptance.py --vendor-name ... --product-name ...`.
Library consumers continue to supply their identity through `Matter_Root_Config_T`.

Local lab paths may be kept in ignored `local/lab.json`; this file is a private
notebook, not automatically loaded by the host. Builds still take explicit paths.
Portable certificate tests use synthetic signed chains and public upstream
fixtures with retained notices. See [fixture provenance](../tools/matter/fixtures/fixture-provenance.md).

The optional Matter.js test controller uses the committed package lock:

```sh
npm ci --prefix tools/matter/controller --ignore-scripts
mkdir -p build
node tools/matter/tests/host_controller.mjs tools/matter/controller/node_modules credentials build/credentials
build/cmake/matter-node --interface 2 --seconds 60 --port 5541 --credentials build/credentials --state build/state.bin --pin 20202021 --discriminator 3846 --case-resumption-profile chip --certificate-validity strict
```

Choose your isolated test interface. `--case-resumption-profile chip` is the
explicit interoperability profile; certificate validity remains strict above.
For an already connected simulated Wi-Fi device, add `--wifi-sim-connected`
and use a fresh state path. It seeds the existing `testharness` AP as configured
and connected; `testharness-2` remains available to scans. The default still has
an empty Networks list. A restored file always takes precedence, including an
empty list: this option never replaces saved settings. It requires `--credentials`.
The radio is simulated; IPv6 transport uses the selected real host interface.
It neither configures nor connects the OS Wi-Fi adapter. ScanNetworks requires
an armed fail-safe as specified by Core 1.6.1 section 11.9.7.1.
To execute the Matter.js network scenario, pass `--modules tools/matter/controller/node_modules`
to `tools/matter/tests/test_host_network.py` together with `--exe`, `--interface`
and `--ipv6`. Windows DLL search can be set with `--runtime`; Node with `--node`.
Other network runners retain these explicit overrides.

`build_host_linux.py --sanitize` builds ASan/UBSan (LSan enabled at runtime).
Run Memcheck separately on the ordinary build with `--leak-check=full
--show-leak-kinds=all --track-origins=yes --error-exitcode=99`.
The Linux `--test` runner also requires `MATTER_IPV6_INJECTOR` pointing to the
fixed-case helper with CAP_NET_RAW; it never grants that capability itself.
SDK/CSA test scripts in `tools/matter/tests` require an externally provisioned
CHIP/TH environment; neither SDK nor TH is redistributed here.

Fixture generators are optional, not build prerequisites. OpenSSL/GCC default
to PATH and support `OPENSSL`/`GCC`. `extract_operational.py` takes explicit
`--rs-matter` and `--matter-js` checkouts; use revisions in tools/matter/fixtures/operational-sources.md.
Committed fixtures remain available without any upstream checkout or CSA PDF.

See [current status and validation](oss/status.md) for unresolved coverage.
