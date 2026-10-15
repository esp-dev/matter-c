# OTA requestor host laboratory

The x86 host can download a Matter OTA image over BDX, validate its header and
digest, authenticate a signed simulation payload, journal a simulated install,
exit for restart, and send NotifyUpdateApplied after restarting. This does not
install executable firmware or implement a production bootloader. The core API
continues to use application callbacks for storage, authentication and reboot.

`tools/matter/tests/test_ota_chip_provider.py` drives this path using the
unmodified CHIP OTA Provider and chip-tool. It creates a fresh 16,585-byte image
for software version 2, signs the simulation manifest with a temporary P-256
key, and writes only the public key. The private signing key is not serialized.
Each run requires a new output directory and disposable commissioning state.
The image targets the default development VID 0xFFF1 / PID 0x8001 and initial
software version 1; a differently configured host requires a matching fixture.

## Prerequisites and execution

Use Linux, Python with `cryptography`, the C `matter-node` executable, official
`chip-ota-provider-app`, chip-tool, development DUT credentials and a development
PAA trust directory containing roots for both devices. Keep all credentials,
images, journals and logs outside tracked files, for example under `build/`.
Attestation verification stays enabled. Development trust is not production trust.

CSA19 uses CHIP v1.6.1.0 at `3bcdd56ba54fb88b2afb4bfef575014671df7aa7`.
From an existing SDK checkout, activate its build environment and build the
provider into a separate output directory:

```sh
source scripts/activate.sh
gn gen --check --fail-on-unused-args --root="$PWD/examples/ota-provider-app/linux" \
  /path/to/lab/provider-build \
  --args='is_debug=true is_clang=true chip_config_network_layer_ble=false'
ninja -C /path/to/lab/provider-build -j3 chip-ota-provider-app
```

From this repository, supply explicit paths for the laboratory:

```sh
python3 tools/matter/tests/test_ota_chip_provider.py \
  --exe build/cmake/matter-node \
  --provider /path/to/lab/provider-build/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/lab/paa \
  --credentials /path/to/lab/credentials --interface 2 \
  --output build/ota-busy-01 --mode busy-update
```

The script owns and terminates its child processes. Reserve UDP ports 5561 for
the provider and 5581 for the requestor, and leave chip-tool's default port free.
Both devices must be discoverable over multicast on the selected interface.
The controller grants requestor node 1 Operate access only to the provider's
endpoint 0 / cluster 0x0029; its own Administer entry remains. Both devices are
commissioned into a disposable fabric, never a user's existing fabric.

`busy-update` checks QueryImage identity against Basic Information, BDX
Synchronous support and false RequestorCanConsent. Location is optional under
Core 1.6.1 11.20.6.6.1 and is omitted by this requestor. The provider first
returns Busy with a 150-second delay. The script observes a real 120-second
window with no second query, repeats AnnounceOTAProvider, then verifies the next
query, complete download, authentication, restart, NotifyUpdateApplied and
version 2 / SoftwareUpdateCompleted through a fresh CASE connection.

Use `--mode update --valgrind` with the normal C binary for the entire two-boot
Memcheck scenario. Then run `--mode update` separately with a binary compiled
with ASan/UBSan/LSan. This shorter mode skips the two-minute Busy procedure;
it must not be reported as timing acceptance. The provider and controller are
independent peers, not instrumented targets of the requestor memory check.

## Relationship to Test Harness

The installed case is **TC-SU-2.1**, SDK YAML Tests / FirstManualSuite, not an
automatic Python `TC_SU_2_1` test. Its three disabled YAML steps become manual
verification prompts in TH; they are not discarded by its manual runner.
Run the official case unchanged, evaluate each prompt against captured evidence,
and attach the laboratory log. A manually entered TH result remains manual
acceptance; the Python scenario is supplementary automation, not a replacement
for CSA assertions or certification. See [CSA19 evidence](oss/csa19-validation.md).
