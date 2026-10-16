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
Core 1.6.1 11.20.6.5.1 and is omitted by this requestor. The provider first
returns Busy with a 150-second delay. The script observes a real 120-second
window with no second query, repeats AnnounceOTAProvider, then verifies the next
query, complete download, authentication, restart, NotifyUpdateApplied and
version 2 / SoftwareUpdateCompleted through a fresh CASE connection.

Use `--mode update --valgrind` with the normal C binary for the entire two-boot
Memcheck scenario. Then run `--mode update` separately with a binary compiled
with ASan/UBSan/LSan. This shorter mode skips the two-minute Busy procedure;
it must not be reported as timing acceptance. The provider and controller are
independent peers, not instrumented targets of the requestor memory check.

## QueryImageResponse scenarios (CSA20)

For actual response-field verification, build the same official provider with
these additional GN arguments: `matter_enable_tracing_support=true` and
`matter_log_json_payload_hex=true`. To avoid a scope-tracing backend, set
`matter_trace_config` to the SDK's absolute `src/tracing/none` path. The SDK
source remains unchanged. These flags affect the external provider only.

Add `--require-trace` to `--mode update` to verify UpdateAvailable on the wire
and the provider's receipt of the final BDX block ACK. The following modes
require JSON trace automatically:

| Mode | Response and expected requestor behavior |
|---|---|
| `busy-60` | Busy / 60 seconds; no retry before 120 seconds, then complete update |
| `busy-180` | Busy / 180 seconds; respect the delay from the response, then complete update |
| `not-available` | NotAvailable; no query or download over a real 120-second observation |
| `same-version` | UpdateAvailable / version 1; reject before BDX |
| `older-version` | UpdateAvailable / version 0; reject before BDX |
| `invalid-uri` | UpdateAvailable / missing BDX file path; reject before BDX |
| `interrupt-retry` | Kill the provider during BDX, wait five real minutes, read Idle, restart the same provider and download from offset zero |

The pinned official provider emits DelayedActionTime only for Busy: its CLI
`--delayedQueryActionTimeSec 60` is ignored for NotAvailable. That optional field
is therefore omitted in the observed NotAvailable response; the 120-second
minimum still applies. This scenario does not test a supplied NotAvailable delay.

Each invocation uses a new output directory. Run the modes sequentially because
they use the same laboratory ports and discriminators. Same/older/invalid URI
checks wait for the requestor's completed Idle decision, challenge the query
floor with another announcement, observe three seconds without download, and
read version 1 / boot reason PowerOn over fresh CASE. This is a bounded rejection
check, not evidence about every future retry. Busy modes verify both query
timestamps and the response-delay interval. The requestor retains a conservative
120-second floor from completion of the preceding QueryImage Invoke. This keeps
a repeated announcement from bypassing the time spent establishing CASE before
the original request reached the provider. The 60-second mode allows a valid
retry at 120 seconds; it does not reject it for arriving shortly after that bound.

The independent Python reader reconstructs the official `json:log` trace from
its Automation log chunks and checks the actual IM response path
0 / 0x0029 / QueryImageResponse and its Status, DelayedActionTime, version and
URI. CLI arguments alone are insufficient, particularly for testing an older
image that a provider might otherwise filter out. The provider log includes
plaintext laboratory protocol data and belongs only in ignored output directories.
This log backend avoids the pinned SDK's file-trace opening failure; no SDK
source patch is required.
The original CSA19 `update` and `busy-update` modes still accept a provider built
without tracing unless `--require-trace` is explicitly supplied.

`interrupt-retry` implements the applicable failure procedure of TC-SU-2.3.
The provider's official `--pollInterval 500` slows its first transfer so the
runner can capture a matching partial file prefix before killing that process.
The first provider must not have received AckEOF, and the requestor must not
have authenticated, published or installed the partial image. The requestor
continues running throughout a 301-second monotonic observation. The runner
then reads UpdateState=Idle and unchanged SoftwareVersion through chip-tool,
checks partial-file cleanup, restarts the provider with its existing KVS and
image, and announces it again. The second provider log must show ReceiveInit
with STARTOFS unset and Start Offset zero. Full download, exact image hash,
authentication, simulated reboot, NotifyUpdateApplied and fresh CASE readback
must still succeed. Separate provider logs retain both attempts.

Run this mode once with the normal executable and `--valgrind`, and separately
with the sanitized executable. Each run waits the full interval. An MRP delivery
error can end the transfer before the BDX idle timer; the runner records the
observed failure time separately. Such an error is not evidence that a BDX idle
timer expired early. The five-minute rule is Core 1.6.1 11.20.3.5; the optional
ReceiveInit STARTOFS field is described in 11.22.5.1. This profile restarts at
zero and does not declare transfer resumption, HTTPS or requestor user consent.

## Relationship to Test Harness

The installed case is **TC-SU-2.1**, SDK YAML Tests / FirstManualSuite, not an
automatic Python `TC_SU_2_1` test. Its three disabled YAML steps become manual
verification prompts in TH; they are not discarded by its manual runner.
Run the official case unchanged, evaluate each prompt against captured evidence,
and attach the laboratory log. A manually entered TH result remains manual
acceptance; the Python scenario is supplementary automation, not a replacement
for CSA assertions or certification. See [CSA19 evidence](oss/csa19-validation.md).
