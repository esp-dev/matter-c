# ESP32-C6 external-stack memory reference

This laboratory compares the C runtime RGB fixture with an external ESP-Matter
light on a second C6. It does not embed ConnectedHomeIP in the C library. Keep
controller state, Wi-Fi headers, device flash backups and UART logs in ignored
`local/` or `build/`. No SDK checkout is modified by the preparation tool.

The measured reference uses ESP-Matter release/v1.6.1 commit
`4c9dd7aa80b3ddfa64c814bdfabe76c60944cc75`, its ConnectedHomeIP submodule
`b1902b39ac6734913ce5f4d2abf153693a50264b`, and ESP-IDF v6.0.2
`7101770dc6db2667b3c477cc31365dd1acd6db4e`. The C runtime uses IDF v6.1.
See the [Memory21 report](../../doc/oss/memory21-validation.md) for results,
failed exploratory runs and configuration differences.

Prepare a **new** copy after exporting the external IDF/ESP-Matter environments:

```sh
python tools/matter/prepare_esp_memory_reference.py \
  --esp-matter /path/to/pinned/esp-matter \
  --output /path/to/new-reference-light \
  --sdkconfig /path/to/existing-reference-sdkconfig \
  --hue-saturation
cd /path/to/new-reference-light
idf.py -B /path/to/reference-build -D IDF_TARGET=esp32c6 build
```

The tool adds observation hooks, enables the existing Hue/Saturation feature
when requested, and disables the three Wi-Fi IRAM placement options to match
the C lab. XY, color temperature, Scenes, other stock features and resource
limits remain enabled. Its board adapter uses WS2812 GPIO8 and button GPIO9.
Flash **that build's actual flasher_args.json**, after backing up the target;
the C runtime and reference have different partition offsets.

The C profile enables `MATTER_C_RUNTIME_RGB`, `MATTER_C_RUNTIME_SOAK`, and
`MATTER_C_RUNTIME_COMPARE_SAMPLER`. Keep `MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS`
off for headline comparisons: that separate attribution table changes layout.
Both observers compile the same `matter_lab_heap_sample.h`, sample internal
8-bit heap nominally every100ms from the SDK timer task, and include their own
timer/global cost. Samples can still miss shorter peaks. The SDK's aggregate
regional free watermark is a separate metric, not an exact simultaneous peak.
Dynamic task stack reservations are included in this heap pool; static RAM and
IRAM are reported separately from the linker map.

For the external light, run the private UART collector (requires pyserial):

```sh
python examples/esp-matter-memory/uart_capture.py --port COM_REFERENCE \
  --output build/private-reference --reset \
  --wifi-header local/private/matter_lab_wifi.h
```

The optional header contains the same JSON-string `MATTER_LAB_WIFI_SSID` and
`MATTER_LAB_WIFI_PASSWORD` macros as the C lab. Provisioning happens locally;
values are redacted before logs are saved. Omit the header for an already
provisioned board. File controls accept memory checkpoints and collector stop
only. `memstat <lowercase-label>` reports heap and all task stack watermarks.

Use the C runtime's existing UART collector for its board. With the pinned
Matter.js0.17.9 dependencies and an IPv6-connected interface, run sequentially:

```sh
node examples/esp-matter-memory/compare.mjs <node_modules> <scoped-ipv6> \
  <private-state> <controller-id> <private-uart-directory> reference commission <interface>
node examples/esp-matter-memory/compare.mjs <node_modules> <scoped-ipv6> \
  <private-state> <existing-controller-id> <private-uart-directory> c reuse <interface>
```

`commission` starts with an uncommissioned board; `reuse` requires one existing
fabric paired with the selected controller. Four temporary fabrics are added.
The private topology journal retains their identities if a test fails; do not
rerun blindly over a partially commissioned fixture. Preserve the original
fabric and controller state or explicitly restore a private lab backup.

The common workload establishes five fabrics, three live CASE sessions/fabric,
15 subscriptions to one Hue path, seven explicit Read paths, NodeLabel writes,
OnOff/Level/HS invokes, six update rounds, and readback. Every subscription must
observe Hue85 and170. RGB readback permits at most2s for the reference's
asynchronous SDK transition handler; it never shortens protocol timers. The
fixture closes subscriptions/sessions, waits12s for retirement, then creates
fresh CASE sessions and requires successful temporary-fabric removal responses.
NodeLabel is restored, the LED ends off, and the primary fabric is retained.

The final optional argument selects cleanup: `drained` (default), `live`, or
`local-close`. `live` removes each temporary fabric through one of its three
still-open CASE sessions, reads through every surviving session, and requires
fresh Hue updates on all surviving subscriptions after every removal.
`local-close` closes only local subscription listeners, waits2s, and removes
through the existing sessions while server exchanges may still owe ACKs.
Both variants require four successful RemoveFabric responses and record their
latencies. These are transport regressions; they do not shorten Matter timers.

Full wildcard inventories are recorded separately (the models differ). A
seven-path subscription workload exhausted the stock reference's shared path
pool; that failure is retained rather than increasing its limits. Our custom
OOM, RX-loss, reconnect and held-TX drain controls remain a separate C-only
regression, not a matched fault-injection test of ESP-Matter or official CSA.
