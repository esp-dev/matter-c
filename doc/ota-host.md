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

For an explicit application query opportunity, start `matter-node` with
`--ota-control` alongside credentials and `--ota-file`. Its private stdin pipe
accepts `ota-query` and `stop`, one command per line; EOF requests a clean stop.
There is no new network command or automatic query on startup. The node prints
`OTA_LOCAL_QUERY result=N`; zero means scheduled, three means busy. The selected
provider must already come from the normal authenticated Requestor model. Rate
limits, provider delay, urgent jitter and Busy/error backoff remain enforced.
The option is disabled by default and does not alter existing GUI control.

The independent runner's `--local-query` uses UpdateAvailable announcements and
then issues this explicit application action after selection. It does not rewrite
the announcement reason or install DefaultOTAProviders. For example, combine
`--mode busy-180 --events --require-trace --local-query --valgrind` for a complete
two-boot memory scenario; repeat separately with a sanitizer node. The local
action and its result must be recorded when this fixture is used with original
CSA procedures. It is an additional documented application precondition, not an
undisclosed change to the original test or a production scheduling default.

After accepted simulated installation, `matter-node` keeps its normal event loop
running until the Applying event's confirmation cursor has drained, or at most
30 seconds. This is a host lifecycle policy, not a Matter-mandated delay. It logs
`OTA_REPORT_DRAIN ready=1|0 waited_ms=N` before `OTA_SIM_REBOOT`; zero records an
expired host wait and must not be interpreted as delivered. Other shutdown causes
still take precedence. No new query or install authorization is introduced.

The OTA runner's `--events --event-min-interval 5` uses a real nonzero subscription
interval to expose premature shutdown. Positive updates must capture the live
Downloading -> Applying event before restarting, independently of the post-boot
history read. The interval option accepts the protocol's uint16 range; intervals
beyond the host wait can intentionally leave delivery incomplete and fail this
positive acceptance. Report such a timeout separately from successful delivery.

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

`Matter_Runtime_Ota_Port_T.progress` is an optional synchronous application
callback for the active download: -1 means unknown and 0..100 is nearest integer
percentage complete. It must not block, perform I/O or reenter the runtime. Invalid values
are exposed as unknown. Consumers must rebuild and zero-initialize omitted
callbacks. The file adapter derives progress from validated whole-file size and
received bytes, without extra file reads. The runtime publishes changed integer
percentages through the existing Requestor attribute and normal IM scheduling;
it does not emit a StateTransition event for each percentage. The published
progress becomes null after the transfer ends. The port retains the terminal
snapshot through sink cancellation until the next prepare, so DownloadError
can report known progress. The host uses `matter_ota_file_last_progress()` for
this snapshot; the older `matter_ota_file_progress()` API still reports unknown
after commit/cancel. Other application sinks remain independent of the file adapter.

Query retry timing and state indication are separate. An unsuccessful query
waits in Idle during its existing bounded backoff; DelayedOnQuery denotes a
Busy response. A successful delayed UpdateAvailable response also waits in Idle
until download starts. Neither correction changes the global 120-second query
floor, provider delay, retry backoff or ApplyUpdateResponse policy.

With an immediately usable image, query handoff publishes Downloading directly;
successful download handoff publishes Applying directly. No transient Idle is
inserted while the update is still in progress. An owner that declines a query
handoff must publish Idle itself; the runtime does this on prepare/dispatch failure
or an unsupported image. Error/cancellation paths still return to Idle.

`--events` subscribes to OTA events before announcement and checks actual
StateTransition fields, VersionApplied versus fresh Basic Information, and
DownloadError byte count/nearest percentage for interruption scenarios. Use
`--mode query-timeout --events` with the ordinary provider's ignore-query option
to check the failure-to-Idle event without terminating the peer. For a real BDX
Idle timeout, supply the separate [stall provider](../tools/matter/patches/README.md)
via `--stall-provider` with `--mode interrupt-retry --events`; it keeps MRP alive.
Provider termination remains a separate fault scenario. Neither changes the
requestor's clock, MRP behavior or 300-second BDX idle timer.

For TC-SU-2.4 use `--mode update --apply-binding --image-version 2`, then a fresh
fixture/output directory with `--image-version 3`. This enables peer JSON traces
and compares the UpdateToken bytes and NewVersion received in ApplyUpdateRequest
to the latest UpdateAvailable QueryImageResponse and the authenticated image.
NotifyUpdateApplied is checked against the same token/version. Published results
contain only the token length and SHA-256, not the token itself. The official
provider does not validate this binding for us; the independent trace oracle does.

For TC-SU-2.6, the same `update --apply-binding` modes with image versions 2 and
3 exercise Notify after simulated restart. Compare the decoded command's token
to the latest Query/Apply and its version to fresh CASE Basic Information; check
BootReason SoftwareUpdateCompleted as well. Use separate fresh fixtures for
Memcheck and sanitizers. The installed TH case is a manual YAML procedure:
record its verification and evidence upload separately from automatic tests.
One observed Notify in a loss-free run does not prove behavior under a missing
response. The runtime durably claims the notification context before dispatch;
Core 11.20.3.6 prohibits application retry if no response is received, while MRP
retry remains within the same exchange. See [CSA25 evidence and limits](oss/csa25-validation.md).

The `version-mismatch` mode offers/header-encodes version 3 but signs version 2
inside the simulation payload. It requires authentication rejection, no Apply or
Notify, no simulated reboot, and fresh CASE readback of the original version 1.
Run these with the normal host under Memcheck and separately with sanitizer
binaries. These extend the fixture; they do not add production image formats or
change OTA authorization. See [CSA22](oss/csa22-validation.md).

For TC-SU-2.5, use fresh output/state directories with each of
`--mode apply-proceed-0`, `apply-proceed-180`, `apply-await-60`,
`apply-await-180` and `apply-discontinue`. These enable JSON peer traces and
the provider's unchanged `--applyUpdateAction` / `--delayedApplyActionTimeSec`
options. That provider returns the chosen action/delay on the first Apply only;
later replies are Proceed/0. No clock is accelerated. Proceed/180 waits 180 real
seconds; Await/60 waits at least 120, and Await/180 at least 180 before retry.
During delayed application, Basic Information must still report version 1.
The runner compares response-receipt and installation-gate monotonic ticks for
Proceed, and the independent provider's response-send/retry-receive timestamps
for Await. Both paths require the latest token/version, one Query/BDX and no
extra Apply after Proceed, including after the simulated restart/Notify.

Discontinue uses a nonzero 180-second delay to check that it is ignored. The
candidate must be disposed before the independent Idle read, without install or
Notify during a further 15-second observation; version 1 remains installed.
The host's discard callback rejects zero/stale IDs and IDs from a restarted
instance. Removal errors revoke the logical candidate and are reported; no
silent cleanup success is claimed. Cancellation/ordinary invalidation keep
their existing separate semantics. The file path is application-owned and must
not be shared or replaced by other writers during artifact use.

Run the five scenarios under Memcheck, then a separate sanitizer build for the
full Await/retry/update/restart path and Discontinue cleanup. The native Apply
tests separately cover malformed responses, timeout/cancel/drain, the 24-hour
delay cap, clock overflow, publication failure and generation changes. These
are laboratory regressions; the five official verification prompts and evidence
upload remain manual TH acceptance. See [CSA23](oss/csa23-validation.md).

The installed case is **TC-SU-2.1**, SDK YAML Tests / FirstManualSuite, not an
automatic Python `TC_SU_2_1` test. Its three disabled YAML steps become manual
verification prompts in TH; they are not discarded by its manual runner.
Run the official case unchanged, evaluate each prompt against captured evidence,
and attach the laboratory log. A manually entered TH result remains manual
acceptance; the Python scenario is supplementary automation, not a replacement
for CSA assertions or certification. See [CSA19 evidence](oss/csa19-validation.md).

For QueryImageResponse coverage with `UpdateAvailable` announcements, add
`--default-provider` to `test_ota_chip_provider.py`. This optional fixture writes
and reads back DefaultOTAProviders after subscribing to events, then announces
with reason1. Configuring the default supplies an initial query opportunity;
repeated reason1 announcements retain the normal query/retry schedule. Without
the option, the existing SimpleAnnouncement route (reason0) is unchanged.
Neither route shortens the requestor's 120-second floor or provider delays.

Use fresh directories for `update` (Memcheck, then separately sanitizers),
`busy-60`, `busy-180`, `not-available`, `invalid-uri` and `same-version`, with
`--events --default-provider`. Actual peer trace fields and state transitions
are checked, not just the provider CLI arguments. These independent scenarios
do not replace the unchanged automatic TC_SU_2_2 result; see
[CSA28](oss/csa28-validation.md). The optional runner requires Python cryptography
and the existing Linux laboratory dependencies.

For recovery after a provider loses its CASE session, use fresh disposable state
with `--mode query-restart --events --event-min-interval 5 --local-query
--require-trace --apply-binding --bdx-profile`. The runner kills only its own
provider child after the requestor receives Busy/60, then starts a new provider
with the same image and KVS. The old session must fail without a decoded response
or download. Reannouncing and requesting a local query must preserve the native
second-failure backoff of 240 real seconds; this value is policy, not a normative
Matter timeout. The requestor process remains alive throughout recovery.

The replacement peer's trace must show either Sigma1/Sigma2/Sigma3 or a resumed
Sigma1/Sigma2Resume/Success exchange. A restarted provider can retain resumption
material in KVS while losing active sessions. The responder SessionID is matched
to the subsequent encrypted QueryImage; merely obtaining a different numeric
SessionID does not prove new CASE. The
scenario then checks exact BDX bytes/counters/EOF, token/version binding, signed
simulated installation, live Applying, restart, Notify and fresh CASE readback.
Run first under Memcheck, then separately ASan/UBSan/LSan. These are independent
fault/recovery checks and cannot replace the original TC_SU_2_2 outcome.
