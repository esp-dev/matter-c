# CSA15: Wi-Fi removal and two-network migration

## Official acceptance and fixture

The DUT is the unchanged CSA14 binary, built from the sources committed as
`9d88156`. No C source, public API, storage format, resource limit, PICS value,
official script or assertion was changed for CSA15.

| Case | Run | Result | Observation |
| --- | --- | --- | --- |
| TC_CNET_4_9, initial fixture | 331 | FAIL | Effective Wi-Fi SSID is empty; 1 failed, 23 pending, 1 passed record |
| TC_CNET_4_9, corrected fixture | 332 | PASS | All 25 records pass, including removal, rollback and CommissioningComplete |
| TC_CNET_4_11 | Not rerun | BLOCKED in this environment | No TH Wi-Fi interface or wpa_supplicant; earlier official FAIL, run 168, is retained |

TH v2.15.1+summer2026, SDK
`e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`, and the endpoint 0 PICS are unchanged.
Both selected script hashes match CSA01. The cumulative official-result matrix
is **90 PASS, 15 FAIL, 21 BLOCKED, 32 MANUAL, 704 NA**. The current environmental
block on 4.11 is recorded separately; it does not erase its historical FAIL or
invent a new official run. All unselected rows are inherited.

### Why SSID was missing

The installed framework's `runner.py` copies `wifi_ssid` and `wifi_passphrase`
into test configuration only when the effective commissioning method is
`ble-wifi` or `nfc-wifi`. Thus supplying `--wifi-ssid` and `--wifi-passphrase`
with the automatically generated `--in-test-commissioning-method on-network`
still leaves `get_wifi_ssid()` empty in 4.9. Run 331 reproduces this before any
test-body command reaches the DUT.

The corrected project fixture uses these explicit test parameters:

```text
wifi-ssid: testharness
wifi-passphrase: wifi-password
in-test-commissioning-method: ble-wifi
```

These are public simulator values, not real access-point credentials. The DUT
starts with `--wifi-sim-connected` and a fresh isolated store. Actual initial
commissioning remains **on-network**. The final explicit in-test option takes
precedence over the generated one and allows the existing parser to retain the
Wi-Fi parameters. TC_CNET_4_9 performs no in-test commissioning, so this does not
exercise BLE or change the tested commands. The project configuration is restored
and checked after the run. Do not apply this override blindly to tests that do
commission inside their body.

Core 1.6.1 sections 11.9.6.6-8, 11.9.7.6-9 and 11.10.7 define the relevant
network status, removal/connection responses and fail-safe/commit behavior.
The installed 4.9 arms its fail-safe before modifying networks; unlike the open
4.4 discrepancy, no server guard needs to be relaxed for it to pass.

## TC_CNET_4_11 boundary

The installed script operates the controller's real network: it removes LAN
default routes, uses a wpa_supplicant control socket, changes the TH connection
between two APs, renews IP configuration and rediscovers the DUT. Preflight found
zero wireless interfaces and no `/var/run/wpa_supplicant` on the TH VM. The DUT's
two simulated AP records do not supply this controller-side infrastructure.

Required before an unmodified official rerun: an isolated TH environment with a
working Wi-Fi adapter/wpa_supplicant, two reachable APs, and a DUT transport that
actually follows the selected Wi-Fi connection. Alternatively, a separately
validated virtual radio/network environment must exercise those transitions.
Provide the primary SSID/password and
`PIXIT.CNET.WIFI_2ND_ACCESSPOINT_SSID` /
`PIXIT.CNET.WIFI_2ND_ACCESSPOINT_CREDENTIALS` for that environment. Merely setting
the PIXITs does not satisfy the missing transport precondition.

The script was not patched to bypass network switching, and its networking
commands were not replaced with successful stubs. A local simulator scenario
must not be reported as TC_CNET_4_11 PASS. Physical Wi-Fi association, IP changes,
DHCP, discovery across APs and BLE commissioning remain unverified.

## Supplementary regression

`tools/matter/tests/chip_tool_three_phase.py` extends the existing opt-in
`--wifi-sim-connected` pair scenario. On both complete runtimes, it checks:

- Exact Networks list contents and connection flags after removal/addition.
- Wrong-password rejection, LastConnectErrorValue and unchanged Breadcrumb.
- Connection to the second simulated AP, cleared connection error and Breadcrumb.
- Rollback to the original network after ArmFailSafe(0).
- CommissioningComplete followed by ArmFailSafe(0) preserves the second network.
- Modifying one runtime leaves the other runtime's network unchanged.

Both runtimes retain their existing CASE/subscription and selective teardown
checks. This exercises configuration commit within the running process; it is
not a new restart/power-loss test. The C binaries and their prior native-build
evidence are inherited from CSA14; only the external Python oracle changed.

The expanded full scenario passes under **Memcheck**, then separately under
**ASan/UBSan/LSan with reverse commissioning order**. Both runs finish all eight
scenario checks and both runtimes exit successfully. Memcheck reports **0 errors,
0 bytes/blocks at exit, 49,628 allocations/frees and no suppressions**. The
sanitizer run exits without diagnostics. All 353 C/header files and the normal
and sanitized binary hashes still match CSA14. No new C build or native CTest
run was necessary for this Python-only change.

The first lab copy missed the runner's `test_mdns_linux.py` dependency and failed
before starting a DUT. The first expanded oracle used the wrong CHIP command
spelling (`wifi` instead of `wi-fi`); that Memcheck scenario failed, and the
following sanitizer attempt was stopped. Those setup logs remain local. The
results above refer only to the corrected, complete runs.

Executed verification, with private fixture paths supplied explicitly:

```sh
# Unmodified official TC_CNET_4_9 through TH; two fixture attempts above.
python tools/matter/tests/test_discovery_startup_linux.py --exe /path/to/runtime-pair-host --chip-tool /path/to/chip-tool --paa /path/to/paa --credentials /path/to/credentials --interface INTERFACE_INDEX --output /path/to/new-results --mode memcheck --wifi-sim-connected
# Then separately: sanitized executable, new output, --mode sanitize --reverse.
python -m py_compile tools/matter/tests/chip_tool_three_phase.py
python tools/matter/check_test_map.py
git diff --check
```

Inventory passes: 228 mapped files, 85 native definitions, 59 core sources and
75 public headers. Python compilation and diff checks pass. Windows, Google
Test Suite, physical devices/radios and firmware integration were not retested.

Build/test artifact hashes, attempts and limits are in
[the result delta](csa15-results.json). Lab paths, addresses, state and raw logs
remain ignored. No report was sent externally and no CSA waiver was obtained.
The roadmap records a possible future compile-time compatibility mode only
after unresolved discrepancies have been reported and discussed with CSA.

**Next: CSA16 - TC_CADMIN_1_10, commissioning-window behavior after successful PASE.**
Keep CNET 4.4 pending specification/test resolution and CNET 4.11 pending a
suitable network fixture; return to both in the next acceptance iteration.
