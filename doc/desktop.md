# Native Windows desktop

`matter-desktop.exe` contains the C/Win32 manager, simulator windows and C node
workers. No Python, Node.js, Qt or MinGW DLL is needed at runtime. Windows/UCRT
system libraries remain dependencies. Initial frontend target: Windows 10 1903+
(UTF-8 process manifest) and Windows 11. This is an experimental host, not a CSA
certified product. Linux retains the CLI and backend acceptance scenario.

Application labels, status and error messages are in English. Native Windows
system UI, such as a folder picker, can still follow the OS language.
The EXE and window icons share an embedded transparent slate/teal energy mark,
with nine ICO sizes (16–256 px). Source PNG, generation prompts and file hashes
are retained in `tools/matter/host/assets/icon-source.json`. The source asset
is not needed alongside the executable at runtime.

## Build

First configure the compiler and official Mbed TLS as in the root README.

```powershell
cmake -S . -B build/desktop-release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build/desktop-release --target matter-desktop -j 3
strip --strip-unneeded build/desktop-release/matter-desktop.exe
& ./build/desktop-release/matter-desktop.exe
```

Retain LICENSE/NOTICE and third-party licenses with a distributed binary.
Development attestation credentials intentionally remain external to the EXE.

## Setup and workflow

**Settings** selects the credentials directory (`dac.der`, `pai.der`, `paa.der`,
`dac-key.bin`, `cd.der`) and the IPv6 interface index (`Get-NetAdapter`). Identity
is fixed to test VID `0xFFF1` / PID `0x8001` and must match the DAC/CD. Vendor and
Product names accept the same CMake settings as the CLI host. The default
`strict` policy checks operational certificate dates; explicit `chip` retains
the existing time-period compatibility policy, preserving signature/trust/profile
checks. Settings take effect on the next node start. The existing simulated
Wi-Fi model does not configure the computer's Wi-Fi.

No Google account ID is stored. Test devices need the corresponding VID/PID
integration in Google Home Developer Console, with the appropriate account/hub.
Many simulated units share one product identity, with independent device state.
See [Google integration setup](https://developers.home.google.com/matter/integration/create)
and [pairing guidance](https://developers.home.google.com/matter/integration/pair).

For inbound networking, run once from an elevated PowerShell with explicit paths:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/matter/Setup-DesktopNetwork.ps1 -Executable C:\path\matter-desktop.exe -InterfaceAlias "My LAN adapter"
```

This permits only that EXE, that adapter, UDP 5353/5546–5599 and LocalSubnet.
Other nodes' rules and the permanent execution policy are unchanged. The desktop
itself runs without elevation. Local control uses inherited pipes, not a network
control server.

1. **New node** opens integration selection before starting a worker.
2. **Power simulator** starts Root 0 and Electrical Sensor 1 with Descriptor,
   Power Topology and EPM. This desktop profile has no On/Off or EEM registers.
3. Slider preview changes while dragging; release commits one changed value.
   Keyboard tracking completion also commits. The confirmation shows accepted
   power/generation. Positive means import; negative export. The wire uses signed
   mW and an accuracy range covering ±10 kW. This is a change notification for
   attribute subscriptions, not an invented Matter EPM event.
4. QR appears after mDNS publication in the initial open commissioning window.
   Complete, expiry, stale status and process exit hide it. Enhanced windows use
   the sharing code from their controller; the initial PIN's QR is hidden then.
5. **Stop/Start** preserves identity and pairing. Restarting an unpaired
   node opens its initial window again. A paired restart keeps that window closed.
6. **Remove integration** stops the worker and returns to source selection, retaining
   its pairing files and last value. Selecting Simulator again reuses them.
   Controller RemoveFabric is separate: after last removal the reply completes
   and the worker stops, following the existing host behavior. Start it again
   for fresh commissioning.

Closing a simulator window hides the view; its worker keeps running. Closing
the manager gracefully stops its workers. A Windows job prevents orphan workers
after manager crash, which is distinct from graceful shutdown. Each worker is a
process of the same EXE with its own C owner loop, UDP port, mDNS name, UniqueID,
PIN, discriminator and locked store. The portable library contract is unchanged.

## State

Default: `%LOCALAPPDATA%\MatterC`. `--data-dir ABSOLUTE_DIRECTORY` selects another
profile (create its parent first). One exclusive lock protects each manager
profile. Separate profiles must select disjoint ports; a bind conflict fails
instead of taking over another listener.

Versioned UTF-16 `settings.ini` holds local paths, interface/policy, integration,
value and onboarding parameters. It is written/flushed to a same-directory
temporary file before atomic replacement. Node stores are opaque existing TLV
files at `nodes/<instance-id>/state.tlv`. The directory inherits the user's ACL;
protect it as pairing data and keep it out of Git. Invalid settings are rejected
without resetting them.

Port pool 5546–5599 (54 nodes) is application policy, not a Matter limit or a
54-node test claim. Windows stack reserve is 8 MiB. Node/path/QR workspaces are
heap-owned through shutdown. Pipe line/work budgets bound malformed input.

## Later integrations

REST HTTP(S) sources are not implemented. Future application adapters should
validate signed power units/range/freshness and feed the same owner-thread input
boundary. HTTP authentication, polling/backoff and source JSON belong outside
EPM. An availability/freshness input must be added before enabling remote sources;
the current simulator pipe accepts available samples only.

See [acceptance and limitations](oss/desktop-validation.md).
