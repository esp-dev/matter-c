# Native desktop acceptance

## English interface and icon update

The desktop frontend now uses English labels/messages and an embedded transparent
slate/teal energy icon, generated with the built-in image tool. Source, exact
prompts and ICO conversion metadata are in `tools/matter/host/assets`. The ICO
contains nine RGBA sizes (16–256 px); PNG/ICO alpha and transparent corners were
checked. All application window classes use large/small resource icons.

MinSizeRel desktop compilation and `test_gui_pairing` CTest pass. Native UI
inspection confirms English manager/simulator/Settings labels, the window icon,
two restored fabrics and the retained source value. The local settings file is
byte-identical before/after the update. Windows/UCRT-only imports and the source
inventory check pass. Windows-owned system UI can retain the OS language.

Only Win32 presentation/resource code changes in this update. Portable stack,
worker protocol, persistence schema and Linux-compiled C sources are unchanged;
the earlier Memcheck/sanitizer/controller results below are retained evidence,
not new runs for this UI update. No new CSA or ecosystem acceptance is claimed.

### Explorer launch and profile recovery

An actual Explorer launch initially showed an empty node list. The same EXE
started through development tools restored a sensor, despite displaying the
same nominal LocalAppData path. Explorer showed only `manager.lock` there;
the tool environment also saw `settings.ini` and a node store. This exposed
different filesystem views, not a working-directory-dependent INI lookup.

The preserved settings and opaque node store were copied, without lock files,
through an ignored staging directory into the interactive user's profile using
Explorer. Staged copies were hash-checked against the originals. Two subsequent
Explorer launches, separated by a graceful manager shutdown, restored one
simulator at +4301 W and two fabrics with the pairing window closed. No reset,
recommissioning, persistence-schema change or application-code change was
needed. Actual Apple/Google reachability after this recovery was not checked.
Tool-launched restoration alone is insufficient evidence for interactive
Windows profile restoration in an isolated development environment.

The portable library API is unchanged. Host simulation options append an optional
copied UniqueID, requiring host consumers to rebuild. Existing callers retain
their DAC-hash identity; GUI instances sharing test credentials use persistent,
independent identities. QR images use unmodified Nayuki v1.8.0 C sources (MIT),
with upstream commit/hashes and retained licenses in third_party/qrcodegen.

## Executed checks

```sh
python tools/matter/tests/test_gui_host_chip.py \
  --exe build/normal/matter-node \
  --payload-exe build/normal/cmake/tests/test_gui_pairing \
  --chip-tool /path/to/chip-tool --credentials /path/to/development-credentials \
  --paa /path/to/development-paa --interface 2 \
  --output build/desktop-memcheck --memcheck
```

Repeat against the separate sanitized build, without Memcheck and with a new
output directory. Use disposable laboratory state, never a paired household node.

Two concurrent workers pass commissioning with verified development attestation,
exact sensor cluster inventory, distinct UniqueIDs, signed Read/Subscribe at
±10 kW, zero and another negative value, and isolation from the second peer.
Invalid/overflow/unknown/oversize commands preserve state; partial lines commit
only after completion. Restart retains pairing/identity and fresh CASE works.
Last-fabric removal returns its success response before exit; the other worker
remains live. EOF exercises clean shutdown. C-generated QR payloads match CHIP
363 for low/high valid onboarding vectors. Early runner corrections replaced a
reserved VID with test VID 0xFFF4 and fixed `statusCode` capitalization; protocol
behavior was not changed to satisfy those assertions.

Final Memcheck: 36 checks, three boots, 59064 matched allocations/frees, zero
errors/live bytes. Separate ASan/UBSan/LSan: 33 checks, three boots, empty diagnostic
stderr. Eight focused CTests pass on Linux and its sanitizer build (root,
IM Read/Subscribe with allocation variants, energy/switch simulators, QR).
Windows QR CTest passes; native desktop/CLI compile with warnings treated as
errors. Inventory checks pass: 234 mapped files and 87 native definitions.
This is not a full suite run. Tested backend binary hashes are recorded in
[desktop-results.json](desktop-results.json).

The native manager, integration choice, QR and slider were visually inspected.
Releasing the slider confirmed +10000 W and −10000 W; configuration/value restore
after manager restart. The first UI pass found that Win32 INI cache flush returns
zero even on success. That assumption was fixed; subsequent node creation and
restart preserve settings. The frontend hides stale QR/status and clears fabric
indication after last-fabric reset. The MinSizeRel stripped EXE imports only
Windows/UCRT system DLLs, with no MinGW DLL dependency.

## Limits and next task

Linux sanitizers do not cover Win32 painting/persistence code. Exhaustive Win32
heap/GDI stress, power-loss durability, 54-node load and automated Apple/Google UI
acceptance are unperformed. External credentials stay local; the pre-existing
standalone sensor is outside this profile and remains unchanged. The CSA matrix
and next CSA24 task are unchanged; these results are not certification.

Next: manual ecosystem pairing of the desktop build, then CSA24. REST adapters
remain a separate later feature.
