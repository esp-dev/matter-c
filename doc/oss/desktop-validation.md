# Native desktop acceptance

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
