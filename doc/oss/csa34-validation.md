# CSA34: Commissionable Node announcements

CSA33 was committed as **`12c04ea`**. Original **TC-DD-2.1** finishes **manual
FAIL in TH run468**: eight entries PASS, seventeen NOT APPLICABLE and one FAIL
at Step15a. The operator reviews retained real x86/controller/wire observations;
TH records that review rather than driving the standalone controller itself.
This campaign uses the unchanged declared IP profile.
The discovered **missing PH in CM=0 is an implementation gap**, distinct from
CSA32's contradictory procedure text. Original source and PICS are not changed
to hide the finding.

## Wire and controller scenario

The new `test_commissionable_announcement_chip.py` uses a disposable full-profile
node and independently encodes/decodes IPv6 multicast DNS messages:

1. Before manufacturer CLI start, its long-discriminator subtype is absent.
   Capture starts before the node, and observes an unsolicited announcement
   before any post-start query from this fixture.
2. In the basic window, check the instance/host formats, PTR/SRV/TXT, port,
   all IPv6 addresses on the selected interface, D/CM, service enumeration,
   long/short discriminator subtypes and _CM. Unmodified chip-tool performs
   unfiltered `discover commissionables`; its own complete result block must
   match this instance, discriminator, port and mode, rather than another node.
3. Commission with the C-generated on-network payload. Verify attestation and
   SendComplete. In CM=0 check the same discovery records and discriminator
   subtypes, absence of _CM in enumeration and direct lookup, and a fresh
   unfiltered chip-tool discovery result.
4. Through CASE, open an enhanced commissioning window. Verify CM=2, the new
   discriminator, a new instance name, withdrawal of the previous instance,
   correct SRV/AAAA/TXT, all required subtype responses and chip-tool discovery.
5. Stop and collect host stderr, Memcheck and separate sanitizer results. Raw
   packets, state, setup material and controller stores stay outside Git.

The required-PH predicate is separate from the functional discovery predicates:
it records FAIL and allows the rest of the coherent scenario to complete. It
does not turn the scenario into PASS because transport, cleanup or memory pass.

The complete normal run passes **37 functional checks under Memcheck** and the
separate sanitizer run passes **36**, but **both overall validations remain
FAIL** at the required-PH conformance check. Memcheck reports **23,960 allocations
and 23,960 frees**, zero errors and zero live bytes. Both host stderr files are
empty; ASan/UBSan/LSan produce no diagnostics. Disposable processes are stopped
and TH is idle. Original YAML/PICS, operator answers, raw result/log hashes and
accepted driver/node identities are in the [result record](csa34-results.json).

Three exploratory fixture failures remain retained: a standalone chip-tool
command incorrectly received an interactive-only option; the parser expected a
different discovery-block heading; and a negative _CM assertion counted unrelated
base/discriminator PTR replies for the same instance. The corrected predicates
keep the required instance/discriminator/port/mode checks and inspect the actual
_CM record owner. Packet evidence showed no positive _CM in the closed state.
No DUT code or original assertion was changed to correct these fixture errors.

## Normative finding and profile gap

Core R1.6.1 **4.3.1.2** calls advertising Commissionable Node Discovery outside
commissioning mode Extended Discovery. **4.3.1.11** requires PH in that CM=0
state. The actual record contains only D and CM=0. The discovery builder has two
TXT entries, and the host republishes that record after commissioning. This is
not inferred solely from an example log or an undeclared optional PICS flag.

Core **4.3.1.3** forbids _CM outside commissioning mode. That behavior passes:
the closed publisher has only long/short discriminator subtypes, while both
open modes also have _CM. Core **4.3.1.6** explicitly makes VP optional; its
absence is not a failure. Values from reference-app examples are not imposed
on this device.

The frozen PICS omits EXTENDED_DISCOVERY and optional TXT/subtype declarations.
Nevertheless, the running host actually publishes CM=0. The missing declaration
does not waive its conditional normative PH requirement. The original optional
PH step is outside the declared optional branch; the unconditional Step15a
discovery record is evaluated against the actual CM=0 state. The result record
retains the operator decision and unchanged PICS identity.

The host's customer-facing policy for limiting/disabling Extended Discovery also
needs review under 4.3.1.2. This campaign does not accept such a control merely
because the executable can be stopped or given a total process lifetime. This
is a follow-up policy/coverage gap; its runtime behavior was not implemented or
accepted here.

Step15b says to leave commissioning mode but includes an example containing
_CM. The actual query is exercised in closed and open modes: long/short subtypes
are present, and _CM is conditional on the mode. Unlike CSA32's explicit CM=0
verification, an illustrative _CM line is not treated as a requirement to violate
4.3.1.3. Step16a's enhanced CM=2 window is a valid commissioning mode; the example
CM=1 value is not a requirement to use a basic window.

## Reproduction and limits

The matrix row stays category MANUAL with manual_result=FAIL. Category totals
remain **97 PASS, 18 FAIL, 3 BLOCKED, 40 MANUAL, 704 NA**. The manual category now
contains **11 PASS, 2 FAIL and 27 without an outcome**. No other row is rerun or
reclassified by this campaign.

```sh
python tools/matter/tests/test_commissionable_announcement_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --payload-exe /path/to/C-payload-utility --paa /path/to/development-paa \
  --credentials /path/to/development-credentials --interface 2 \
  --output /path/to/fresh-private-memcheck --valgrind
# Repeat separately with the sanitizer executable, without --valgrind.
# A conformance failure intentionally returns a nonzero exit code.
python -m py_compile tools/matter/tests/test_commissionable_announcement_chip.py
python tools/matter/check_test_map.py
git diff --check
```

BLE advertisement timing and Wi-Fi PAF are outside this declared IP profile;
their original guarded branches receive NOT APPLICABLE, never PASS. The test
does not validate physical Wi-Fi, multiple physical interfaces, Home app UI,
printed labels, embedded RAM fit or certification. Runnable native sources and
binaries are unchanged CSA30 builds; only a new controller fixture and evidence
are added. Existing paired Windows instances are untouched. CSA30 remains
deferred and CSA32's separate discrepancy remains open.

Next: **CSA35 — Extended Discovery PH and customer policy**. Supply truthful
pairing hints for the actual host methods, provide an explicit privacy control,
review PICS against the resulting behavior and rerun the affected original
discovery procedures plus this full wire/controller scenario.
