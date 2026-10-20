# CSA70: distinct attestation credentials on two native instances

**Original TC_DA_1_7 passes: run611 under Memcheck and run612 under separate
ASan/UBSan/LSan,18/18 TH entries each.** A deliberate cloned-DAC control,
run610, fails only the final key comparison after both DUT chains are examined.
No native implementation, original test, PICS or assertion changed.
[Receipt](csa70-results.json) records the original outcomes, evidence fingerprints,
memory results, earlier attempts and limits.

## Reused evidence and actual prerequisite

CSA01 run172 failed before the test's commissioning step because only one setup
payload/discriminator was supplied. The test explicitly requires two during
certification-time execution; its alternative single-DUT flags are not a
uniqueness test. The saved record still matches matrix SHA-256
`d1680c0fac715f27432b67f4c2334636f594a17a8b2443bed706e957f5f8e4c6`.
No key comparison was reached in that run.

Read-only inspection reconfirms installed `TC_DA_1_7.py` SHA-256
`c71532d1ca884b3063a7def69f4bf0238a6179f947091147482c41bbda731af2`,
identical to CSA01 and the CSA69 inspection. The missing fixture is now supplied,
rather than repeating the one-DUT failure or selecting `allow_sdk_dac` or
`post_cert_test`. Both remain false; PICS_SDK_CI_ONLY remains false. PICS stays
`bf5469cb96f6ea195c70db1de32d922207f6e2c62065aa1dbaf3ec0418a19600`.

## Two instances and meaningful negative control

The fixture creates one fresh random laboratory PAA, one PAI and two random
P-256 DAC keys, with distinct DAC subjects and serials. Both DACs have the same
test VID/PID. Private scalars stay only in new0600 files inside0700 credential
directories on the test host. Existing paired-device keys/stores are untouched;
no private key, public certificate or full SDK source is committed.

Each live host has its own port, discriminator, node ID, credential directory
and persistent store. The original TH commissioning/test commands receive two
setup payloads and two DUT node IDs. A temporary scoped PAA is placed in the
mounted trust store for these runs and removed afterwards. Development CD reuse
does not assert production identity; the separate DA1.2 VID prerequisite remains.

| Run | Fixture / execution | Original result |
| --- | --- | --- |
| 172, historical | One DUT | FAIL before uniqueness checks |
| 609 | Wrong inherited PAA path in project setup | Suite ERROR; case CANCELLED,18 cancelled entries |
| 610 | Two hosts using the same DAC-A, both under Memcheck | Expected FAIL:17 passed, final key comparison failed |
| 611 | Two hosts using distinct DAC-A/DAC-B, both under Memcheck | PASS18/18 |
| 612 | Same distinct identities, fresh stores, separate sanitized hosts | PASS18/18 |

Run609 exposed an inherited fixture setting pointing at an older laboratory
PAA store. Only this new project's trust-store path was corrected. The test,
assertions, PICS and host binaries were unchanged. Its ERROR/cancelled outcome
is retained and is not called an attestation uniqueness failure.

Observed public-key SHA-256 values from original test logs match the provisioned
pair exactly. The negative has two occurrences of DAC-A; positives contain one
DAC-A and one DAC-B. Both DUTs' PAI signature validations appear in every final
run. Thus merely opening two ports with one shared identity does not obtain PASS.

An additional collector initially assumed observations must be ordered A,B;
run611 legitimately reported B,A. That collector failure is retained in the
receipt. The corrected collector requires the exact multiset of two expected
keys, preserving duplicate multiplicity in the negative control. No original
test, assertion or result was changed, and no TH run was repeated for this fix.

## Memory and binary identity

The two binaries are the exact CSA67 normal/sanitized binaries. Tracked C/H
inputs have no changes since that acceptance; no new build or focused CTest
execution is claimed. Both variants execute the full original two-DUT scenario.

| Run | DUT | Memcheck allocations/frees | Errors / live blocks |
| --- | --- | --- | --- |
| 610 | 1 | 30733/30733 | 0/0 |
| 610 | 2 | 30729/30729 | 0/0 |
| 611 | 1 | 30691/30691 | 0/0 |
| 611 | 2 | 30710/30710 | 0/0 |

These counts are cumulative heap activity, not peak RAM usage. The two native
processes in run612 stop cleanly with empty sanitizer stderr, detect_leaks=1
and halt_on_error enabled. No Valgrind or debugger is combined with sanitizers.
The earlier run609 also has clean native exits and zero Memcheck errors/live
blocks, recorded separately from successful acceptance.

TH initially had no Valgrind. Ubuntu Valgrind3.22.0 and the exact matching
libc6-dbg package were downloaded and extracted only inside the local stage
directory, without sudo, system package installation or libc replacement.
Valgrind then needed its local search path mapped to the matching loader's
`.gnu_debuglink`; the unsuccessful smoke/start attempts are retained. They
preceded native execution or TH submission and are not new CSA outcomes.

## Standards and qualification limits

Matter Core R1.6.1 section6.2.2 requires a device-unique DAC and private key,
unique certificate subjects per issuer, and a chain to an approved PAA. These
simulations demonstrate distinct credentials and actual rejection of duplicated
keys by the original automated case.

**Production PAA approval and DCL provenance are not established.** The installed
script loads its configured PAA directory, verifies the PAI signature, rejects two
SDK root identifiers and compares DAC keys. It does not query DCL or prove the
root's approval. Our scoped laboratory root is not presented as an approved
production PAA. Passing this automated case does not establish manufacturing key
injection security, population-wide uniqueness, production provisioning, physical
device certification or DA1.2 acceptance.

## Reproduction and final state

Use two independently generated, valid laboratory credential directories and
isolated node stores. Launch the same native binary twice, with different
`--port`, `--discriminator`, `--credentials` and `--state` inputs. On the separate
TH project, supply both discriminators/passcodes and both `dut-node-id` values;
select the PAA trust store containing their chain root. Keep original tests,
PICS and the two single-device bypass flags unchanged.

For a manual repeat in the installed th-cli Python environment, use the existing
exact-selection runner and answer the commissioning prompts:

```sh
python tools/matter/th/run_exact.py --project-id PROJECT --tests-list TC_DA_1_7 \
  --title RUN_TITLE --no-color --no-streaming
```

The laboratory launcher selects the exact Python collection/case to avoid CLI
alias expansion and answers only commissioning readiness prompts. It supplies no
verification PASS. Use the normal host under full Memcheck with origins and
error-exitcode99, then a separate sanitized build with leak detection. Repeat
the negative control with both hosts deliberately using the same credential set;
require failure specifically at final key comparison, not during commissioning.

Public evidence checks:

```sh
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
python tools/matter/check_test_map.py
git diff --check
```

All six final-run native lifetimes ended cleanly; no stage node process remains.
The temporary trust-store PAA was removed after an exact hash check. TH is idle,
original source unchanged, and paired Windows nodes untouched. Raw logs, new
credentials, project configuration and administrative helpers remain ignored.
TH timestamps in the receipt are UTC.

Only TC_DA_1_7 changes FAIL to PASS; original172, ERROR609 and expected-negative610
remain visible. Counts become **123 PASS/27 FAIL/5 prerequisites**. Other tests
are inherited, not rerun; no physical/Windows execution or whole-matrix acceptance.

Next: **CSA71**, consolidate the generic TC_SU_4_1 triage using CSA27 evidence and
current original script/helper identity. Do not repeat its known full failure
without a changed prerequisite or distort native list-operation statuses.
