# CSA69: attestation identity and provisioning prerequisites

**Original TC_DA_1_2 remains FAIL171 at step6.2.** The installed test is unchanged
and the simulation still supplies test VID0xFFF1. This is an identified identity
prerequisite of this test, not a demonstrated native signature defect or test
defect. [Receipt](csa69-results.json) retains source/evidence hashes and limits.
No unchanged full test was repeated.

## Prior finding confirmed

CSA01 already documented that DA1.2 rejects the test VID. Its exact record has
SHA-256 `be43a852ff8d48290d065c456fff33cdf261f0562e6ae77ba6dfc390f8a7fbc1`,
matching the matrix. The retained official log has SHA-256
`ae2fcabbef95f8283003877667a79e3fd1b94507d84ce776e828f853fdac9565`.
Run171 reached CD format_version validation, then failed at line369:

```python
asserts.assert_in(vendor_id, range(1, 0xfff0), "Vendor ID is out of range")
```

The failure detail was65521 (`0xFFF1`) outside1..65519 (`0x0001..0xFFEF`).
It occurs after CD VID equality with Basic Information, before the remaining
CD fields, certificate identity/origin checks, CD signature step9, attestation
nonce/signature checks and later negative controls. Those later checks were
not validated by this run. The TH record has13 passed,1 failed and18 pending
steps; these include harness bookkeeping and are not32 independent crypto checks.

Fresh read-only SSH inspection confirms installed `TC_DA_1_2.py` SHA-256
`e40e0eee6bb7d54ac1fb9e31c71211739f5cc4027c83dc7843aa45c271a0d442`,
identical to the CSA01 snapshot. No source patch, SDK-CI switch or PICS change.

## Test CD and test VID are different policies

The supplied Matter Core R1.6.1, section2.5.2, reserves0xFFF1..0xFFF4 for
test/development. A valid development identity does not establish assigned
manufacturer identity for the original test's non-CI VID assertion.

Section6.3.1 permits a CD signed by a test certificate with certification_type0
for certification testing. Production environments require a CD signed by a
valid CSA certificate. The installed test reflects this distinction:

- Step6.2 excludes test VIDs outside SDK CI.
- Step6.9 permits test/provisional/official CD types during certification testing.
  `post_cert_test` additionally requires provisional/official types.
- Step9 accepts configured development/test CD signers for a test CD, but still
  verifies its ECDSA signature. CD signer trust is separate from PAA trust.

Therefore an official production CD is **not** necessarily needed merely to run
this certification-time test. An authorized assigned VID and consistent test
credentials can remove this particular prerequisite. Simply changing the number
to another vendor's VID, editing an existing signed CD, or enabling SDK CI would
not constitute valid original-profile acceptance. Any alternative development
testing policy needs explicit accepted guidance, not a silent test relaxation.

## Current host and public credential review

Only public DAC/PAI/PAA certificates and the CD were read from the existing
laboratory credential directory. No private key was opened or exported.
Diagnostic DER/TLV decoding of the current public CD gives:

| Field | Value |
| --- | --- |
| format_version | 1 |
| vendor_id | 0xFFF1 |
| product_id_array | [0x8001] |
| certification_type | 0, development/test |
| CD SHA-256 | 0c25d394f40cdbfa51653fe32d8d18a09bc032c2a5d477470893e30f699da951 |

OpenSSL subject inspection also reports DAC VID0xFFF1/PID0x8001 and PAI
VID0xFFF1 without PID. This is metadata inspection, not fresh signature/chain
verification. No certificate bytes are committed. Current files are not claimed
byte-identical to all historical campaign credentials; the same rejected VID is
confirmed independently in the old log and current CD.

The source path explains why rebuilding alone cannot fix step6.2:

1. `tools/matter/host/matter_node.c` sets simulation numeric VID/PID to0xFFF1/0x8001.
   Text branding macros do not change this identity.
2. `tools/matter/host/matter_server.c` loads supplied DAC/PAI/PAA/CD and DAC key
   from the caller's directory; no certificate or CD is issued by the node.
3. `main/apps/matter/runtime/matter_runtime.c` passes Root identity VID/PID into
   the attestation configuration. The reusable runtime accepts caller identity;
   the standalone host's fixed simulation IDs are a separate adapter limitation.
4. `matter_opcreds_host.c` and `matter_attestation_cert.c` check DAC identity,
   certificate chain/profile and key match through ports during construction.
   This source review does not claim a fresh execution of those checks.
5. `matter_opcreds.c` sends the supplied CD in attestation elements and signs the
   elements plus session challenge. Commissioner-side CD verification is not
   equivalent to the node's local DAC chain check.

## Concrete rerun gate

Provide an authorized assigned manufacturer VID/PID and an isolated host fixture
that exposes it consistently in Basic Information and onboarding/discovery.
Supply a CD with the appropriate identity/product list and real verifiable
signature. DAC/PAI identities must meet the CD's normal or permitted origin-field
rules. Configure the correct PAA trust input and, for a certification-time test
CD, its trusted test signer separately. Do not generate production credentials
inside this library or borrow an arbitrary VID to obtain PASS.

For the current constructor, select a DAC whose VID/PID directly matches the
configured identity: its local verifier enforces that equality. A profile using
different `dac_origin_vendor_id`/`dac_origin_product_id` would need separate
support/review before provisioning it. The original test contains that optional
branch, but run171 never reached it; no live failure of that branch is claimed.

The current standalone host needs a separately scoped identity configuration
change before such a fixture can run; the reusable runtime already takes identity
through its configuration. That change was not implemented here and
would require build, full memory acceptance and unchanged end-to-end tests.
After legitimate prerequisites change, rerun the original test and inspect all
remaining assertions. Getting past step6.2 is not sufficient acceptance.

## Verification and disposition

Executed: read-only TH test inspection; comparison against the saved CSA01
source/record/log; public certificate subject inspection with OpenSSL; diagnostic
CD decoding; static tracing of host/runtime/cluster identity ownership. Local
analysis checks are in ignored `build/` tooling. Campaign checks:

```sh
python tools/matter/csa_campaign.py --write
python tools/matter/csa_campaign.py
python tools/matter/check_test_map.py
git diff --check
```

No full TH rerun, fresh crypto verification, native build, Memcheck, sanitizer,
physical firmware, manufacturing uniqueness or certification result is claimed.
Paired nodes, original tests and PICS remain unchanged. Original FAIL is retained;
counts stay122 PASS/28 FAIL/5 prerequisites. The identified rerun prerequisite
does not silently change a historical FAIL into a BLOCKED or PASS result.

Next: **CSA70**, review TC_DA_1_7 original evidence and distinct-device credential
requirements before preparing or rerunning two isolated instances.
