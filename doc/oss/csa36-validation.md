# CSA36: Commissioner Discovery / UDC applicability

CSA35 is committed as **`d86016b`**. This audit corrects an unsupported optional
capability declaration; it does not add a protocol implementation or a CSA PASS.

**TC-SC-4.7 is not applicable to the current reference profile.** Its top-level
guards require both `MCORE.ROLE.COMMISSIONEE` and `MCORE.DD.COMM_DISCOVERY`.
The first remains true; the second is corrected from true to false in
`tools/matter/th/full_profile_project.py`. See [the retained record](csa36-results.json).

## Specification and source evidence

Matter Core R1.6.1 **4.3.3** explicitly makes Commissioner Discovery optional for
both Commissionee and Commissioner. A Commissionee discovers commissioners through
`_matterd._udp`; it may select one and use the User Directed Commissioning (UDC)
doorbell protocol. Core **5.2.2.4 / 5.3** describe that flow; **5.3.2** and
**4.4.3.4, Table 14**
identify UDC protocol ID **0x0003**. This differs from:

| Capability | Service / purpose | Current reference runtime |
| --- | --- | --- |
| Commissionable Node Discovery, 4.3.1 | `_matterc._udp`; another controller finds this node | Supported, including PH and controlled Extended Discovery |
| Operational Discovery, 4.3.2 | `_matter._tcp`; resolve an operational peer | Supported; the service name does not declare TCP transport support |
| Commissioner Discovery, 4.3.3 | `_matterd._udp`; this node finds a commissioner | Unsupported, optional |
| UDC, 5.3 | Sessionless commissioning doorbell, protocol 0x0003 | Unsupported |

The checked-in discovery builders create only commissionable/operational records
(`matter_discovery.c/.h`). `Matter_Resolver_Query_T` addresses a compressed fabric
ID and node ID; its contract explicitly describes operational DNS-SD. The runtime
dispatcher registers protocols 0, 1 and 2, admits incoming PASE/CASE and IM, and
provides the outbound OTA IM/BDX path. It has no registered UDC handler or
commissioner-browsing/selection path. The limited OTA controller role is retained;
it does not imply a Commissioner role or UDC. Generic DNS/message primitives are
not by themselves an implemented Commissioner Discovery feature.

The installed SDK `PICS.yaml` labels `MCORE.DD.COMM_DISCOVERY` as support for
**Commissioner Discovery**. It is not a flag for ordinary commissionable mDNS.
The original TC-SC-4.7 precondition requires this feature on both DUT and TH;
its commissioner-advertising steps use `_matterd._udp`. Step3 also contains a
commissionable `_matterc._udp` example. That inconsistent example does not change
the top-level guards or the normative distinction. No original test was edited.

## Actual Test Harness applicability check

On the installed **TH v2.15.1+summer2026**, a separate project was imported from
the retained CSA35 configuration, changing only that PICS value. The original
project remains unchanged. The actual backend endpoint
`GET /api/v1/projects/{id}/applicable_test_cases` was called before and after:

- Applicable test titles: **164 to 163**; removed **only TC-SC-4.7**, none added.
- TC-SC-4.1, TC-SC-4.3, TC-DD-2.1 and TC-SC-2.1 remain eligible.
- TC-DD-3.3, TC-DD-3.4 and TC-SC-4.6 remain inapplicable; they already failed
  UI and/or Commissioner-role guards before this correction.
- Original four YAML source hashes match the frozen CSA01 catalog. The PICS
  definition and backend evaluator/support hashes are recorded; none was modified.

These counts are eligible **titles in one root project**, not the 862
endpoint/collection positions or a count of tests still to execute. There was
**no new TH test execution/run ID**, no manual PASS answer and no UDC wire test.
The result is an official-backend eligibility observation plus specification/
source audit, not an executed protocol test or certification acceptance.

## Validation and accounting

The old committed and new generators were each run through the real CLI for
endpoints **0, 1, 3, 4, 5**, using the same frozen profile/configuration. Comparing
the entire decoded output shows exactly one changed PICS boolean per endpoint;
all other declarations and project fields are preserved, including commissioning,
the limited OTA controller role, PH and Extended Discovery. The cumulative result
chain was replayed from CSA01, including final attempts and classification changes.
Only the TC-SC-4.7 row changes **MANUAL to NA**, with no prior manual outcome.

Current totals: **97 PASS, 18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA** (862 positions).
MANUAL contains **12 PASS, 1 FAIL and 26 without an outcome**. The inherited
automatic/manual results are not rerun or promoted by this audit. The original
CSA01 matrix and earlier reports remain immutable historical evidence.

`python tools/matter/check_test_map.py` and `git diff --check` pass. Private
comparison/receipt validation scripts and generated configurations remain under
ignored `build/csa36/`; source/PICS/receipt hashes are retained in the public record.
No C/H, API, runtime, persistence or native binary changes; compilation, Memcheck,
sanitizers, Home UI and the full CSA campaign were not rerun for this declaration
correction. TH remains idle. No DUT was started and paired Windows nodes were
untouched. CSA30 remains deferred; CSA32's discrepancy remains open.

**Next: CSA37 — TC-SC-2.1, the original manual PASE exchange procedure.** Keep its
Commissionee guard enabled; gather real wire/controller evidence for PBKDF,
Pake1/2/3, message headers and final success before answering manual steps. Compare
the procedure's size/hasPBKDF wording with Core1.6.1 4.4/4.14 and retain any
discrepancy explicitly. Existing unit tests or commissioning success alone are
not acceptance of every manual assertion. This next procedure has not been run.
