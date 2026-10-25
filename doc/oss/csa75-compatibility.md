# CSA75: explicit legacy SDK/test compatibility

The owner requested opt-in implementation exceptions after the
[CSA74 comparison](csa74-comparison.md). This is an implementation decision,
not an answer from CSA or a change to the normative interpretation recorded
in CSA72. All exceptions are OFF by default. Historical strict-profile results
and new compatibility-profile results must remain distinguishable.

## Build selection

With CMake, use a separate build directory:

```sh
cmake -S . -B build/compat -DMATTER_CSA_COMPAT=ON
cmake --build build/compat
ctest --test-dir build/compat --output-on-failure
```

The umbrella enables all four exceptions. With the umbrella OFF, select
individual exceptions using the corresponding CMake options:

| Definition / option | Effect | Original failing cases |
| --- | --- | --- |
| `MATTER_CSA_COMPAT_PENDING_ROOT` | Include a pending root even when byte-identical to an installed root. | TC_CGEN_2_2 |
| `MATTER_CSA_COMPAT_PROXY_VIEW` | Accept privilege 2, round-trip it and grant View only, subject to normal fabric, subject and target checks. | TC_ACL_2_4 |
| `MATTER_CSA_COMPAT_REVOKE_REPLY` | Drain the original PASE RevokeCommissioning reply before terminating its session and continuing rollback. | TC_CADMIN_1_10, TC_OPCREDS_3_4 |
| `MATTER_CSA_COMPAT_FAILSAFE_REARM` | An initial CASE arm with exactly MaxCumulativeFailsafeSeconds uses a shorter cumulative budget for the legacy test. | Final steps of TC_CGEN_2_2 |

For builds outside CMake, define `MATTER_CSA_COMPAT=1` consistently for all
library objects, or define the individual macros to 0/1. Defaults and validation
are in `matter_compat.h`. CMake exports the effective definitions to consumers
and applies the same configuration to instrumented test objects and unit8.
No persistent data format or application callback signature changes.
`MATTER_CSA_COMPAT_FAILSAFE_SECONDS` selects the short cumulative budget, default
20s, matching the original test's default PIXIT wait. It must be in 1..65535 and
cannot increase the configured cumulative maximum. Match it to the test's PIXIT
when using another wait value.

## Boundaries

**Pending root.** The read encoder follows the committed-plus-pending ordering
found in all three pinned reference sources. Only list visibility changes.
Once AddNOC associates the staged root with its pending fabric, no additional
unassociated-root entry is emitted. This follows CHIP's pending-root API,
rs-matter's pending-root flags and matter.js's fabric-list refresh.
Certificate parsing, self-signature/profile validation, CSR/AddNOC checks,
storage admission and fail-safe rollback remain in effect. The exception to
Core 1.6.1's exact-duplicate command rule is intentional and explicitly selected.

**ProxyView.** This follows the legacy CHIP/matter.js View semantics, not
rs-matter's separate flag with no ordinary read rights. It grants no Operate,
Manage or Administer authority. Invalid PASE ACL entries, Group Administer,
invalid subjects/targets and cross-fabric access retain their checks.
A strict image fails closed on a stored legacy privilege-2 entry. Remove those
ACL entries with a compatibility image before switching an existing profile back
to strict mode; otherwise the strict persistent-image validator rejects it.

**PASE revocation.** Admission closes as soon as retirement begins. Only an
already accepted pending Administrator Commissioning operation on PASE can
retain its original reply exchange. CASE callers keep their cleanup wait.
The authorization exception exists only within synchronous polling of that
accepted exchange, for endpoint 0 / AdministratorCommissioning / RevokeCommissioning.
It cannot authorize a new request, another session/path, a closing transaction,
or a reply after its deadline. Normal session lookup still refuses that token.
The existing finite retirement deadline and local UDP completion rule apply;
no peer ACK is required before rollback. Stop cancels the exception immediately.
Unrelated CASE sessions survive selective PASE retirement.
The earlier TimedRequest StatusResponse is not counted as delivery of the final
InvokeResponse on that same exchange.

**CASE fail-safe re-arm.** Original TC_CGEN_2_2 reads the advertised cumulative
maximum (900s), then replaces its local `maxFailsafe` with the short PIXIT wait
(20s), re-arms with the original maximum, and expects expiry at the shorter wait.
The optional exception starts a short cumulative budget only when CASE initially
arms with the advertised maximum. Subsequent re-arms retain that budget. A short
initial arm still allows the ordinary extension to the maximum (the test also
checks that earlier in step 34). PASE and other initial durations keep their normal
behavior. This intentionally reduces the usable cumulative budget in that case; it is
NOT ordinary interoperability behavior inferred from all three reference stacks.
CHIP starts a separate cumulative timer on initial arm and renews the requested
expiry timer. matter.js delegates extension to its failsafe timer; rs-matter's
same-session re-arm updates its timeout and has an explicit extension test.

## Native defect found beyond the original failure

After the pending-root exception passed the early assertion, the unchanged
original test reached a new PASE session and AddTrustedRootCertificate failed
with FailsafeRequired. Core 1.6.1 section 5.5 requires automatic initial fail-safe
arming for 60s after PASE establishment; CHIP does this as well. This missing
handoff behavior is now repaired in BOTH strict and compatibility images.

The runtime journals state and arms the initial timer before exposing the secure
session to IM. An existing armed/cleaning context or failed journal begin refuses
installation of that session. Secure objects are released on failure. Root-only
models without General Commissioning are unaffected. Tests cover failed begin,
duplicate admission, exact expiry, pending cleanup and saturating deadlines.

The ProxyView exception also applies to persistent-image validation, and a newly
visible duplicate pending root advances its data version in compatibility mode.

## Changed surfaces

- `matter_compat.h`, CMake and the installed-header manifest define and export
  the same profile for library, runtime, consumers and instrumented test copies.
- ACL and persistent-image validators implement the legacy value consistently;
  Fabric encoder/host implement root visibility and its data-version change.
- Administrator Commissioning, dispatcher and runtime implement bounded reply
  draining without exposing a revoked session through normal session lookup.
- Root and dispatcher add the normative initial PASE fail-safe handoff; the
  separately selected CASE exception affects only the initial maximum arm.
- Existing ACL, Admin, Root, dispatch, Fabric encoding and storage tests gain
  positive/negative cases for both profiles, ownership, rollback and OOM.

## Validation record

The original, unmodified tests reach PASS on the compatibility image.
The [machine-readable receipt](csa75-compatibility.json) pins final source/build
hashes, exact definitions, original test/PICS hashes, all collected attempts and
memory/cleanup evidence. Its source hashes refer to the worktree bytes actually
exported and compiled, including line endings, rather than canonical Git blobs.

| Test | Initial accepted run | Final exact-image run | Passed steps |
| --- | --- | --- | --- |
| TC_ACL_2_4 | 717 | 743 | 47 |
| TC_CADMIN_1_10 | 718 | 744 | 14 |
| TC_OPCREDS_3_4 | 719 | 745 | 33 |
| TC_CGEN_2_2 | 721 | 746 | 50 |

All four final runs use the same executable SHA256
`35d75102d45e8180de9a732fcbf26008992db1c4caa06b41721dad021b3747f1`.
Test scripts, shared support and PICS remain unchanged. The harness is idle,
the temporary test PAA is removed and task-owned native/controller processes
are stopped. One orphan controller from a superseded attempt was identified by
its exact task script/output paths and stopped normally; unrelated processes
and services were not changed.

A subsequent 19-case neighbor/repair sweep produced 17 PASS and 2 FAIL. Both
failures were retained and repeated with the original longer window fixture,
without changing native code, original scripts or PICS: TC_CADMIN_1_3 passes
17 steps in run 741 and TC_CADMIN_1_9 passes 8 in run 742. Run 729's WindowStatus
prime-report race matches the earlier CSA02/run243 symptom: the old zero report
satisfies the closure matcher before the new 180s window closes. Run 731 accepts
the correct PIN after 20 rapidly failed attempts; this symptom did not repeat in
742. No native change or claim of eliminating those intermittent failures is
made. Their outer timeout setting differs (360s versus 840s); that difference
alone does not establish the cause of the rapid-PASE failure.

Native acceptance covers GCC 13.3.0 / CMake 3.28.3 on Linux:

| Build | Broad CTest before final delta | Two-instance lifecycle | Six wire/fault cases |
| --- | --- | --- | --- |
| Strict, normal | 109/109 | 6/6 under Memcheck | Not rerun in this variant |
| Compatibility, normal | 109/109 | 6/6 under Memcheck | 6/6 under Memcheck |
| Compatibility, ASan/UBSan/LSan | 109/109 | 6/6 separately with sanitizers | 6/6 separately with sanitizers |

The final delta removes the extra unassociated pending root after AddNOC, adds
its data-version assertions and makes the maximum 65535s definition compile
without a type-limits warning. After that delta, all three variants rebuild and
pass the five affected Root/Fabric/encoding/OOM tests and the full 6-check
two-instance lifecycle again, under Memcheck or separately with sanitizers.
The six-case wire matrix above belongs to the preceding image; it was not
repeated for this read-encoder delta. No compiler or native memory diagnostics
were observed; completed Memcheck scenarios report zero errors and zero bytes
in use at exit. The wire oracle requires zero live core allocations at stop.
Installed/relocated consumers, including all public headers, are included in
the broad CTest set.

On Windows / GCC 16.2.0 UCRT, both profiles pass the final five affected tests and
the additional Fabric data-version assertion; compatibility also passes the
focused ACL/dispatch/Root/storage allocation checks. Three UDP timeouts inside
the restricted sandbox passed when repeated outside it; those sandbox outcomes
are retained and are not presented as protocol successes inside the sandbox.
Macro-selection checks cover defaults, umbrella, each independent flag, rejected
non-boolean values and duration bounds. The maximum 65535s Root syntax build
also succeeds with `-Wall -Wextra -Werror`.

Executed test commands include the broad set and final focused selection:

```sh
ctest --test-dir <build> --output-on-failure -E runtime_wire
ctest --test-dir <build> --output-on-failure -R '^test_(fabric|fabric_encoding|fabric_encoding_alloc|root|root_alloc)$'
```

The full callback-runtime scenario uses `runtime-pair-host` and
`chip_tool_three_phase.py --source-registers --meter-services`, with separate
disposable profiles and operator-supplied development credentials. The wire
matrix uses `runtime_wire.py`, first with `--memcheck`, then a separate
`MATTER_SANITIZE=ON` build; see [wire test contract](../runtime-wire-tests.md).

No wire run of the three reference *server* implementations, full 27-case repair,
physical device acceptance or certification is implied. The strict historical
campaign and CSA72 questions remain unchanged; these results belong to the
explicit compatibility build.
