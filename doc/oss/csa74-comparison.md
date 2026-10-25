# CSA74: compare historical failures with independent implementations

## Scope and decision rule

This is an initial source comparison and a differential-test plan, not a new CSA
run. Native code, PICS, credentials and historical outcomes are unchanged:
123 PASS / 27 FAIL / 5 prerequisites. Four of the 27 failed identities have an
initial source comparison below; the remaining 23 await investigation.

For each failure, compare the original failing input with the target Core 1.6.1
requirement, earlier revisions, the original test and pinned implementations of
ConnectedHomeIP, rs-matter and matter.js. Compare externally observable results:
status vectors, readback, events, session lifetime, retries and persistent state.
Do not infer wire behavior solely from a command handler or an enum declaration.

Three agreeing implementations are strong interoperability evidence, but not a
normative erratum. They can share legacy behavior or the same test workaround.
Prefer an implementation choice that satisfies both the specification and peers.
Where that is impossible, record the exact contradiction and any proposed
compatibility behavior explicitly. Do not silently broaden access privileges,
skip certificate verification, weaken replay protection or relabel a FAIL.

The machine-readable [inventory and queue](csa74-comparison.json) pins source
revisions and reviewed file hashes. These are existing clean local checkouts,
not a claim about the latest upstream releases. Third-party source was not edited.

## Initial findings

### ProxyView: TC_ACL_2_4 / CSA72-Q07

- Core 1.6.1 section 9.10.5.2, printed page 637, marks privilege value 2 as D.
  The supplied PDF was checked with layout-preserving text extraction, avoiding
  the scrambled columns in an older plain-text extraction.
- Historical SDK data-model snapshots for 1.3, 1.4 and 1.4.1 contain provisional /
  mandatory conformance. Snapshots for 1.4.2, 1.5 and 1.6.1 use
  `deprecateConform`. These are historical model extracts, not a fresh reading of
  the complete older Core PDFs, which were not found in the inspected workspace.
- Native `matter_acl.c:privilege` rejects value 2.
- CHIP's ACL conversion accepts it;
  `AccessControl.cpp:CheckRequestPrivilegeAgainstEntryPrivilege` treats it as
  sufficient for View.
- rs-matter represents it as an independent `PROXYVIEW` flag, round-trips it, but
  deliberately grants no ordinary non-proxy read rights through that flag.
- matter.js retains ProxyView -> View explicitly for compatibility with SDK/tests,
  despite its model marking the value D. Its source links the existing upstream
  [certification blocker #41840](https://github.com/project-chip/connectedhomeip/issues/41840).
  The issue was observed open; this is a maintainer report, not a CSA decision.

Thus all three accept the stored value at source level, but they do NOT implement
the same authorization semantics. Merely accepting value 2 may move our test
failure to a later access check. Next probe must write/read the ACL and exercise
both allowed and forbidden operations using the affected subject, retaining an
independent administrator for cleanup. No compatibility change has been made.

### Identical root certificate: TC_CGEN_2_2 / CSA72-Q05

- Core 1.6.1 section 11.18.6.13 explicitly requires an exact byte-for-byte
  duplicate to succeed without changing the TrustedRootCertificates list.
- Section 11.18.5.5 separately permits duplicate entries arising from per-fabric
  storage. That general permission alone does not resolve the command-specific
  rule above.
- Native root-list encoding suppresses the pending entry if it matches an
  installed root. Earlier CSA02 evidence establishes exact equality in the
  original failing input; it was not just a similar certificate.
- CHIP `ReadRootCertificates` emits committed roots and then a pending root.
  Its pending-root installation uses a new available fabric slot and no
  equality check is present in the inspected path.
- rs-matter stages the validated root in fail-safe storage; its read handler
  chains committed roots with `pending_root_ca()` without deduplicating.
- matter.js constructs the attribute from committed roots and unconditionally
  pushes the successfully staged root.

All three inspected source paths therefore predict an additional pending list
entry for this input. This is the strongest first differential-test candidate.
It is NOT yet an observed three-stack wire result and does not by itself justify
ignoring the command-specific requirement. Verify byte equality, root counts and
list contents before/after ArmFailSafe, AddTrustedRootCertificate, expiry and
recommissioning; retain signature validation and rollback checks.

### RevokeCommissioning over PASE: TC_CADMIN_1_10 and TC_OPCREDS_3_4 / CSA72-Q06

- Core 1.6.1 section 11.19.8.3 requires PASE termination and says a PASE caller
  must not expect a reply. Native retirement prevents sending that reply;
  unchanged original tests wait for it and time out, as recorded in CSA16.
- rs-matter explicitly expires rather than immediately removes the requesting
  PASE session, allowing its in-flight exchange to complete before cleanup.
- matter.js calls `initiateClose()` on the PASE NodeSession. The NodeSession
  override defers physical close until active exchanges finish. This provides
  a path for the command response; it still needs a wire observation.
- CHIP forces fail-safe expiry through an asynchronous event, closes the window
  and returns Success. The event marks PASE for eviction. Inspection of these
  functions alone does not establish whether the response is sent before eviction.
  Upstream [#41379](https://github.com/project-chip/connectedhomeip/issues/41379)
  and [fix #41715](https://github.com/project-chip/connectedhomeip/pull/41715)
  document that PASE cleanup itself previously had a race.

There is no demonstrated unanimous wire result. Test both CASE-initiated and
PASE-initiated revocation, response delivery, rejection of NEW PASE exchanges,
window advertising, fail-safe rollback and survival of unrelated CASE sessions.
Sending a final reply and continuing to authorize new requests are different
behaviors and must be checked separately.

## Ordered follow-up

1. Freeze comparable runnable hosts and exact SDK/test versions; use isolated
   profiles and credentials. Record supported cluster revisions and features.
   Missing support is UNSUPPORTED, never evidence of a PASS or FAIL.
2. Run the identical-root probe on all four stacks first. Then run ProxyView
   storage plus authorization checks, then RevokeCommissioning lifetime checks.
   Record each packet transcript separately from the original CSA outcome.
3. Investigate remaining protocol failures in batches: list-write response
   aggregation (including controller-side SDK processing), Subscribe path/status
   handling, then MRP/PASE/BDX details. Timing/OTA scenarios follow only after
   deterministic fixtures and common triggering are in place.
4. Handle identity, real-Wi-Fi and profile prerequisites separately; a generic
   sample application with different features cannot answer their applicability.
5. For every confirmed native defect, implement the smallest change, cover
   negative/lifetime cases, rerun the original failing test and related regression.
   Runnable-host changes still require Memcheck and separate ASan/UBSan/LSan.
6. For a genuine spec/peer contradiction, attach the exact older/current wording,
   pinned source and wire results to the existing unsent CSA72 question. A
   compatibility choice must state its scope and security effects explicitly.

## Validation and limits

Source inventory, hashes and the 27-identity queue were checked locally against
the CSA72 packet. Existing campaign and packet consistency checks were run.
No reference host was compiled or run, no CSA test was rerun, no paired application
state changed and no normative issue was submitted. Build/sanitizer reruns are
not claimed for this documentation-only investigation.

Next task: isolated, byte-identical duplicate-root differential probe.
