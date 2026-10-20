# CSA72: consolidated questions, rerun gates and VM activity

The [review packet](csa72-questions.md), generated from [JSON](csa72-questions.json),
covers every current open case/endpoint/collection exactly once: **27 FAIL and
5 prerequisites** in 22 CSA question groups and 4 owner/laboratory groups.
Nothing was sent or uploaded. No original test was repeated, native or official
test source/PICS changed, or paired Windows node restarted. This stage changes
no conformance verdict.

## Package and retained evidence

Each group identifies the earlier observation, selected original/diagnostic run,
public evidence, requested decision and concrete condition for repeating the
test. Protocol/test questions are separate from assigned-identity provisioning,
the real two-AP Wi-Fi bench, final onboarding artifacts and the deferred long
diagnostics run. These are pending questions, not confirmed CSA defects.

The JSON pins all 54 linked public evidence files to their canonical Git blob
bytes at source commit `220815a6d83c151b337932643e320bdcbbbf9ad3`. Historical
test/helper hashes remain historical; no fresh SDK/binary audit is implied.
Original failures, unexecuted steps and local-corrected acceptance stay separate.
No raw trace, credential, certificate or specification PDF is attached.

`tools/matter/csa_review_packet.py` validates complete/unique open-case coverage,
retained verdicts, pending decisions, evidence hashes and generated Markdown.
It contains no sending or test-execution operation. Changes to the campaign
require deliberate packet review; the checker rejects stale identities/verdicts.
The campaign's previously empty DGGEN blocker now records its existing CSA30/47
prerequisite, without changing its BLOCKED status or checkpoint run reference.

## Read-only CPU investigation

Samples were approximately three seconds long and were not simultaneous:

| Observation | Result |
| --- | --- |
| Initial DUT guest, aggregate across 24 vCPUs | 0.14% busy |
| Initial TH guest, aggregate across 4 vCPUs | 0.33% busy; API idle |
| Windows, two VMware processes across 24 logical CPUs | 0.561% and 0.432%; about 0.993% combined |
| Later DUT guest samples | 8.73%, then 3.27% busy |
| Later TH guest | 0.25% busy; API idle |
| Separate active memory-worker child | Memcheck about 99.61% of one core |

The separate memory-optimization worker started at
2026-10-20T18:43:31.580000+00:00, after the initial inspection. Its scoped source
and progress files show normal build/CTest/paired-runtime work, followed by
sanitizer build/tests and focused Memcheck checks. The last process sample
identifies a Memcheck child of that worker running the CASE allocation test.
It is progressing work, so it was left running. Its outputs are **not** CSA72
validation or a new CSA result. No old CSA test jobs were observed.

Initial process-name/argument filtering missed the separate worker; scoped
inspection and expanded matching identified it. The first restricted Windows
CIM read lacked host visibility; the successful read-only host sample outside
the sandbox supplied the Windows values. An empty restricted inventory was
not used as evidence of absence. Some root/other-user metadata was inaccessible.
Fast-lived build children are not all represented in the two-endpoint process
ranking. Guest aggregate, single-core process and whole-host percentages use
different denominators. These samples identify active work but cannot prove
the source of all CPU or diagnose earlier peaks. No process, service, VM setting
or network interface was changed; no continuous monitor was installed.

Raw process details and host paths stay in ignored `build/csa72/`.

## Checks and limits

Executed local checks:

```sh
python tools/matter/csa_review_packet.py
python tools/matter/csa_campaign.py
python tools/matter/check_test_map.py
python build/csa72/validate_public.py
git diff --check
```

The private metadata validator checks receipt hashes, local links, sensitive-data
exclusion and changed-file scope. Negative controls reject missing/duplicate
coverage, unauthorized execution flags, missing evidence hashes and stale
verdicts. These validate the package mechanism, not the Matter implementation.
The test-map check verifies inventory; it does not execute its native tests.

Counts stay **123 PASS / 27 FAIL / 5 prerequisites**, with automatic/manual
tracks preserved. No build, memory acceptance, physical/product certification
or newly accepted CSA interpretation is claimed by this stage.

Next: owner review and prioritization of the unsent packet. Select recipients
and attachments only after explicit authorization; rerun a case only when its
documented prerequisite changes. Do not restart the deferred multi-hour
diagnostics test merely because this package has been prepared.
