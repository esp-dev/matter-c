# Documentation and privacy review

2026-10-26. Scope: the public Matter C repository, including 2170 blob versions
reachable from main at `a4f7d34`, current tracked files and the shipped graphics.
This review changes documentation only; runtime behavior, test outcomes, source
hashes and third-party attributions are preserved.

## Reader-facing changes

The root README now introduces implemented features, application ownership,
memory policy, build/install steps and platform examples. Detailed build options
and host flags moved to [build](../build.md) and [host](../host.md) guides.
The [validation index](validation-index.md) collects memory and CSA reports;
individual evidence and the existing status/campaign remain authoritative for
recorded outcomes. No historical failure is converted to a PASS.

## Findings and cleanup

Seven incidental environment-specific locations were normalized in four reports:

| File | Change |
| --- | --- |
| [CSA18](csa18-validation.md) | Use a placeholder for the remote laboratory checkout. |
| [Memory18](memory18-validation.md) | Replace two machine-specific wrapper/build commands with equivalent activated-IDF commands and relative paths. |
| [Memory19](memory19-validation.md) | Apply the same normalization to its two build commands. |
| [Memory21 receipt](memory21-results.json) | Label clean upstream SDK status by checkout name instead of an absolute home-directory path; retain both values and all recorded versions/hashes. |

No matches were found for the checked unrelated-project names or common access-
token/private-PEM patterns in the reviewed main history. Current tracked files
exclude private `local/`, `build/` data and captured operational fixtures. Public
synthetic/development keys and upstream certificate vectors remain intentional
fixtures with [documented provenance](../../tools/matter/fixtures/fixture-provenance.md).

The two published memory plots and desktop PNG were visually inspected; the ICO
is the documented derivative of that PNG. No unrelated project screenshots or
information were identified. This is a scoped repository review, not proof that
every possible secret encoding or external artifact has been examined.

Published history retains the original environment-specific path metadata; no
history rewrite is performed. No live credential exposure was identified that
would require credential replacement. Future private captures/configuration
should continue to stay outside tracked source.

## Validation

Executed successfully:

- Local documentation checks:8 Markdown files,200 local links/anchors, all5
  original command blocks retained and all120 former README destinations still
  discoverable. The edited Memory21 JSON equals the original after path-key
  normalization; recorded test data/hashes are unchanged.
- `python tools/matter/check_test_map.py`:280 mapped files,118 native definitions,
  70 core sources and80 closed public headers; inventory consistent.
- `python tools/matter/csa_campaign.py`:155 applicable +707 NA; evidence identities,
  counts and generated progress agree with the existing campaign.
- `python tools/matter/csa_review_packet.py`:32 open positions across26 groups;
  source identity, coverage and rendering consistent; no submission performed.
- Graphic metadata/chunk checks for both plots and the desktop PNG/ICO; the
  nine-frame ICO and PNG match their recorded source hashes.
- Working-tree privacy rescan and `git diff --check`.

No C source, API, build configuration, license or runtime behavior changed.
No new firmware compilation, physical run, memory benchmark or CSA execution
was performed for this documentation-only update. Next: resume the existing
acceptance queue using its recorded prerequisites.
