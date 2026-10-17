# Source and license inventory

First-party code: Apache-2.0, selected by the project owner. See root LICENSE.
Retained third-party material keeps its original terms; see NOTICE.

- Optional SDK test correction: `tools/matter/patches/TC_SU_2_5-progress-order.patch`
  modifies Apache-2.0 `TC_SU_2_5.py`, Copyright (c) 2025 Project CHIP Authors.
  Exact original/patched hashes, scope and local-only acceptance rules are in
  `tools/matter/patches/README.md`. The complete test/TH distribution is not bundled.

- Desktop QR image generator: nayuki/QR-Code-generator v1.8.0, commit
  720f62bddb7226106071d4728c292cb1df519ceb; MIT. Unmodified C/header, full
  copyright/license and SHA-256 inventory in third_party/qrcodegen.

- mDNS: mjansson/mdns, commit a569c4759bd47e0f2a7bfc4d4c19620445782806,
  Unlicense; original header and LICENSE in tools/matter/host/vendor/mdns.
- Crypto dependency: official Mbed-TLS/mbedtls 3.6.0, commit
  2ca6c285a0dd3f33982dd57299012dacab1ff206. Apache-2.0 selected from upstream
  dual licensing. Explicit bootstrap, pin and file hashes in cmake/dependencies.json.
- Public rs-matter/Matter.js certificate fixtures: Apache-2.0, pinned sources,
  file hashes and retained copyrights in tools/matter/fixtures/operational-sources.md.
- SPAKE2+ constants/test values: draft-bar-cfrg-spake2plus-01, sections 5 and
  Appendix B; Simplified BSD text in licenses/IETF-BSD-2-Clause.txt.
- Optional JavaScript controller: dependencies/versions/licenses in its package-lock.json.
- Synthetic fixtures, generators and numerical parameter sources:
  tools/matter/fixtures/fixture-provenance.md.

This snapshot excludes private Git history, laboratory captures, logs, live state,
local configuration, CSA documents and the CSA Test Harness distribution.
Simulation test keys are public by design and unsuitable for real credentials.
This engineering inventory is not a legal warranty or certification.
