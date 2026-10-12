# Operational certificate fixture sources

`test_operational_vectors.h` contains public upstream fixtures extracted by
`extract_operational.py`, with the original copyright notices in its header.
The immutable dependency inventory records the following pinned sources:

| Source | Revision | Source file SHA-256 | License |
| --- | --- | --- | --- |
| [rs-matter](https://github.com/project-chip/rs-matter) `rs-matter/src/cert.rs` | `7d5684f495fe5bca03d993647543508ab7587f10` | `1af298bec4bd5e6955a38b4112fb0c5f15a0f038e3e09059199e6704ad09472c` | Apache-2.0 |
| [Matter.js](https://github.com/matter-js/matter.js) `packages/protocol/test/certificate/TestCertificates.ts` | `c363e9e6a651f6c18c0cb0c575e8a91ffa4234e6` | `6cf6367e932e7f88a65ca83fc986bc86fdae3a85d7ebc36329b7d612539985bf` | Apache-2.0 |

Copyright (c) 2022-2026 Project CHIP Authors.
Copyright 2022-2026 Matter.js Authors.
See `operational-APACHE-2.0.txt` and `operational-matter-js-NOTICE.txt` alongside
this document. The extraction does not copy upstream implementation code into
the production library. DER/TLV fixtures retain the upstream bytes.

`test_synthetic_operational_vectors.h` is separate, first-party Apache-2.0 test
data. Generate it with `python tools/matter/fixtures/generate_synthetic_operational.py`.
It uses public test scalars 21..23, synthetic Root/ICAC/Node identifiers, Fabric 1,
validity 2025-01-01 through 2035-01-01, and a noncritical opaque SAN extension.
Python constructs DER/TLV independently; OpenSSL signs and verifies every TBS.
ECDSA signatures may differ on regeneration. No local paths, captured certificates
or production keys are inputs. The C regression verifies exact DER reconstruction,
chain signatures and rejection of modified signed contents, wrong roots and expiry.

Captured laboratory certificates are excluded; they are not required by the tests.
