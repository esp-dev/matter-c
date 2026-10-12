# Test data provenance

First-party test code/data use Apache-2.0. Public test keys and simulation
credentials are deliberately reproducible and must never be deployed as secrets.
No CSA PDF, specification certificate PEM, TH distribution or captured operational
certificate is required to generate/build these fixtures.

| Data | Origin and regeneration | Terms |
| --- | --- | --- |
| TLV reader/writer/validator and positive fuzz seeds | `generate_tlv_reference.py`, 50 synthetic cases generated with Python integer/struct encodings; the C implementation is not the oracle | Apache-2.0 |
| IM Read request/report | Same generator, independently encoded schema with explicit synthetic endpoint/cluster/attribute values | Apache-2.0 |
| DAC/PAI/PAA profile | `generate_attestation.py`, public scalars 1..4 and OpenSSL; 59 certificates, 51 cases including 17 valid chains | Apache-2.0 |
| Operational synthetic chain | `generate_synthetic_operational.py`, scalars 21..23, explicit identifiers/dates and a signed opaque SAN | Apache-2.0 |
| Operational upstream vectors | `extract_operational.py`; exact revisions, file hashes and copyrights in [operational-sources.md](operational-sources.md) | Apache-2.0, retained notices |
| ACL peer certificate | Existing `generate_fabric.py --acl-peer-only`, public scalar 12, synthetic Node 102/Fabric 1, root scalar 8; regenerated with OpenSSL | Apache-2.0 |
| SHA-256/HMAC/HKDF | `generate_hash_reference.py`, independently computed with Python hashlib/hmac, synthetic HMAC/HKDF inputs | Apache-2.0 |
| PBKDF2 | Python hashlib recipe documented in `test_crypto_mbedtls.c`; known input/output calculation | Apache-2.0 |
| SPAKE2+ M/N points and reference scalars/transcript values | [draft-bar-cfrg-spake2plus-01](https://datatracker.ietf.org/doc/html/draft-bar-cfrg-spake2plus-01), section 5 and Appendix B; source notices in crypto headers/tests and `pase-vector.py` | [Simplified BSD](../../../licenses/IETF-BSD-2-Clause.txt) |
| P-256 domain parameters | Mathematical constants from [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final); no NIST source implementation copied | Numerical protocol parameters |
| PASE, CASE, CCM, operational credentials, fabric vectors | Local generators `pase-vector.py`, `check_case.py`, `generate_case_credentials.py`, `ccm-vector.cjs`, `generate_credentials.py`, `generate_fabric.py`; explicit simulation inputs, Python/OpenSSL/Node oracles | Apache-2.0; SPAKE constants as above |

Malformed TLV cases are authored boundary/fault tests. Two redundant positive
attestation examples copied from a specification were removed; their positive
profile paths and the negative mutations are covered by synthetic certificates.
OpenSSL ECDSA signatures are nondeterministic: regenerated headers can differ
while still satisfying exact reconstruction and signature validation tests.
TLV/hash output is deterministic. Protocol field identifiers/formats implement
interoperability requirements; this repository does not reproduce specification
prose or claim ownership of third-party standards.

This is an engineering inventory, not certification or a legal warranty.

PBKDF2 reproduction uses `hashlib.pbkdf2_hmac('sha256', password, salt,
iterations, dklen)`: (`b'passwd'`, `b'salt'`, 1, 64), (empty, empty, 1, 32)
and (`bytes.fromhex('f1c12001')`, `bytes(range(16))`, 1000 or 100000, 80).
The setup-PIN encoding is a protocol example value; output is computed locally.
