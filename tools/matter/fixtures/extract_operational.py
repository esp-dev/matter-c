"""Manual extraction of public upstream TLV/TBS vectors; not run by C tests.

Explicit pinned upstream checkouts; provenance is recorded in tools/matter/fixtures/operational-sources.md.
No upstream implementation is copied into production code.
"""
from pathlib import Path
import re
import argparse
import hashlib

repo = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--rs-matter', type=Path, required=True)
parser.add_argument('--matter-js', type=Path, required=True)
args = parser.parse_args()
rs = args.rs_matter / 'rs-matter/src/cert.rs'
ts = args.matter_js / 'packages/protocol/test/certificate/TestCertificates.ts'
vectors = {}
source = rs.read_text()
for name in ['NOC1_SUCCESS', 'ICAC1_SUCCESS', 'RCA1_SUCCESS', 'CHIP_CERT_INPUT1',
             'CHIP_CERT_INPUT2', 'CHIP_CERT_TXT_IN_DN', 'ASN1_OUTPUT1',
             'ASN1_OUTPUT2', 'ASN1_OUTPUT_TXT_IN_DN']:
    match = re.search(r'const ' + name + r':.*?= &\[(.*?)\];', source, re.S)
    vectors['rs_' + name.lower()] = bytes(int(x, 0) for x in re.findall(r'0x[0-9a-fA-F]+|\b[0-9]+\b', match[1]))
sets, rows = [], []
match = re.search(r'TEST_NOC_CERT_CAT_ASN1 = Bytes.fromHex\(\s*"([0-9a-f]+)"', ts.read_text())
vectors['js_cat_tbs'] = bytes.fromhex(match[1])
for group in re.finditer(r'^    "([^"]+)": \{(.*?)(?=^    "|^};)', ts.read_text(), re.M | re.S):
    title, block = group[1], group[2]
    stem = 'js_' + re.sub('[^a-z0-9]+', '_', title.lower()).strip('_')
    certs = {}
    for cert in re.finditer(r'^        (ROOT|ICAC|NOC): \{(.*?)(?=^        [A-Z]|^    },)', block, re.M | re.S):
        kind, contents = cert[1], cert[2]
        name = stem + '_' + kind.lower()
        certs[kind] = name
        for fmt, hextext in re.findall(r'(TLV|ASN1): Bytes.fromHex\(\s*"([0-9a-f]+)"', contents):
            vectors[name + '_' + fmt.lower()] = bytes.fromhex(hextext)
        if name + '_tlv' in vectors:
            rows.append((name, kind, name + '_asn1' if name + '_asn1' in vectors else None))
    if 'NOC' in certs and 'ROOT' in certs:
        sets.append((stem, certs))
text = '''/* Independent public certificate vectors, extracted without alteration.
 * rs-matter: Copyright (c) 2022-2026 Project CHIP Authors.
 * matter.js: Copyright 2022-2026 Matter.js Authors.
 * SPDX-License-Identifier: Apache-2.0
 * See tools/matter/fixtures/operational-sources.md for revisions, source hashes and license.
 * ASN1 arrays are TBS only, NOT the entire certificate. */
'''
for name, data in vectors.items():
    text += 'static const uint8_t ' + name + '[] = {\n'
    for off in range(0, len(data), 16):
        text += '    ' + ','.join('0x%02x' % b for b in data[off:off + 16]) + ',\n'
    text += '};\n'
text += 'static const struct { const char* name; Matter_Cert_Tlv_T tlv; Matter_Operational_Type_T type; Matter_Der_T tbs; } reference[] = {\n'
for name, kind, tbs in rows:
    text += '    {"' + name + '",{' + name + '_tlv,sizeof(' + name + '_tlv)},MATTER_CERT_' + ('RCAC' if kind == 'ROOT' else kind) + ',' + ('{' + tbs + ',sizeof(' + tbs + ')}' if tbs else '{0}') + '},\n'
text += '};\nstatic const struct { const char* name; Matter_Cert_Tlv_T noc,icac,root; } chains[] = {\n'
for stem, certs in sets:
    def span(kind):
        n = certs.get(kind)
        return '{' + n + '_tlv,sizeof(' + n + '_tlv)}' if n else '{0}'
    text += '    {"' + stem + '",' + ','.join(span(k) for k in ('NOC', 'ICAC', 'ROOT')) + '},\n'
text += '};\n'
(repo / 'tools/matter/tests/test_operational_vectors.h').write_text(text)
for path in (rs, ts):
    print(path, hashlib.sha256(path.read_bytes()).hexdigest())
print('vectors', len(vectors), 'rows', len(rows), 'chains', len(sets))
