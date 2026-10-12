"""SPDX-License-Identifier: Apache-2.0
Synthetic independent DER fixtures, generated with OpenSSL.

Public TEST scalars 1..4 only. No C implementation is imported. Mutated profiles
are re-signed by OpenSSL so profile rejection is not merely a broken signature.
Runtime tests consume the committed header, never Python/OpenSSL/spec files.
"""
from pathlib import Path
import os
import subprocess

repo = Path(__file__).resolve().parents[3]
work = repo / 'build/m07g-oracle'
work.mkdir(parents=True, exist_ok=True)
openssl = os.environ.get('OPENSSL', 'openssl')
config = work / 'openssl.cnf'
config.write_text('oid_section=oids\n[oids]\nVID=1.3.6.1.4.1.37244.2.1\nPID=1.3.6.1.4.1.37244.2.2\n[req]\ndistinguished_name=dn\n[dn]\n')

def run(*args):
    return subprocess.check_output([openssl, *args], cwd=work, stderr=subprocess.PIPE,
                                   env={**os.environ, 'OPENSSL_CONF': str(config)})

def der(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else b'\x82' + n.to_bytes(2, 'big')
    return bytes([tag]) + length + value

def payload(data):
    n = data[1]
    if n < 128:
        h = 2
    else:
        h = 2 + (n & 127)
        n = int.from_bytes(data[2:h], 'big')
    assert h + n == len(data)
    return data[h:]

def children(data):
    result = []
    while data:
        n, h = data[1], 2
        if n >= 128:
            h += n & 127
            n = int.from_bytes(data[2:h], 'big')
        result.append(data[:h + n])
        data = data[h + n:]
    return result

def sign(cert, change, issuer):
    outer = children(payload(cert))
    tbs = children(payload(outer[0]))
    change(tbs)
    outer[0] = der(0x30, b''.join(tbs))
    (work / 'tbs.der').write_bytes(outer[0])
    outer[2] = der(3, b'\0' + run('dgst', '-sha256', '-sign', issuer + '.pem', 'tbs.der'))
    return der(0x30, b''.join(outer))

def change_extension(tbs, oid_tail, transform):
    exts = children(payload(payload(tbs[7])))
    for i, ext in enumerate(exts):
        parts = children(payload(ext))
        if payload(parts[0]) == bytes([0x55, 0x1d, oid_tail]):
            exts[i:i + 1] = transform(parts, ext)
            break
    else:
        raise AssertionError(oid_tail)
    tbs[7] = der(0xa3, der(0x30, b''.join(exts)))

def replace_extension(tbs, oid_tail, value):
    def replace(parts, _):
        parts[-1] = der(4, value)
        return [der(0x30, b''.join(parts))]
    change_extension(tbs, oid_tail, replace)

def subject(tbs, value):
    # Replace CN only, preserving dedicated OIDs if present.
    rdns = children(payload(tbs[5]))
    parts = children(payload(payload(rdns[0])))
    parts[1] = der(12, value.encode())
    rdns[0] = der(0x31, der(0x30, b''.join(parts)))
    tbs[5] = der(0x30, b''.join(rdns))

def fallback_subject(tbs, value):
    subject(tbs, value)
    tbs[5] = der(0x30, children(payload(tbs[5]))[0])

vectors, cases = {}, []
for n, name in enumerate(('paa', 'pai', 'dac'), 1):
    key = bytes.fromhex('30310201010420') + n.to_bytes(32, 'big') + bytes.fromhex('a00a06082a8648ce3d030107')
    (work / (name + '.key.der')).write_bytes(key)
    run('ec', '-inform', 'DER', '-in', name + '.key.der', '-out', name + '.pem')
subjects = {'paa': '/CN=PAA', 'pai': '/CN=PAI/VID=FFF1', 'dac': '/CN=DAC/VID=FFF1/PID=8000'}
for name, issuer in (('paa', None), ('pai', 'paa'), ('dac', 'pai')):
    ca = name != 'dac'
    ext = 'basicConstraints=critical,CA:' + ('TRUE,pathlen:' + ('1' if name == 'paa' else '0') if ca else 'FALSE')
    ext += '\nkeyUsage=critical,' + ('keyCertSign,cRLSign' if ca else 'digitalSignature')
    ext += '\nsubjectKeyIdentifier=hash\n'
    if issuer:
        ext += 'authorityKeyIdentifier=keyid:always\n'
    (work / 'extensions.cnf').write_text(ext)
    run('req', '-new', '-key', name + '.pem', '-subj', subjects[name], '-out', name + '.csr')
    args = ['x509', '-req', '-in', name + '.csr', '-set_serial', '1', '-days', '1000', '-sha256',
            '-extfile', 'extensions.cnf', '-out', name + '.crt']
    args += ['-CA', issuer + '.crt', '-CAkey', issuer + '.pem'] if issuer else ['-signkey', name + '.pem']
    run(*args)
    vectors[name] = run('x509', '-in', name + '.crt', '-outform', 'DER')
run('verify', '-CAfile', 'paa.crt', '-untrusted', 'pai.crt', 'dac.crt')
cases.append(('unscoped_paa_pai_no_pid', 'dac', 'pai', 'paa', True))

def variant(name, role, change, ok=False):
    vectors[name] = sign(vectors[role], change, {'dac': 'pai', 'pai': 'paa', 'paa': 'paa'}[role])
    chain = [name if r == role else r for r in ('dac', 'pai', 'paa')]
    cases.append((name, *chain, ok))

for name, cn, ok in (
    ('fallback_adjacent', 'Mvid:FFF1Mpid:8000', True),
    ('fallback_leftmost', 'Mvid:FFF1 Mvid:FFF2 Mpid:8000 Mpid:1111', True),
    ('fallback_later_valid', 'Mpid:Mvid:FFF1 Mpid:12cd Mpid:8000', True),
    ('fallback_embedded', 'Mvid:FFF1ABC Mpid:80009899', True),
    ('fallback_lowercase', 'Mvid:fff1 Mpid:8000', False),
    ('fallback_short', 'Mvid:FF1 Mpid:8000', False),
    ('fallback_prefix_only', 'Mvid:FFF1 Mpid:', False),
    ('fallback_zero_pid', 'Mvid:FFF1 Mpid:0000', False),
    ('fallback_wrong_vid', 'Mvid:FFF2 Mpid:8000', False),
    ('fallback_wrong_pid', 'Mvid:FFF1 Mpid:8001', False)):
    variant(name, 'dac', lambda t, cn=cn: fallback_subject(t, cn), ok)
variant('preferred_ignores_cn', 'dac', lambda t: subject(t, 'Mvid:bad Mpid:1111'), True)
variant('cn_too_long', 'dac', lambda t: subject(t, 'X' * 65))
variant('cn_unicode_64', 'dac', lambda t: subject(t, '\u00e9' * 64), True)

def cn_encoding(t, tag, encoded):
    fallback_subject(t, 'placeholder')
    rdns = children(payload(t[5]))
    parts = children(payload(payload(rdns[0])))
    parts[1] = der(tag, encoded)
    t[5] = der(0x30, der(0x31, der(0x30, b''.join(parts))))
for name, tag, encoded in (
    ('bmp', 30, 'Mvid:FFF1 Mpid:8000'.encode('utf-16-be')),
    ('universal', 28, 'Mvid:FFF1 Mpid:8000'.encode('utf-32-be')),
    ('printable', 19, b'Mvid:FFF1 Mpid:8000'),
    ('t61', 20, b'Mvid:FFF1 Mpid:8000')):
    variant('fallback_' + name, 'dac', lambda t, tag=tag, v=encoded: cn_encoding(t, tag, v), True)
variant('fallback_bmp_truncated', 'dac', lambda t: cn_encoding(t, 30, b'\x00M\x00'))
variant('cn_bad_utf8', 'dac', lambda t: cn_encoding(t, 12, b'\xffMvid:FFF1 Mpid:8000'))
variant('paa_pid', 'paa', lambda t: (subject(t, 'PAA Mvid:FFF1 Mpid:8000'), t.__setitem__(3, t[5])))
variant('paa_different_issuer', 'paa', lambda t: t.__setitem__(3, t[3].replace(b'PAA', b'Paa')))

# A fallback PAI subject is reflected exactly in the DAC issuer. The DAC may
# independently keep its preferred OID subject (field-by-field selection).
vectors['fallback_pai'] = sign(vectors['pai'], lambda t: fallback_subject(t, 'PAI Mvid:FFF1'), 'paa')
pai_subject = children(payload(children(payload(vectors['fallback_pai']))[0]))[5]
vectors['fallback_pai_dac'] = sign(vectors['dac'], lambda t: t.__setitem__(3, pai_subject), 'pai')
cases.append(('fallback_pai_preferred_dac', 'fallback_pai_dac', 'fallback_pai', 'paa', True))

def append_id(t, which, value):
    rdn = der(0x31, der(0x30, der(6, bytes.fromhex('2b0601040182a27c02') + bytes([which])) + der(12, value.encode())))
    t[5] = der(0x30, payload(t[5]) + rdn)
vectors['pai_wrong_pid'] = sign(vectors['pai'], lambda t: append_id(t, 2, '8001'), 'paa')
wrong_subject = children(payload(children(payload(vectors['pai_wrong_pid']))[0]))[5]
vectors['dac_pai_wrong_pid'] = sign(vectors['dac'], lambda t: t.__setitem__(3, wrong_subject), 'pai')
cases.append(('pai_pid_mismatch', 'dac_pai_wrong_pid', 'pai_wrong_pid', 'paa', False))
vectors['paa_wrong_vid'] = sign(vectors['paa'], lambda t: (append_id(t, 1, 'FFF2'), t.__setitem__(3, t[5])), 'paa')
wrong_root = children(payload(children(payload(vectors['paa_wrong_vid']))[0]))[5]
vectors['pai_paa_wrong_vid'] = sign(vectors['pai'], lambda t: t.__setitem__(3, wrong_root), 'paa')
cases.append(('paa_vid_mismatch', 'dac', 'pai_paa_wrong_vid', 'paa_wrong_vid', False))

def mutate_dn(t, mode):
    rdns = children(payload(t[5]))
    if mode == 'mixed':
        subject(t, 'Mpid:8000')
        rdns = children(payload(t[5]))[:-1]
    elif mode == 'order':
        rdns[-2:] = reversed(rdns[-2:])
    elif mode == 'duplicate':
        rdns.insert(1, rdns[-2])
    elif mode == 'printable':
        for i in (1, 2):
            parts = children(payload(payload(rdns[i])))
            parts[1] = der(19, payload(parts[1]))
            rdns[i] = der(0x31, der(0x30, b''.join(parts)))
    elif mode == 'lowercase':
        rdns[1] = rdns[1].replace(b'FFF1', b'fff1')
    t[5] = der(0x30, b''.join(rdns))
for mode in ('mixed', 'order', 'duplicate', 'printable', 'lowercase'):
    variant('oid_' + mode, 'dac', lambda t, m=mode: mutate_dn(t, m), mode == 'printable')
for role, oid, name in (('dac', 19, 'basic'), ('dac', 15, 'usage'), ('pai', 19, 'basic'), ('paa', 15, 'usage')):
    variant(role + '_' + name + '_not_critical', role,
            lambda t, oid=oid: change_extension(t, oid, lambda parts, _: [der(0x30, parts[0] + parts[-1])]))
for oid, name in ((14, 'skid'), (35, 'akid')):
    variant('missing_' + name, 'dac', lambda t, oid=oid: change_extension(t, oid, lambda p, e: []))
variant('wrong_key_usage', 'dac', lambda t: replace_extension(t, 15, bytes.fromhex('030205a0')))
variant('pai_no_path', 'pai', lambda t: replace_extension(t, 19, bytes.fromhex('30030101ff')))
variant('pai_path_one', 'pai', lambda t: replace_extension(t, 19, bytes.fromhex('30060101ff020101')))
variant('paa_no_path', 'paa', lambda t: replace_extension(t, 19, bytes.fromhex('30030101ff')), True)
variant('paa_path_zero', 'paa', lambda t: replace_extension(t, 19, bytes.fromhex('30060101ff020100')))
variant('ca_sign_bit', 'pai', lambda t: replace_extension(t, 15, bytes.fromhex('03020186')), True)

def extra(t, critical=False, duplicate=False):
    extension = der(0x30, der(6, bytes.fromhex('2a0304')) + (bytes.fromhex('0101ff') if critical else b'') + der(4, b'\x05\x00'))
    exts = payload(payload(t[7])) + extension * (2 if duplicate else 1)
    t[7] = der(0xa3, der(0x30, exts))
variant('unknown_noncritical', 'dac', lambda t: extra(t), True)
variant('unknown_critical', 'dac', lambda t: extra(t, True))
variant('duplicate_unknown', 'dac', lambda t: extra(t, duplicate=True))
variant('duplicate_skid', 'dac', lambda t: change_extension(t, 14, lambda p, e: [e, e]))
variant('short_skid', 'dac', lambda t: replace_extension(t, 14, der(4, bytes(19))))
variant('wrong_akid', 'dac', lambda t: replace_extension(t, 35, der(0x30, der(0x80, bytes(20)))))
variant('issuer_case', 'dac', lambda t: t.__setitem__(3, t[3].replace(b'PAI', b'Pai')))
variant('dac_before_pai', 'dac', lambda t: t.__setitem__(4, der(0x30, der(23, b'000101000000Z') + children(payload(t[4]))[1])))
# Unlike operational SKID, attestation key IDs are not constrained to method(1).
custom_id = bytes(range(20))
vectors['custom_paa'] = sign(vectors['paa'], lambda t: replace_extension(t, 14, der(4, custom_id)), 'paa')
vectors['custom_pai'] = sign(vectors['pai'], lambda t: replace_extension(t, 35, der(0x30, der(0x80, custom_id))), 'paa')
cases.append(('custom_key_identifier', 'dac', 'custom_pai', 'custom_paa', True))
vectors['public'] = run('pkey', '-in', 'dac.pem', '-pubout', '-outform', 'DER')[-65:]
# Independently generated unrelated root for the trust-negative regression.
(work / 'other.key.der').write_bytes(bytes.fromhex('30310201010420') + (4).to_bytes(32, 'big') + bytes.fromhex('a00a06082a8648ce3d030107'))
run('ec', '-inform', 'DER', '-in', 'other.key.der', '-out', 'other.pem')
run('req', '-new', '-x509', '-key', 'other.pem', '-subj', '/CN=Other PAA', '-sha256', '-days', '1000',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-addext', 'subjectKeyIdentifier=hash', '-out', 'other.crt')
vectors['other_paa'] = run('x509', '-in', 'other.crt', '-outform', 'DER')

text = '/* Generated by fixtures/generate_attestation.py; ' + run('version').decode().strip() + '.\n * Synthetic DER, OpenSSL signatures, public TEST keys 1..4.\n * SPDX-License-Identifier: Apache-2.0. See fixtures/fixture-provenance.md. Never provision these keys. */\n'
for name, data in vectors.items():
    assert len(data) <= 600, (name, len(data))
    text += 'static const uint8_t att_' + name + '[] = {\n'
    for off in range(0, len(data), 16):
        text += '    ' + ','.join('0x%02x' % b for b in data[off:off + 16]) + ',\n'
    text += '};\n'
text += 'static const struct { const char* name; Matter_Der_T dac,pai,paa; bool valid; } att_cases[] = {\n'
for name, *chain, ok in cases:
    text += '    {"' + name + '",' + ','.join('{att_' + x + ',sizeof(att_' + x + ')}' for x in chain) + ',' + str(ok).lower() + '},\n'
text += '};\n'
(repo / 'tools/matter/tests/test_attestation_vectors.h').write_text(text, encoding='utf-8', newline='\n')
print(len(vectors), 'vectors;', len(cases), 'cases;', sum(c[-1] for c in cases), 'valid')
