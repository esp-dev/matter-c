"""Generate synthetic signed operational certificates with an opaque extension.

SPDX-License-Identifier: Apache-2.0
Only Python's standard library and OpenSSL are used, never the implementation
under test. Public TEST scalars 21..23 and synthetic IDs; no captured material.
DER/TLV are constructed independently. OpenSSL signs and verifies each TBS.
ECDSA signatures vary between runs. The generated header is committed so normal
builds do not need OpenSSL. Never use these keys as device credentials.
"""
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def der(tag, data):
    size = len(data)
    length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length()+7)//8)]) + size.to_bytes((size.bit_length()+7)//8, 'big')
    return bytes([tag]) + length + data


def seq(*data):
    return der(0x30, b''.join(data))


def uint(tag, value):
    size = next(n for n in (1, 2, 4, 8) if value < 1 << (n*8))
    return bytes([0x24 + (size.bit_length()-1), tag]) + value.to_bytes(size, 'little')


def octets(tag, value):
    assert len(value) < 256
    return bytes([0x30, tag, len(value)]) + value


def dn(fields):
    encoded = []
    for tag, value in fields:
        oid = bytes.fromhex('2b0601040182a27c01') + bytes([tag-16])
        encoded.append(der(0x31, seq(der(6, oid), der(12, f'{value:016X}'.encode()))))
    return seq(*encoded), bytes([0x37, 0]) + b''.join(uint(t, v) for t, v in fields) + b'\x18'


def extension(oid, value, critical=False):
    return seq(der(6, bytes.fromhex('551d') + bytes([oid])), b'\x01\x01\xff' if critical else b'', der(4, value))


def raw_signature(signature):
    assert signature[0] == 0x30 and signature[1] == len(signature)-2
    position, out = 2, b''
    for _ in range(2):
        assert signature[position] == 2
        size = signature[position+1]
        out += int.from_bytes(signature[position+2:position+2+size], 'big').to_bytes(32, 'big')
        position += size+2
    assert position == len(signature)
    return out


def main():
    repo = Path(__file__).resolve().parents[3]
    openssl = os.environ.get('OPENSSL', 'openssl')
    vectors = {}
    with tempfile.TemporaryDirectory(prefix='matter-synthetic-') as directory:
        work = Path(directory)
        (work/'openssl.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n', encoding='utf-8')
        def run(*args):
            return subprocess.check_output([openssl, *args], cwd=work, stderr=subprocess.PIPE,
                                           env={**os.environ, 'OPENSSL_CONF': str(work/'openssl.cnf')})
        keys = {}
        for scalar, name in enumerate(('root', 'icac', 'noc'), 21):
            key = bytes.fromhex('30310201010420') + scalar.to_bytes(32, 'big') + bytes.fromhex('a00a06082a8648ce3d030107')
            (work/(name+'.key.der')).write_bytes(key)
            run('ec', '-inform', 'DER', '-in', name+'.key.der', '-out', name+'.pem')
            public = run('pkey', '-in', name+'.pem', '-pubout', '-outform', 'DER')[-65:]
            assert len(public) == 65 and public[0] == 4
            run('pkey', '-in', name+'.pem', '-pubout', '-out', name+'.pub.pem')
            keys[name] = public
        names = {'root': [(20, 21)], 'icac': [(19, 22)], 'noc': [(21, 1), (17, 23)]}
        algorithm = bytes.fromhex('300a06082a8648ce3d040302')
        key_algorithm = bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107')
        before, after = datetime.datetime(2025, 1, 1), datetime.datetime(2035, 1, 1)
        epoch = datetime.datetime(2000, 1, 1)
        for serial, name in enumerate(('root', 'icac', 'noc'), 21):
            issuer = 'root' if name != 'noc' else 'icac'
            ca = name != 'noc'
            subject_der, subject_tlv = dn(names[name])
            issuer_der, issuer_tlv = dn(names[issuer])
            skid, akid = (hashlib.sha1(keys[n]).digest() for n in (name, issuer))
            # Same regression shape as a maximally padded chain: the SAN value
            # is intentionally opaque/unsupported, noncritical, and signed.
            opaque = extension(17, der(4, b'S'*100))
            extensions = [extension(19, seq(b'\x01\x01\xff' if ca else b''), True),
                          extension(15, der(3, b'\x01\x06' if ca else b'\x07\x80'), True)]
            ext_tlv = b'\x37\x0a\x35\x01' + bytes([0x29 if ca else 0x28, 1]) + b'\x18' + uint(2, 96 if ca else 1)
            if not ca:
                extensions.append(extension(37, seq(der(6, bytes.fromhex('2b06010505070302')), der(6, bytes.fromhex('2b06010505070301'))), True))
                ext_tlv += b'\x36\x03\x04\x02\x04\x01\x18'
            extensions += [extension(14, der(4, skid)), extension(35, seq(der(0x80, akid))), opaque]
            ext_tlv += octets(4, skid) + octets(5, akid) + octets(6, opaque) + b'\x18'
            tbs = seq(der(0xa0, b'\x02\x01\x02'), der(2, bytes([serial])), algorithm, issuer_der,
                      seq(der(23, before.strftime('%y%m%d%H%M%SZ').encode()), der(23, after.strftime('%y%m%d%H%M%SZ').encode())),
                      subject_der, seq(key_algorithm, der(3, b'\0'+keys[name])), der(0xa3, seq(*extensions)))
            (work/'tbs.der').write_bytes(tbs)
            signature = run('dgst', '-sha256', '-sign', issuer+'.pem', 'tbs.der')
            (work/'signature.der').write_bytes(signature)
            run('dgst', '-sha256', '-verify', issuer+'.pub.pem', '-signature', 'signature.der', 'tbs.der')
            certificate = seq(tbs, algorithm, der(3, b'\0'+signature))
            (work/(name+'.crt.der')).write_bytes(certificate)
            run('x509', '-inform', 'DER', '-in', name+'.crt.der', '-noout')
            tlv = b'\x15' + octets(1, bytes([serial])) + uint(2, 1) + issuer_tlv[:1] + b'\x03' + issuer_tlv[2:]
            tlv += uint(4, int((before-epoch).total_seconds())) + uint(5, int((after-epoch).total_seconds()))
            tlv += subject_tlv[:1] + b'\x06' + subject_tlv[2:] + uint(7, 1) + uint(8, 1) + octets(9, keys[name])
            tlv += ext_tlv + octets(11, raw_signature(signature)) + b'\x18'
            assert len(tlv) <= 400 and len(certificate) <= 600
            vectors['synthetic_'+name+'_tlv'] = tlv
            vectors['synthetic_'+name+'_der'] = certificate
    text = ('/* SPDX-License-Identifier: Apache-2.0\n'
            ' * Generated by fixtures/generate_synthetic_operational.py.\n'
            ' * Public TEST scalars 21..23, synthetic IDs, signed opaque SAN.\n'
            ' * No captured certificates. Never use these keys on a device. */\n')
    for name, value in vectors.items():
        text += 'static const uint8_t '+name+'[]={\n'
        for offset in range(0, len(value), 16):
            text += '    '+','.join(f'0x{b:02x}' for b in value[offset:offset+16])+',\n'
        text += '};\n'
    (repo/'tools/matter/tests/test_synthetic_operational_vectors.h').write_text(text, encoding='utf-8', newline='\n')
    print('Generated synthetic DER/TLV chain; OpenSSL verified all three TBS signatures.')


if __name__ == '__main__':
    main()
