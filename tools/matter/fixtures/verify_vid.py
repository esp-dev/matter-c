"""Independent OpenSSL check of test_fabric.exe <export-prefix> output.

Only public fixture keys/signatures; no provisioned credentials are exported.
Core 1.6.1 6.4.10.1 and TC-OPCREDS-3.8 define this transcript layout.
"""
import base64
import os
from pathlib import Path
import subprocess
import sys

prefix = Path(sys.argv[1]).resolve()
openssl = os.environ.get('OPENSSL', 'openssl')


def integer(value):
    value = value.lstrip(b'\0') or b'\0'
    if value[0] & 128:
        value = b'\0' + value
    return b'\x02' + bytes([len(value)]) + value


for kind, size in [('plain', 126), ('statement', 211)]:
    stem = str(prefix) + '-' + kind
    tbs = Path(stem + '-tbs.bin').read_bytes()
    raw = Path(stem + '-signature.bin').read_bytes()
    point = Path(stem + '-public.bin').read_bytes()
    assert len(tbs) == size and len(raw) == 64 and len(point) == 65
    assert tbs[:33] == b'\x01' + bytes(range(1, 33))
    assert tbs[33:49] == bytes(range(0xa0, 0xb0)) and tbs[49:52] == b'\x02\x01\x04'
    assert tbs[124:126] == bytes.fromhex('6a01')
    if kind == 'statement':
        assert tbs[126:] == b'\x5a' * 85
    der = integer(raw[:32]) + integer(raw[32:])
    Path(stem + '-signature.der').write_bytes(b'\x30' + bytes([len(der)]) + der)
    spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + point
    Path(stem + '-public.pem').write_bytes(b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(spki) + b'-----END PUBLIC KEY-----\n')
    for offset in [None, 0, 1, 33, 49, 50, 51, 116, 124, size-1]:
        data = bytearray(tbs)
        if offset is not None:
            data[offset] ^= 1
        Path(stem + '-check.bin').write_bytes(data)
        result = subprocess.run([openssl, 'dgst', '-sha256', '-verify', stem + '-public.pem',
                                 '-signature', stem + '-signature.der', stem + '-check.bin'], capture_output=True)
        assert (result.returncode == 0) == (offset is None), (kind, offset, result.stderr)
print('PASS OpenSSL VID: NOC signatures with/without statement; altered transcript/challenges rejected')
