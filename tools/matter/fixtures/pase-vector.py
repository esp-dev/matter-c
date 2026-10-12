"""Independent, test-only Core 1.6.1 3.10 / 4.14.1 vector.

Python hashlib/hmac plus simple affine arithmetic, not production crypto.
Deliberately predictable randomness and x=1/y=2 MUST NOT be used in a device.
No dependencies on the C implementation or its serialized output.
M/N constants: draft-bar-cfrg-spake2plus-01 section 5; Copyright (c) 2020
IETF Trust / Tim Taubert / Christopher A. Wood. See licenses/IETF-BSD-2-Clause.txt.
"""
import hashlib
import hmac
import json

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b


def point(encoded):
    raw = bytes.fromhex(encoded)
    x = int.from_bytes(raw[1:], 'big')
    y = pow((x**3 - 3*x + B) % P, (P+1)//4, P)
    if y % 2 != raw[0] % 2:
        y = P-y
    assert (y*y-x*x*x+3*x-B) % P == 0
    return x, y


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y+v) % P == 0: return None
    m = ((3*x*x-3) * pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    z = (m*m-x-u) % P
    return z, (m*(x-z)-y) % P


def mul(n, a):
    out = None
    while n:
        if n & 1: out = add(out, a)
        a = add(a, a)
        n >>= 1
    return out


def enc(a): return b'\x04' + a[0].to_bytes(32, 'big') + a[1].to_bytes(32, 'big')
def mac(k, m): return hmac.digest(k, m, 'sha256')
def hkdf(k, info, size):
    prk = mac(b'', k)
    out, block = b'', b''
    for i in range(1, (size+31)//32+1):
        block = mac(prk, block+info+bytes([i]))
        out += block
    return out[:size]


G = point('036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')
M = point('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f')
Q = point('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49')
wide = hashlib.pbkdf2_hmac('sha256', (20202021).to_bytes(4, 'little'), b'\x42'*16, 1000, 80)
w0, w1 = (int.from_bytes(wide[i:i+40], 'big') % N for i in (0, 40))
pa, pb = enc(add(G, mul(w0, M))), enc(add(mul(2, G), mul(w0, Q)))
z, v = enc(mul(2, G)), enc(mul(2*w1, G))
random = bytes(range(32))
req = bytes.fromhex('15300120') + random + bytes.fromhex('25027b0025030000280418')
resp = bytes.fromhex('15300120') + random + bytes.fromhex('300220') + random + bytes.fromhex('2503c80135042501e803300210') + b'\x42'*16 + bytes.fromhex('1818')
context = hashlib.sha256(b'CHIP PAKE V1 Commissioning' + req + resp).digest()
tt = b''.join(len(a).to_bytes(8, 'little')+a for a in (context, b'', b'', enc(M), enc(Q), pa, pb, z, v, w0.to_bytes(32, 'big')))
ka_ke = hashlib.sha256(tt).digest()
kc = hkdf(ka_ke[:16], b'ConfirmationKeys', 32)
ca, cb = mac(kc[:16], pb), mac(kc[16:], pa)
session = hkdf(ka_ke[16:], b'SessionKeys', 48)
print(json.dumps({k: value.hex() for k, value in dict(request=req, response=resp,
    pake1=b'\x15\x30\x01\x41'+pa+b'\x18', pake2=b'\x15\x30\x01\x41'+pb+b'\x30\x02\x20'+cb+b'\x18',
    pake3=b'\x15\x30\x01\x20'+ca+b'\x18', finished=bytes(8), keys=session).items()}, indent=2))
