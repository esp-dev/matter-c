"""Verify test_opcreds exports with OpenSSL, independent of the C/mbedTLS stack.
Usage: test_opcreds.exe build/m10d-oracle; python tools/matter/fixtures/verify_opcreds.py build/m10d-oracle
The export directory must exist. Uses only public TEST DAC (scalar 3).
"""
from pathlib import Path
import base64, os, re, subprocess, sys
repo=Path(__file__).resolve().parents[3]
work=Path(sys.argv[1]).resolve()
openssl=os.environ.get('OPENSSL','openssl')
def run(*args,ok=True):
    r=subprocess.run([openssl,*args],cwd=work,capture_output=True)
    assert (r.returncode==0)==ok,(args,r.stdout,r.stderr)
    return r.stdout
header=(repo/'tools/matter/tests/test_opcreds_vectors.h').read_text()
body=re.search(r'oc_public\[\]=\{(.*?)\};',header,re.S)[1]
point=bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',body))
spki=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')+point
pem=b'-----BEGIN PUBLIC KEY-----\n'+base64.encodebytes(spki)+b'-----END PUBLIC KEY-----\n'
(work/'dac-public.pem').write_bytes(pem)
def integer(b):
    b=b.lstrip(b'\0') or b'\0'
    if b[0]&128: b=b'\0'+b
    return b'\x02'+bytes([len(b)])+b
for kind in ('attestation','csr'):
    raw=(work/(kind+'-signature.bin')).read_bytes(); assert len(raw)==64
    sig=integer(raw[:32])+integer(raw[32:]); sig=b'\x30'+bytes([len(sig)])+sig
    (work/'signature.der').write_bytes(sig)
    tbs=(work/(kind+'-tbs.bin')).read_bytes()
    run('dgst','-sha256','-verify','dac-public.pem','-signature','signature.der',kind+'-tbs.bin')
    # Wrong session challenge and altered signed elements both fail independently.
    for index in (-1,5):
        bad=bytearray(tbs); bad[index]^=1; (work/'tampered.bin').write_bytes(bad)
        run('dgst','-sha256','-verify','dac-public.pem','-signature','signature.der','tampered.bin',ok=False)
run('req','-inform','DER','-in','csr.der','-verify','-noout')
print('PASS OpenSSL: attestation/CSR outer DAC signatures, inner PKCS#10 proof, tampered elements and wrong session challenge rejected')
