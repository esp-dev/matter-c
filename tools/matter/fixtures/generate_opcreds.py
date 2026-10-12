"""Offline TEST provisioning, OpenSSL oracle; never production credentials.
Copies the existing M07g public chain (DAC scalar=3); independently generates a
CMS development CD signed by public test scalar=4. No C code is imported.
The CD signer is local test trust, NOT a CSA/DCL trust anchor or certificate ID.
"""
from pathlib import Path
import os, re, subprocess
repo=Path(__file__).resolve().parents[3]
work=repo/'build/m10d-oracle'; work.mkdir(parents=True, exist_ok=True)
openssl=os.environ.get('OPENSSL','openssl')
(work/'openssl.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n')
def run(*args):
    return subprocess.check_output([openssl,*args],cwd=work,stderr=subprocess.PIPE,
        env={**os.environ,'OPENSSL_CONF':str(work/'openssl.cnf')})
key=bytes.fromhex('30310201010420')+(4).to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107')
(work/'cd-key.der').write_bytes(key)
run('ec','-inform','DER','-in','cd-key.der','-out','cd-key.pem')
run('req','-new','-x509','-key','cd-key.pem','-subj','/CN=LOCAL TEST CD','-days','3650',
    '-addext','subjectKeyIdentifier=hash','-out','cd-signer.pem')
# Canonical minimal-width TLV, Core 6.3.1. VID FFF1, PID8000, sensor 0510.
cd=bytes.fromhex('15 24 00 01 25 01 f1 ff 36 02 05 00 80 18 25 03 10 05 2c 04 13')
cd+=b'LOCAL-TEST-000000001'+bytes.fromhex('24 05 00 24 06 00 24 07 01 24 08 00 18')
(work/'cd.tlv').write_bytes(cd)
run('cms','-sign','-binary','-nodetach','-noattr','-nosmimecap','-keyid','-nocerts','-md','sha256',
    '-in','cd.tlv','-signer','cd-signer.pem','-inkey','cd-key.pem','-outform','DER','-out','cd.der')
assert run('cms','-verify','-binary','-inform','DER','-in','cd.der','-certfile','cd-signer.pem','-noverify')==cd
source=(repo/'tools/matter/tests/test_attestation_vectors.h').read_text()
values={}
for name in ('paa','pai','dac','public'):
    body=re.search(r'static const uint8_t att_'+name+r'\[\] = \{(.*?)\};',source,re.S)
    if not body:
        body=re.search(r'static const uint8_t att_'+name+r'\[\]\s*=\s*\{(.*?)\};',source,re.S)
    assert body,name
    values[name]=bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]{2})',body[1]))
values['cd']=(work/'cd.der').read_bytes()
out='/* Public TEST keys/identity only. Regenerate: fixtures/generate_opcreds.py */\n'
for name,data in values.items():
    out+='static const uint8_t oc_'+name+'[]={\n'
    out+=''.join('    '+','.join(f'0x{x:02x}' for x in data[i:i+16])+',\n' for i in range(0,len(data),16))+'};\n'
(repo/'tools/matter/tests/test_opcreds_vectors.h').write_bytes(out.encode())
print('PASS OpenSSL CMS development CD; exported DAC/PAI/PAA and CD fixtures')
