"""Independent Core 1.6.1 CASE wire oracle (Python stdlib + OpenSSL).
Run test_case.exe <existing-output-dir> first. Fixed PUBLIC TEST ephemeral
scalars 21/22 and fixture root 8; no Matter code or mbedTLS in this verifier.
"""
import hashlib, hmac, os, subprocess, sys
from pathlib import Path
work=Path(sys.argv[1]).resolve()
chip=len(sys.argv)==3 and sys.argv[2]=='chip'
assert len(sys.argv)==2 or chip
openssl=os.environ.get('OPENSSL','openssl')
gcc=os.environ.get('GCC','gcc')
env=dict(os.environ)
if Path(gcc).parent != Path('.'):
    env['PATH']=str(Path(gcc).parent)+os.pathsep+env.get('PATH','')
def run(*args): return subprocess.check_output([openssl,*args],cwd=work,stderr=subprocess.PIPE)
def save(n,b): (work/n).write_bytes(b); return str(work/n)
def hkdf(ikm,salt,info,size):
    prk=hmac.digest(salt,ikm,'sha256'); out=b''; last=b''
    for i in range(1,(size+31)//32+1): last=hmac.digest(prk,last+info+bytes([i]),'sha256'); out+=last
    return out[:size]
def parse(data):
    def item(i):
        control=data[i]; i+=1; kind=control&31; tag=None
        if control>>5==1: tag=data[i]; i+=1
        else: assert control>>5==0
        if kind in (21,22,23):
            v={}
            while data[i]!=24:
                t,x,i=item(i); assert t not in v; v[t]=x
            return tag,v,i+1
        if kind in (4,5,6,7):
            w=1<<(kind-4); return tag,int.from_bytes(data[i:i+w],'little'),i+w
        if kind in (16,17,18,19):
            w=1<<(kind-16); n=int.from_bytes(data[i:i+w],'little'); i+=w
            return tag,data[i:i+n],i+n
        if kind in (8,9): return tag,kind==9,i
        raise AssertionError(kind)
    t,v,n=item(0); assert t is None and n==len(data); return v
# Certificates need only their top-level point (nested extensions can repeat
# anonymous tags), so skip container values rather than decode their schema.
def point(cert):
    needle=b'\x30\x09\x41\x04'; pos=cert.index(needle); return cert[pos+3:pos+68]
def octets(tag,b):
    return bytes([0x30 if len(b)<256 else 0x31,tag])+len(b).to_bytes(1 if len(b)<256 else 2,'little')+b
def spki(p): return bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')+p
def integer(b):
    b=b.lstrip(b'\0') or b'\0'
    if b[0]&128: b=b'\0'+b
    return bytes([2,len(b)])+b
def key(k):
    save('private.der',bytes.fromhex('30310201010420')+k.to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107'))
    run('ec','-inform','DER','-in','private.der','-out','private.pem')
    return run('ec','-in','private.pem','-pubout','-outform','DER')[-65:]
subprocess.run([gcc,'-std=c99','-Wall','-Wextra','-Werror',str(Path(__file__).parents[1]/'tests/case_openssl_ccm.c'),'-lcrypto','-o',str(work/'ccm.exe')],check=True,env=env)
def decrypt(k,iv,aad,cipher,valid=True):
    args=[save(n,b) for n,b in zip(('key.bin','iv.bin','aad.bin','cipher.bin'),(k,iv,aad,cipher))]
    r=subprocess.run([str(work/'ccm.exe'),*args,str(work/'plain.bin')],env=env)
    assert (r.returncode==0)==valid
    if valid: return (work/'plain.bin').read_bytes()
s1,s2,s3=[(work/f'sigma{i}.bin').read_bytes() for i in (1,2,3)]
a,b,c=map(parse,(s1,s2,s3)); root=key(8)
compressed=hkdf(root[1:],(1).to_bytes(8,'big'),b'CompressedFabric',8)
ipk=hkdf(bytes([0x42])*16,compressed,b'GroupKey v1.0',16)
assert a[3]==hmac.digest(ipk,a[1]+root+(1).to_bytes(8,'little')+(100).to_bytes(8,'little'),'sha256')
assert a[4]==key(21) and b[3]==key(22)
key(21); save('peer.der',spki(b[3])); run('pkey','-pubin','-inform','DER','-in','peer.der','-out','peer.pem')
shared=run('pkeyutl','-derive','-inkey','private.pem','-peerkey','peer.pem'); assert len(shared)==32
h=lambda x:hashlib.sha256(x).digest()
k2=hkdf(shared,ipk+b[1]+b[3]+h(s1),b'Sigma2',16)
k3=hkdf(shared,ipk+h(s1+s2),b'Sigma3',16)
for sigma,key_value,cipher,own,peer in ((2,k2,b[4],b[3],a[4]),(3,k3,c[1],a[4],b[3])):
    nonce=f'NCASE_Sigma{sigma}N'.encode(); t=parse(decrypt(key_value,nonce,b'',cipher))
    signed=b'\x15'+octets(1,t[1])+(octets(2,t[2]) if 2 in t else b'')+octets(3,own)+octets(4,peer)+b'\x18'
    signature=integer(t[3][:32])+integer(t[3][32:]); signature=bytes([0x30,len(signature)])+signature
    save('signed.bin',signed); save('sig.der',signature); save('signer.der',spki(point(t[1])))
    run('pkey','-pubin','-inform','DER','-in','signer.der','-out','signer.pem')
    run('dgst','-sha256','-verify','signer.pem','-signature','sig.der','signed.bin')
    decrypt(key_value,nonce,b'',cipher[:-1]+bytes([cipher[-1]^1]),False)
wrong=hkdf(shared,ipk+b[1]+b[3]+h(s1+b'\0'),b'Sigma2',16)
decrypt(wrong,b'NCASE_Sigma2N',b'',b[4],False)
keys=hkdf(shared,ipk+h(s1+s2+s3),b'SessionKeys',48)
assert (work/'challenge.bin').read_bytes()==keys[32:]
packet=(work/'secure.bin').read_bytes(); nonce=packet[3:4]+packet[4:8]+(101).to_bytes(8,'little')
assert decrypt(keys[:16],nonce,packet[:8],packet[8:])==bytes.fromhex('01023412010015')
decrypt(keys[:16],packet[3:4]+packet[4:8]+bytes(8),packet[:8],packet[8:],False)
print('PASS independent OpenSSL CASE: DestinationID, ECDH, Sigma2/3 CCM/signatures, transcript KDF, challenge and CASE nonce; corruption/wrong transcript/PASE nonce rejected')

# Independent resumed path: both MICs use empty plaintext, the OLD ID belongs
# to Sigma1; Sigma2 uses NEW. Explicit CHIP traffic KDF uses OLD instead.
r1,r2=[parse((work/f'resume{i}.bin').read_bytes()) for i in (1,2)]
assert r1[6]!=r2[1]
salt1=r1[1]+r1[6]; salt2=r1[1]+r2[1]
assert decrypt(hkdf(shared,salt1,b'Sigma1_Resume',16),b'NCASE_SigmaS1',b'',r1[7])==b''
assert decrypt(hkdf(shared,salt2,b'Sigma2_Resume',16),b'NCASE_SigmaS2',b'',r2[2])==b''
decrypt(hkdf(shared,salt1,b'Sigma2_Resume',16),b'NCASE_SigmaS2',b'',r2[2],False)
rkeys=hkdf(shared,salt1 if chip else salt2,b'SessionResumptionKeys',48)
assert rkeys!=keys and (work/'resume-challenge.bin').read_bytes()==rkeys[32:]
packet=(work/'resume-secure.bin').read_bytes(); nonce=packet[3:4]+packet[4:8]+(101).to_bytes(8,'little')
assert decrypt(rkeys[:16],nonce,packet[:8],packet[8:])==bytes.fromhex('01023412010015')
decrypt(keys[:16],nonce,packet[:8],packet[8:],False)
decrypt(hkdf(shared,salt2 if chip else salt1,b'SessionResumptionKeys',48)[:16],nonce,packet[:8],packet[8:],False)
print(('CHIP profile: ' if chip else 'SPEC profile: ')+ 'PASS independent OpenSSL resumption: S1/S2 MIC, old/new ID salts, fresh traffic KDF/challenge/CCM; wrong MIC salt, other profile and old traffic key rejected')
