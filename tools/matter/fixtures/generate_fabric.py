"""Independent M10e commissioning certificates. Public TEST scalars 8..16.
Construct DER/TLV from Core 1.6.1 schema; sign and verify with OpenSSL, no C code.
Dates 2020..2049 and explicit test identities. Never production provisioning.
"""
from pathlib import Path
import os, subprocess, hashlib, datetime, base64
repo=Path(__file__).resolve().parents[3]; work=repo/'build/m10e-oracle'; work.mkdir(parents=True,exist_ok=True)
openssl=os.environ.get('OPENSSL','openssl')
def run(*args): return subprocess.check_output([openssl,*args],cwd=work,stderr=subprocess.PIPE)
def der(t,b):
    n=len(b); return bytes([t])+(bytes([n]) if n<128 else b'\x81'+bytes([n]) if n<256 else b'\x82'+n.to_bytes(2,'big'))+b
def seq(*parts): return der(0x30,b''.join(parts))
def integer(n):
    b=n.to_bytes(max(1,(n.bit_length()+7)//8),'big'); return der(2,(b'\0' if b[0]&128 else b'')+b)
def oid(b): return der(6,bytes.fromhex(b))
def dn(items): return seq(*(der(0x31,seq(oid('2b0601040182a27c01'+f'{tag-16:02x}'),der(12,f'{value:016X}'.encode()))) for tag,value in items))
def scalar(tag,n):
    w=next(w for w in (1,2,4,8) if n<1<<(8*w)); return bytes([0x24+(w.bit_length()-1),tag])+n.to_bytes(w,'little')
def octets(tag,b): return bytes([0x30 if len(b)<256 else 0x31,tag])+len(b).to_bytes(1 if len(b)<256 else 2,'little')+b
def dntlv(tag,items): return bytes([0x37,tag])+b''.join(scalar(k,v) for k,v in items)+b'\x18'
def children(data):
    result=[]
    while data:
        h=2; n=data[1]
        if n>=128: h+=n&127; n=int.from_bytes(data[2:h],'big')
        result.append(data[h:h+n]); data=data[h+n:]
    return result
keys={}
for k in range(8,17):
    (work/f'key{k}.der').write_bytes(bytes.fromhex('30310201010420')+k.to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107'))
    run('ec','-inform','DER','-in',f'key{k}.der','-out',f'key{k}.pem')
    point=run('ec','-in',f'key{k}.pem','-pubout','-outform','DER')[-65:]
    keys[k]=(point,hashlib.sha1(point).digest())
alg=bytes.fromhex('300a06082a8648ce3d040302')
spki=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
epoch=datetime.datetime(2000,1,1,tzinfo=datetime.timezone.utc)
before=int((datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc)-epoch).total_seconds())
after=int((datetime.datetime(2049,12,31,23,59,59,tzinfo=datetime.timezone.utc)-epoch).total_seconds())
def certificate(name,key,issuer,subject,issuer_dn,ca):
    pub,skid=keys[key]; akid=keys[issuer][1]
    def ext(id,value,critical=False): return seq(oid('551d'+f'{id:02x}'),*( [der(1,b'\xff')] if critical else []),der(4,value))
    exts=[ext(19,seq(der(1,b'\xff'),integer(1)) if ca else seq(),True),ext(15,der(3,b'\x01\x06' if ca else b'\x07\x80'),True)]
    if not ca: exts+=[ext(37,seq(oid('2b06010505070301'),oid('2b06010505070302')),True)]
    exts+=[ext(14,der(4,skid)),ext(35,seq(der(0x80,akid)))]
    tbs=seq(der(0xa0,integer(2)),integer(1),alg,dn(issuer_dn),seq(der(23,b'200101000000Z'),der(23,b'491231235959Z')),dn(subject),spki+pub,der(0xa3,seq(*exts)))
    (work/'tbs.der').write_bytes(tbs); sig=run('dgst','-sha256','-sign',f'key{issuer}.pem','tbs.der')
    rs=children(children(sig)[0]); raw=b''.join(v.lstrip(b'\0').rjust(32,b'\0') for v in rs); assert len(raw)==64
    full=seq(tbs,alg,der(3,b'\0'+sig)); (work/f'{name}.der').write_bytes(full)
    run('x509','-inform','DER','-in',f'{name}.der','-out',f'{name}.pem')
    tlv=b'\x15'+octets(1,b'\1')+scalar(2,1)+dntlv(3,issuer_dn)+scalar(4,before)+scalar(5,after)+dntlv(6,subject)+scalar(7,1)+scalar(8,1)+octets(9,pub)
    tlv+=bytes.fromhex('37 0a 35 01')+(b'\x29\x01'+scalar(2,1) if ca else b'\x28\x01')+b'\x18'+scalar(2,0x60 if ca else 1)
    if not ca: tlv+=bytes.fromhex('36 03 04 01 04 02 18')
    tlv+=octets(4,skid)+octets(5,akid)+b'\x18'+octets(11,raw)+b'\x18'; assert len(tlv)<=400
    return tlv
# M10h peer on the SAME fabric as noc0, without regenerating old random signatures.
if '--acl-peer-only' in __import__('sys').argv:
    certificate('root',8,8,[(20,1)],[(20,1)],True)
    data=certificate('acl_peer',12,8,[(17,102),(21,1)],[(20,1)],False)
    run('verify','-attime','1791417600','-CAfile','root.pem','acl_peer.pem')
    out='/* Public TEST scalar12, Node102/Fabric1; OpenSSL signed/verified. */\nstatic const uint8_t acl_peer_noc[]={\n'
    out+=''.join('    '+','.join(f'0x{v:02x}' for v in data[i:i+16])+',\n' for i in range(0,len(data),16))+'};\n'
    (repo/'tools/matter/fixtures/acl_peer_vectors.h').write_text(out)
    print('PASS OpenSSL ACL peer certificate generated/verified')
    raise SystemExit(0)

vectors={'root':certificate('root',8,8,[(20,1)],[(20,1)],True)}
vectors['icac']=certificate('icac',9,8,[(19,1)],[(20,1)],True)
for i in range(7):
    intermediate=i==6
    vectors[f'noc{i}']=certificate(f'noc{i}',10+i,9 if intermediate else 8,[(17,100+i),(21,i+1)],[(19,1)] if intermediate else [(20,1)],False)
    args=['verify','-attime','1791417600','-CAfile','root.pem']
    if intermediate: args+=['-untrusted','icac.pem']
    run(*args,f'noc{i}.pem')
vectors['invalid_node']=certificate('invalid_node',10,8,[(17,0),(21,1)],[(20,1)],False)
vectors['invalid_fabric']=certificate('invalid_fabric',10,8,[(17,100),(21,0)],[(20,1)],False)
# Same root/fabric as noc0, but the next CSR's key (11) to exercise FabricConflict.
vectors['conflict']=certificate('conflict',11,8,[(17,101),(21,1)],[(20,1)],False)
out='/* Public TEST scalar keys 8..16; generated independently by generate_fabric.py */\n'
for name,data in vectors.items():
    out+=f'static const uint8_t fab_{name}[]={{\n'+''.join('    '+','.join(f'0x{x:02x}' for x in data[i:i+16])+',\n' for i in range(0,len(data),16))+'};\n'
(repo/'tools/matter/tests/test_fabric_vectors.h').write_bytes(out.encode())
print('PASS OpenSSL independent RCAC/NOC and ICAC chains; exported TEST TLV certificates')
