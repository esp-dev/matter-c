"""Real multicast service-listing/known-answer/TC checks against a disposable Linux node.
No raw sockets or privileges. Independent DNS encoder/decoder; artifacts contain
public discovery packets only. Private test credentials stay in the given folder.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import time


def dns_name(value):
    return b''.join(bytes([len(x)])+x.encode('ascii') for x in value.rstrip('.').split('.'))+b'\0'


def read_name(data, pos, seen=()):
    if pos in seen or len(seen)>128:
        raise ValueError('DNS name cycle')
    labels=[]
    while True:
        length=data[pos]; pos+=1
        if not length:
            return '.'.join(labels)+'.', pos
        if length&0xc0==0xc0:
            target=((length&63)<<8)|data[pos]
            suffix,_=read_name(data,target,seen+(pos-1,))
            return '.'.join(labels)+('.' if labels else '')+suffix,pos+1
        if length>63 or pos+length>len(data):
            raise ValueError('DNS label')
        labels.append(data[pos:pos+length].decode('ascii')); pos+=length


def decode(data):
    _,flags,nq,na,ns,nr=struct.unpack_from('!6H',data)
    pos=12
    for _ in range(nq):
        _,pos=read_name(data,pos); pos+=4
    records=[]
    for _ in range(na+ns+nr):
        owner,pos=read_name(data,pos)
        typ,cl,ttl,length=struct.unpack_from('!HHIH',data,pos); pos+=10
        end=pos+length
        if end>len(data): raise ValueError('DNS RDATA')
        if typ==12:
            target,_=read_name(data,pos); payload=dns_name(target)
        elif typ==33:
            target,_=read_name(data,pos+6); payload=data[pos:pos+6]+dns_name(target)
        elif typ==47:
            target,bitmap=read_name(data,pos); payload=dns_name(target)+data[bitmap:end]
        else:
            payload=data[pos:end]
        records.append((owner.lower(),typ,cl&0x7fff,ttl,payload))
        pos=end
    if pos!=len(data): raise ValueError('DNS trailing data')
    return flags,records


def query(owner=None,typ=12,known=(),tc=False,ttl=60):
    question=dns_name(owner)+struct.pack('!HH',typ,1) if owner else b''
    answers=b''.join(dns_name(o)+struct.pack('!HHIH',t,c,ttl,len(d))+d for o,t,c,_,d in known)
    return struct.pack('!6H',0,0x200 if tc else 0,int(owner is not None),len(known),0,0)+question+answers


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('node','credentials','output'): p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--interface',required=True,type=int)
    a=p.parse_args(); out=a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    args=[str(a.node.resolve()),'--interface',str(a.interface),'--credentials',str(a.credentials.resolve()),
          '--state',str(out/'state.tlv'),'--port','5544','--seconds','120']
    checks=[]; packets=[]
    def check(label,ok):
        checks.append({'name':label,'status':'PASS' if ok else 'FAIL'})
        (out/'result.json').write_text(json.dumps(checks,indent=2)+'\n')
        print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok: raise AssertionError(label)
    with (out/'node.log').open('w') as log, (out/'node.err').open('w') as err:
        child=subprocess.Popen(args,stdout=log,stderr=err,env=env)
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline and child.poll() is None:
                text=(out/'node.log').read_text()
                if 'PUBLISHED' in text: break
                time.sleep(.05)
            check('published',child.poll() is None and 'PUBLISHED' in text)
            instance,service,host=re.search(r'NODE instance=(\S+) service=(\S+) host=(\S+)',text).groups()
            instance=(instance+'.'+service).lower(); service=service.lower(); host=host.lower()
            with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,a.interface)
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
                sock.bind(('::',5353))
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_JOIN_GROUP,socket.inet_pton(socket.AF_INET6,'ff02::fb')+struct.pack('@I',a.interface))
                group=('ff02::fb',5353,0,a.interface)
                meta='_services._dns-sd._udp.local.'
                listing_targets=set()
                def receive(duration,listing=False):
                    result=[]; until=time.monotonic()+duration
                    while time.monotonic()<until:
                        if not select.select([sock],[],[],max(0,until-time.monotonic()))[0]: break
                        data,source=sock.recvfrom(4096)
                        try: flags,records=decode(data)
                        except (ValueError,IndexError,struct.error,UnicodeError): continue
                        ours=any(r[0]==meta and r[1]==12 and r[3]==120 and
                                 read_name(r[4],0)[0].lower() in listing_targets for r in records) if listing else \
                             any(r[0] in (instance,host) and r[3]==120 for r in records)
                        if flags&0x8000 and ours:
                            stamp=time.monotonic(); result.append((stamp,records))
                            packets.append({'time':stamp,'source':source[0],'hex':data.hex()})
                    return result
                def send(data): sock.sendto(data,group)
                def begin(): receive(1.15)  # preserve publisher's existing multicast rate gate
                def types(received): return {r[1] for _,rr in received for r in rr}
                receive(2.3)  # finish unsolicited second announcement
                send(query(service)); baseline=receive(.8)
                records=[r for _,rr in baseline for r in rr]
                check('baseline PTR/SRV/TXT/A/AAAA',types(baseline)=={1,12,33,16,28})
                ptr=next(r for r in records if r[1]==12)
                srv=next(r for r in records if r[1]==33); txt=next(r for r in records if r[1]==16)
                fields={}; pos=0
                while pos<len(txt[4]):
                    size=txt[4][pos]; pos+=1
                    key,value=txt[4][pos:pos+size].decode().split('=',1); fields[key]=value; pos+=size
                disc=int(fields['D'])
                listing_targets={service,f'_l{disc}._sub.{service}',f'_s{disc>>8}._sub.{service}'}
                if int(fields.get('CM','0')): listing_targets.add(f'_cm._sub.{service}')
                begin(); send(query(meta)); result=receive(.8,listing=True)
                listing_rows=[r for _,rr in result for r in rr]
                check('service enumeration base and active subtypes',bool(listing_rows) and types(result)=={12} and
                      all(r[0]==meta for r in listing_rows) and
                      {read_name(r[4],0)[0].lower() for r in listing_rows}==listing_targets)
                for ttl,expect in ((59,True),(60,False)):
                    begin(); send(query(meta,known=listing_rows,ttl=ttl))
                    check('enumeration known TTL '+str(ttl),bool(receive(.8,listing=True))==expect)
                for ttl,expect in ((59,True),(60,False),(61,False)):
                    begin(); send(query(service,known=[ptr],ttl=ttl)); result=receive(.8)
                    check('PTR known TTL '+str(ttl),bool(result)==expect)
                begin(); send(query(instance,255,[srv])); result=receive(.8)
                check('partial ANY excludes known SRV also in Additional',types(result)=={1,16,28})
                begin(); send(query(instance,255,[srv,txt])); check('all answers known',not receive(.8))
                begin(); start=time.monotonic(); send(query(instance,255,tc=True)); result=receive(.9)
                elapsed=result[0][0]-start if result else 0
                check('TC no continuation waits 400-500ms plus scheduler',bool(result) and .39<=elapsed<=.75)
                begin(); start=time.monotonic(); send(query(instance,255,tc=True)); early=receive(.1)
                send(query(known=[srv])); result=early+receive(.8)
                elapsed=result[0][0]-start if result else 0
                check('TC final partial Answer keeps deadline and omits SRV',types(result)=={1,16,28} and .39<=elapsed<=.75)
                begin(); send(query(instance,255,tc=True)); early=receive(.1)
                send(query(known=[srv,txt])); check('TC final all known suppresses response',not early and not receive(.8))
                begin(); start=time.monotonic(); send(query(instance,255,tc=True)); early=receive(.25)
                continued=time.monotonic(); send(query(known=[srv],tc=True)); result=early+receive(.95)
                elapsed=result[0][0]-continued if result else 0
                check('TC continuation restarts 400-500ms wait',types(result)=={1,16,28} and .39<=elapsed<=.75)
                begin(); send(query(known=[srv,txt],tc=True)); check('orphan continuation ignored',not receive(.8))
                begin(); send(query(service)); check('recovery after suppression/TC',types(receive(.8))=={1,12,33,16,28})
                # NSEC is synthesized only for names owned by the DUT.
                nsecs={}
                for owner,expected in ((host,b'\x00\x04\x40\x00\x00\x08'),
                                       (instance,b'\x00\x05\x00\x00\x80\x00\x40')):
                    begin(); send(query(owner,15)); result=receive(.8)
                    rr=[r for _,rows in result for r in rows]
                    check('NSEC bitmap '+owner,len(rr)==1 and rr[0][1:4]==(47,1,120) and
                          rr[0][0]==owner and rr[0][4].lower()==dns_name(owner)+expected)
                    nsecs[owner]=rr[0]
                for ttl,expect in ((59,True),(60,False)):
                    begin(); send(query(host,15,[nsecs[host]],ttl=ttl)); result=receive(.8)
                    check('NSEC known TTL '+str(ttl),bool(result)==expect)
                begin(); send(query(host,15,tc=True)); early=receive(.1)
                send(query(known=[nsecs[host]])); check('NSEC TC continuation suppresses',not early and not receive(.8))
                begin(); send(query(service,1)); check('shared name no negative answer',not receive(.8))
                begin(); send(query('absent.local.',1)); check('unknown name no negative answer',not receive(.8))
                begin(); send(query(instance,47)); check('explicit NSEC query',types(receive(.8))=={47})
                # Legacy unicast is unambiguous on an ephemeral port even with
                # several responders sharing port5353 in the same Linux host.
                with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as legacy:
                    legacy.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,a.interface)
                    legacy.settimeout(2)
                    request=bytearray(query(host,15)); request[0:2]=b'\x12\x34'
                    legacy.sendto(request,group); data,_=legacy.recvfrom(4096)
                    flags,rr=decode(data)
                    check('legacy NSEC ID/question/TTL',data[:2]==b'\x12\x34' and flags==0x8400 and
                          struct.unpack_from('!H',data,4)[0]==1 and len(rr)==1 and rr[0][1:4]==(47,1,10))
                begin(); send(query(service)); check('recovery after NSEC',types(receive(.8))=={1,12,33,16,28})
                for typ in (1,28):
                    begin(); send(query(host,typ)); result=receive(.8)
                    rr=[r for _,rows in result for r in rows]
                    check('address query '+str(typ)+' includes both families',types(result)=={1,28} and
                          {r[4] for r in rr if r[1] in (1,28)}=={r[4] for r in records if r[1] in (1,28)})
                def duplicate(rows,ttl):
                    body=b''.join(dns_name(o)+struct.pack('!HHIH',t,c|0x8000,ttl,len(d))+d for o,t,c,_,d in rows)
                    send(struct.pack('!6H',0,0x8400,0,len(rows),0,0)+body)
                for ttl in (119,121):
                    begin(); send(query(instance,255,tc=True)); early=receive(.08)
                    duplicate([srv],ttl); result=early+receive(.8)
                    check('duplicate SRV TTL '+str(ttl),types(result)==({1,16,28,33} if ttl==119 else {1,16,28}))
                begin(); send(query(instance,255,tc=True)); early=receive(.08)
                duplicate([srv,txt],121); check('duplicate full answer suppresses pending multicast',not early and not receive(.8))
                begin(); send(query(service)); check('recovery after duplicate responses',types(receive(.8))=={1,12,33,16,28})
                check('node remains alive',child.poll() is None)
        finally:
            if child.poll() is None: child.terminate()
            try: child.wait(timeout=15)
            except subprocess.TimeoutExpired: child.kill(); child.wait(); raise
            (out/'packets.json').write_text(json.dumps(packets,indent=2)+'\n')
    check('clean stop',child.returncode==0)
    check('stderr empty',not (out/'node.err').stat().st_size)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
