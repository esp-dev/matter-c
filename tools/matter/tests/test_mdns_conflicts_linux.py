"""Bounded multicast conflict scenarios on a disposable Linux Matter node.
Uses public DNS records only. --live tests operational reprobe on an existing DUT.
"""
import argparse
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

from test_mdns_linux import decode, dns_name, query


def claim(records, response=False, delta=1):
    srv=next(r for r in records if r[1]==33)
    owner=srv[0]
    rows=[r for r in records if r[0]==owner and r[1] in (16,33)]
    body=b''
    for o,t,c,ttl,data in rows:
        if t==33:
            data=data[:4]+struct.pack('!H',struct.unpack_from('!H',data,4)[0]+delta)+data[6:]
        body+=dns_name(o)+struct.pack('!HHIH',t,c|(0x8000 if response else 0),ttl,len(data))+data
    question=b'' if response else dns_name(owner)+struct.pack('!HH',255,1)
    return struct.pack('!6H',0,0x8400 if response else 0,0 if response else 1,
                       len(rows) if response else 0,0 if response else len(rows),0)+question+body


class Wire:
    def __init__(self, interface, port, out):
        self.port=port; self.out=out; self.packets=[]; self.checks=[]
        self.sock=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        self.sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,interface)
        self.sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
        self.sock.bind(('::',5353))
        self.sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_JOIN_GROUP,
                             socket.inet_pton(socket.AF_INET6,'ff02::fb')+struct.pack('@I',interface))
        self.group=('ff02::fb',5353,0,interface)

    def check(self, name, ok):
        self.checks.append({'name':name,'status':'PASS' if ok else 'FAIL'})
        (self.out/'result.json').write_text(json.dumps(self.checks,indent=2)+'\n')
        print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok: raise AssertionError(name)

    def send(self, data):
        self.sock.sendto(data,self.group)

    def receive(self, duration, stop=None):
        result=[]; until=time.monotonic()+duration
        while time.monotonic()<until:
            if not select.select([self.sock],[],[],max(0,until-time.monotonic()))[0]: break
            data,source=self.sock.recvfrom(4096)
            try: flags,records=decode(data)
            except (ValueError,IndexError,struct.error,UnicodeError): continue
            # Injected proposals have a different port; never count their loopback.
            if not any(r[1]==33 and len(r[4])>=6 and struct.unpack_from('!H',r[4],4)[0]==self.port for r in records): continue
            row=(time.monotonic(),bool(flags&0x8000),records); result.append(row)
            self.packets.append({'time':row[0],'source':source[0],'hex':data.hex()})
            if stop and stop(row): break
        return result

    def reprobe(self, records):
        self.receive(.3)
        start=time.monotonic(); self.send(claim(records,True))
        rows=self.receive(3,lambda r:r[1])
        probes=[r for r in rows if not r[1]]
        self.check('response conflict triggers three probes and republish',
                   len(probes)==3 and bool(rows[-1][1]) and probes[0][0]-start<.6 and
                   rows[-1][0]-probes[-1][0]>=.24)
        return rows[-1][2]

    def close(self):
        self.sock.close()
        (self.out/'packets.json').write_text(json.dumps(self.packets,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface',required=True,type=int)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--port',default=5544,type=int)
    p.add_argument('--node',type=Path); p.add_argument('--credentials',type=Path)
    p.add_argument('--live',action='store_true')
    a=p.parse_args()
    if not a.live and (not a.node or not a.credentials): p.error('node and credentials required')
    out=a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
    wire=Wire(a.interface,a.port,out)
    try:
        if a.live:
            wire.send(query('_matter._tcp.local.'))
            rows=wire.receive(3,lambda r:r[1])
            wire.check('operational instance discovered',bool(rows) and rows[-1][1])
            wire.reprobe(rows[-1][2])
            return 0
        env=dict(os.environ,ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        for scenario,delta in (('lose',1),('win',-1)):
            folder=out/scenario; folder.mkdir()
            wire.receive(.2)
            with (folder/'node.log').open('w') as log, (folder/'node.err').open('w') as err:
                child=subprocess.Popen([str(a.node.resolve()),'--credentials',str(a.credentials.resolve()),
                    '--interface',str(a.interface),'--port',str(a.port),'--state',str(folder/'state.tlv'),
                    '--seconds','60'],stdout=log,stderr=err,env=env)
                expected_exit=0
                try:
                    first=wire.receive(5,lambda r:not r[1])
                    wire.check(scenario+' first probe',bool(first) and not first[-1][1])
                    start=time.monotonic(); wire.send(claim(first[-1][2],delta=delta))
                    rows=wire.receive(4,lambda r:r[1]); probes=[r for r in rows if not r[1]]
                    wire.check(scenario+' publishes',bool(rows) and rows[-1][1] and child.poll() is None)
                    wire.check(scenario+' tie timing and count',len(probes)==(3 if delta>0 else 2) and
                               ((.99<=probes[0][0]-start<1.5) if delta>0 else (probes[0][0]-start<.5)))
                    if scenario=='win':
                        records=rows[-1][2]; wire.receive(2.3)
                        start=time.monotonic(); wire.send(claim(records))
                        defense=wire.receive(.6,lambda r:r[1])
                        wire.check('published probe defended promptly',bool(defense) and defense[0][1] and defense[0][0]-start<.2)
                        wire.send(claim(records)); second=wire.receive(.7,lambda r:r[1])
                        wire.check('defense rate limit 250ms',bool(second) and second[0][1] and .24<=second[0][0]-defense[0][0]<.6)
                        records=wire.reprobe(records)
                        wire.check('node survives recovery',child.poll() is None)
                        wire.receive(1.2); wire.send(claim(records,True))
                        retry=wire.receive(1,lambda r:not r[1])
                        wire.check('persistent conflict reaches probe',bool(retry) and not retry[-1][1])
                        wire.send(claim(records,True))
                        child.wait(timeout=5); expected_exit=1
                        wire.check('persistent owner conflict reported',child.returncode==1 and
                                   'mDNS publication failed' in (folder/'node.err').read_text())
                finally:
                    if child.poll() is None: child.terminate()
                    try: child.wait(timeout=10)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(); raise
            wire.check(scenario+' expected exit',child.returncode==expected_exit)
            errors=(folder/'node.err').read_text()
            wire.check(scenario+' sanitizer clean',not errors if expected_exit==0 else
                       'AddressSanitizer' not in errors and 'runtime error:' not in errors and 'LeakSanitizer' not in errors)
    finally:
        wire.close()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
