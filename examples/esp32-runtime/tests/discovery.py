from pathlib import Path
import sys,time,threading,ipaddress,json
from zeroconf import Zeroconf,ServiceBrowser,ServiceListener,IPVersion
from importlib.metadata import version
assert version('zeroconf')=='0.147.0'
class Listener(ServiceListener):
    def __init__(self): self.found=set(); self.removed=set(); self.lock=threading.Lock()
    def add_service(self,zc,kind,name):
        with self.lock: self.found.add((kind,name))
    def update_service(self,zc,kind,name): self.add_service(zc,kind,name)
    def remove_service(self,zc,kind,name):
        with self.lock: self.removed.add((kind,name))
if len(sys.argv)!=5: raise SystemExit('Usage: discovery.py <interface-index> <IPv6-without-zone> <service-type> <private-result.json>')
index=int(sys.argv[1]); target=ipaddress.IPv6Address(sys.argv[2]).packed
kind=sys.argv[3] if len(sys.argv)>3 else '_matterc._udp.local.'
types=[kind]
if kind=='_matterc._udp.local.':
    types += ['_L3840._sub._matterc._udp.local.','_S15._sub._matterc._udp.local.','_CM._sub._matterc._udp.local.']
zc=Zeroconf(interfaces=[index],ip_version=IPVersion.V6Only); listener=Listener(); browser=ServiceBrowser(zc,types,listener)
try:
    end=time.monotonic()+18; info=None
    while time.monotonic()<end:
        with listener.lock: found=list(listener.found)
        for service,name in found:
            if service!=kind: continue
            candidate=zc.get_service_info(kind,name,timeout=2000)
            if candidate and target in candidate.addresses_by_version(IPVersion.V6Only): info=candidate; break
        if info: break
        time.sleep(.1)
    assert info,'No independently resolved target service'
    assert info.port==5540
    if kind=='_matterc._udp.local.':
        assert info.properties[b'D']==b'3840' and info.properties[b'CM']==b'1',info.properties
        end=time.monotonic()+8
        while time.monotonic()<end:
            with listener.lock: seen={kind for kind,name in listener.found if name==info.name}
            if set(types)<=seen: break
            time.sleep(.1)
        assert set(types)<=seen,seen
    Path(sys.argv[4]).write_text(json.dumps(dict(pass_=True,
        version=version('zeroconf'),service=kind,port=info.port,properties={k.decode():v.decode() for k,v in info.properties.items()},
        types=types),indent=2))
    print('C6_DISCOVERY_PASS PTR/SRV/TXT/AAAA/subtypes IPv6')
finally:
    browser.cancel(); zc.close()
