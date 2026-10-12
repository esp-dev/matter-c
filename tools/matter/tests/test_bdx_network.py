"""Real independent Matter.js provider, complete OTA image staged on x86."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time

p = argparse.ArgumentParser()
for name in ('exe', 'node', 'modules', 'credentials', 'ipv6', 'output'):
    p.add_argument('--'+name, required=True)
p.add_argument('--interface', type=int, required=True)
p.add_argument('--mode', choices=['bdx', 'bdx-corrupt', 'bdx-fault', 'bdx-apply-proceed', 'bdx-apply-await', 'bdx-apply-discontinue', 'bdx-apply-tamper', 'bdx-apply-restart'], default='bdx')
a = p.parse_args()
apply_mode = a.mode.startswith('bdx-apply-')
run = Path(a.output).resolve(); run.mkdir(parents=True, exist_ok=False)
# Independent fixed TLV header, SHA-256 from Python. Many full blocks + partial EOF.
payload = bytes((i*17+3) % 256 for i in range(16387))
digest = hashlib.sha256(payload).digest()
header = (b'\x15\x25\x00\xf1\xff\x25\x01\x01\x80\x24\x02\x02\x2c\x03\x02v2'
          + b'\x26\x04'+struct.pack('<I',len(payload))+b'\x24\x08\x01\x30\x09\x20'+digest+b'\x18')
image = struct.pack('<IQI',0x1beef11e,16+len(header)+len(payload),len(header))+header+payload
if a.mode == 'bdx-corrupt': image = image[:-1]+bytes([image[-1]^1])
(run/'source.ota').write_bytes(image)
env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
node = provider = None; logs = []
def wait(test, timeout=65):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        if test(): return
        for proc in (node,provider):
            if proc and proc.poll() is not None: raise AssertionError('child stopped prematurely')
        time.sleep(.05)
    raise AssertionError('BDX network timeout')
try:
    out=(run/'node.log').open('w'); err=(run/'node.err').open('w'); logs.extend([out,err])
    node=subprocess.Popen([a.exe,'--credentials',a.credentials,'--state',str(run/'state.tlv'),
        '--interface',str(a.interface),'--seconds','230','--ota-file',str(run/'download.ota')],stdout=out,stderr=err,env=env)
    wait(lambda:'NODE instance=' in (run/'node.log').read_text())
    banner=next(x for x in (run/'node.log').read_text().splitlines() if x.startswith('NODE '))
    port=next(x[5:] for x in banner.split() if x.startswith('port='))
    log=(run/'provider.log').open('w'); logs.append(log)
    provider=subprocess.Popen([a.node,'tools/matter/tests/host_ota_provider.mjs',a.modules,
        a.ipv6+'%'+str(a.interface),port,str(run),a.mode],stdout=log,stderr=subprocess.STDOUT,env=env)
    expected='OTA_DOWNLOAD_FAILED' if a.mode=='bdx-corrupt' else 'OTA_DOWNLOAD_SAVED'
    wait(lambda:expected in (run/'node.log').read_text())
    if a.mode=='bdx-corrupt': assert not (run/'download.ota').exists()
    else: assert (run/'download.ota').read_bytes()==image
    assert not (run/'download.ota.part').exists()
    if apply_mode:
        wait(lambda:(run/'apply-1.json').exists())
        first = json.loads((run/'apply-1.json').read_text())
        if a.mode == 'bdx-apply-tamper':
            altered = bytearray(image); altered[-1] ^= 1
            (run/'download.ota').write_bytes(altered)
        if a.mode == 'bdx-apply-restart':
            node.terminate(); assert node.wait(timeout=15)==0
            assert 'OTA_APPLY_GATE' not in (run/'node.log').read_text()
            out=(run/'restart.log').open('w'); err=(run/'restart.err').open('w'); logs.extend([out,err])
            node=subprocess.Popen([a.exe,'--credentials',a.credentials,'--state',str(run/'state.tlv'),
                '--interface',str(a.interface),'--seconds','80','--ota-file',str(run/'download.ota')],stdout=out,stderr=err,env=env)
            wait(lambda:(run/'query-2').exists())
            wait(lambda:'OTA_STATE state=1 reason=1' in (run/'restart.log').read_text())
            wait(lambda:'PUBLISHED' in (run/'restart.log').read_text())
            assert 'OTA_APPLY_' not in (run/'restart.log').read_text()
            assert (run/'download.ota').read_bytes()==image
        else:
            wait(lambda:'OTA_APPLY_DONE' in (run/'node.log').read_text(), 150)
            text=(run/'node.log').read_text()
            if a.mode == 'bdx-apply-discontinue':
                assert 'OTA_APPLY_DONE result=1' in text and 'OTA_APPLY_GATE' not in text
            else:
                integrity = 0 if a.mode == 'bdx-apply-tamper' else 1
                assert f'OTA_APPLY_GATE provider=1 integrity={integrity} authenticated=0 installed=0 version=2' in text
                assert 'OTA_APPLY_DONE result=5' in text
                assert time.time()*1000-first['time'] >= 1900
            if a.mode == 'bdx-apply-await':
                assert 'OTA_APPLY_STATE state=6' in text
                second=json.loads((run/'apply-2.json').read_text())
                assert second['time']-first['time'] >= 119900
    (run/'download-result').write_text('verified')
    wait(lambda:(run/'provider-pass').exists())
    node.terminate(); assert node.wait(timeout=15)==0
    (run/'node-stopped').write_text('stopped'); assert provider.wait(timeout=15)==0
    assert not (run/'node.err').read_text()
    if a.mode == 'bdx-apply-restart': assert not (run/'restart.err').read_text()
    result={'mode':a.mode,'result':'PASS','size':len(image),'sha256':hashlib.sha256(image).hexdigest()}
    (run/'result.json').write_text(json.dumps(result,indent=2)+'\n'); print(result)
finally:
    for proc in (node,provider):
        if proc and proc.poll() is None: proc.kill(); proc.wait()
    for log in logs: log.close()
