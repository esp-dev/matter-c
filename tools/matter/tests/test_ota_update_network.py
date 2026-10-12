"""M14f: independent OpenSSL-backed signatures and Matter.js CASE/OTA peer.

Requires Python cryptography. --valgrind instruments the normal C binary only,
including commissioning, download, rejection/install, restart and shutdown.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

p = argparse.ArgumentParser(description=__doc__)
for name in ('exe', 'node', 'modules', 'credentials', 'ipv6', 'output'):
    p.add_argument('--'+name, required=True)
p.add_argument('--interface', type=int, required=True)
p.add_argument('--mode', choices=['ok','wrong-key','signature','body','identity','version','tamper','interrupt','notify-error','notify-timeout','rollback','crash','retry'], default='ok')
p.add_argument('--valgrind', action='store_true')
p.add_argument('--certificate-validity', choices=['strict','chip'], default='strict')
a = p.parse_args()
if a.valgrind and a.mode=='crash': p.error('SIGKILL has no cleanup; use rollback/retry for Memcheck')
run = Path(a.output).resolve(); run.mkdir(parents=True, exist_ok=False)
body = bytes((i*17+3) % 256 for i in range(16387))
key = ec.generate_private_key(ec.SECP256R1())
manifest = b'WWOTA001'+struct.pack('<HHIQ',0xfff2 if a.mode=='identity' else 0xfff1,0x8001,3 if a.mode=='version' else 2,len(body))+hashlib.sha256(body).digest()
r,s = utils.decode_dss_signature(key.sign(manifest, ec.ECDSA(hashes.SHA256())))
signature = r.to_bytes(32,'big')+s.to_bytes(32,'big')
if a.mode=='signature': signature=bytes([signature[0]^1])+signature[1:]
if a.mode=='body': body=body[:-1]+bytes([body[-1]^1])
if a.mode=='wrong-key': key=ec.generate_private_key(ec.SECP256R1())
(run/'public.sec1').write_bytes(key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint))
del key  # Private test key stays in this process; never saved or logged.
payload=manifest+signature+body
header=(b'\x15\x25\x00\xf1\xff\x25\x01\x01\x80\x24\x02\x02\x2c\x03\x02v2'
        +b'\x26\x04'+struct.pack('<I',len(payload))+b'\x24\x08\x01\x30\x09\x20'+hashlib.sha256(payload).digest()+b'\x18')
image=struct.pack('<IQI',0x1beef11e,16+len(header)+len(payload),len(header))+header+payload
(run/'source.ota').write_bytes(image)
env=dict(os.environ,ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
node=provider=None; logs=[]; phase=0; listen_port=None

def text(): return (run/f'node-{phase}.log').read_text()
def wait(test, timeout=120, allow_exit=False):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if test(): return
        if provider and provider.poll() is not None: raise AssertionError('provider stopped')
        if node and node.poll() is not None and not allow_exit: raise AssertionError('node stopped')
        time.sleep(.05)
    raise AssertionError('OTA simulation timeout')

def start(boot=None):
    global node,phase
    phase+=1
    out=(run/f'node-{phase}.log').open('w'); err=(run/f'node-{phase}.err').open('w'); logs.extend([out,err])
    cmd=[a.exe,'--credentials',a.credentials,'--state',str(run/'state.tlv'),'--interface',str(a.interface),
         '--seconds','240','--ota-file',str(run/'download.ota'),'--ota-sim-key',str(run/'public.sec1'),
         '--certificate-validity',a.certificate_validity]
    # Keep a device-like stable port across reboots. Address-cache churn in
    # the independent controller is tested separately from OTA rollback.
    if listen_port: cmd += ['--port',listen_port]
    if boot: cmd += ['--ota-sim-boot',boot]
    if a.valgrind:
        cmd=['valgrind','--leak-check=full','--show-leak-kinds=all','--errors-for-leak-kinds=definite,indirect,possible',
             '--track-origins=yes','--error-exitcode=99','--log-file='+str(run/f'valgrind-{phase}.log'),*cmd]
    node=subprocess.Popen(cmd,stdout=out,stderr=err,env=env)
    wait(lambda:('OTA_SIM_TRIAL_WAIT' if boot else 'NODE instance=') in text(),allow_exit=bool(boot))

def stop():
    wait(lambda:'PUBLISHED' in text())
    node.terminate(); assert node.wait(timeout=30)==0

try:
    start()
    banner=next(x for x in text().splitlines() if x.startswith('NODE '))
    port=next(x[5:] for x in banner.split() if x.startswith('port=')); listen_port=port
    out=(run/'provider.log').open('w'); logs.append(out)
    provider=subprocess.Popen([a.node,'tools/matter/tests/host_ota_provider.mjs',a.modules,a.ipv6+'%'+str(a.interface),
                               port,str(run),'bdx-sim-'+a.mode],stdout=out,stderr=subprocess.STDOUT,env=env)
    success=a.mode in ('ok','notify-error','notify-timeout')
    rollback=a.mode in ('rollback','crash','retry')
    early_reject=a.mode in ('wrong-key','signature','body','identity','version')
    wait(lambda:('OTA_DOWNLOAD_FAILED' if early_reject else 'OTA_DOWNLOAD_SAVED') in text())
    if a.mode in ('tamper','interrupt'):
        wait(lambda:(run/'apply-1.json').exists())
        if a.mode=='tamper':
            changed=bytearray(image); changed[-1]^=1; (run/'download.ota').write_bytes(changed)
            wait(lambda:'OTA_APPLY_DONE result=5' in text())
            assert 'integrity=0 authenticated=0 installed=0' in text()
    if success or rollback:
        wait(lambda:'OTA_SIM_REBOOT' in text(),allow_exit=True)
        assert node.wait(timeout=30)==0 and 'authenticated=1 installed=1' in text()
    else:
        if early_reject: assert 'OTA_AUTH accepted=0' in text() and 'OTA_APPLY_' not in text()
        if a.mode=='interrupt': assert 'OTA_APPLY_GATE' not in text()
        stop()
    assert not (run/'download.ota.part').exists()
    if rollback:
        start('hold' if a.mode=='crash' else 'fail')
        assert 'OTA_NOTIFY_ATTEMPT' not in text() and 'OTA_SIM_CONFIRMED' not in text()
        if a.mode=='crash':
            node.kill(); assert node.wait(timeout=30)!=0
        else: assert node.wait(timeout=30)==0
    start()
    if success: wait(lambda:'OTA_NOTIFY_DONE' in text())
    wait(lambda:'PUBLISHED' in text())
    (run/'verify-restart').write_text('ready')
    wait(lambda:(run/'restart-verified').exists())
    assert f'OTA_SIM_VERSION version={2 if success else 1} boot={5 if success else 1}' in text()
    if success: assert f'OTA_NOTIFY_DONE success={0 if a.mode.startswith("notify-") else 1}' in text()
    if a.mode=='retry':
        stop(); (run/'retry-ready').write_text('ready'); start()
        wait(lambda:'OTA_SIM_REBOOT' in text(),allow_exit=True)
        assert node.wait(timeout=30)==0
        start(); wait(lambda:'OTA_NOTIFY_DONE success=1' in text())
        wait(lambda:'PUBLISHED' in text())
        (run/'retry-verify').write_text('ready')
        wait(lambda:(run/'retry-verified').exists())
        success=True
    stop(); start()
    wait(lambda:'PUBLISHED' in text()); time.sleep(2)
    assert f'OTA_SIM_VERSION version={2 if success else 1} boot=1' in text() and 'OTA_NOTIFY_ATTEMPT' not in text()
    (run/'download-result').write_text('verified')
    wait(lambda:(run/'provider-pass').exists()); stop()
    (run/'node-stopped').write_text('done'); assert provider.wait(timeout=20)==0
    for i in range(1,phase+1):
        assert not (run/f'node-{i}.err').read_text()
        if a.valgrind:
            report=(run/f'valgrind-{i}.log').read_text()
            assert 'ERROR SUMMARY: 0 errors' in report and 'All heap blocks were freed -- no leaks are possible' in report
    result={'result':'PASS','mode':a.mode,'valgrind':a.valgrind,'restarts':phase-1,'image_bytes':len(image)}
    (run/'result.json').write_text(json.dumps(result,indent=2)+'\n'); print(result)
finally:
    for proc in (node,provider):
        if proc and proc.poll() is None: proc.kill(); proc.wait()
    for log in logs: log.close()
