"""Two GUI-controlled C workers, signed power, persistence and CHIP oracle.

Disposable profiles only. Run under Memcheck and separately ASan/UBSan/LSan.
Win32 painting itself requires a separate native desktop check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from chip_tool_resources import Client
from chip_tool_energy_profile import frames, integer, ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('exe', 'payload-exe', 'chip-tool', 'credentials', 'paa', 'interface', 'output'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--memcheck', action='store_true')
    a = parser.parse_args()
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'GUI worker protocol, not CSA or Apple UI acceptance', 'checks': [],
              'host_sha256': hashlib.sha256(Path(a.exe).read_bytes()).hexdigest()}
    workers = []; clients = []; logs = []; boot = 0
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')

    def check(name, ok):
        report['checks'].append({'name': name, 'passed': bool(ok)})
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        assert ok, name

    def wait(test, timeout=40):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if test():
                return
            time.sleep(.05)
        raise AssertionError('condition timed out')

    def status(w):
        data = w['log'].read_text(errors='replace')
        lines = [line[11:] for line in data.splitlines() if line.startswith('GUI_STATUS ')]
        return json.loads(lines[-1]) if lines else {}

    def start(index, paired=False):
        nonlocal boot
        boot += 1
        log = out / f'node-{boot}.log'; err = out / f'node-{boot}.err'
        stdout, stderr = log.open('w'), err.open('w'); logs.extend([stdout, stderr])
        cmd = [a.exe, '--interface', a.interface, '--seconds', '0', '--port', str(5546 + index),
               '--credentials', a.credentials, '--state', str(out / f'state-{index}.tlv'), '--pin', '20202021',
               '--discriminator', str(3850 + index), '--power-sensor-only', '--gui-control',
               '--instance-id', f'{index + 1:016x}']
        if a.memcheck:
            cmd = ['valgrind', '--error-exitcode=99', '--leak-check=full', '--show-leak-kinds=all',
                   '--errors-for-leak-kinds=all', '--track-origins=yes', '--log-file=' + str(out / f'memcheck-{boot}.log'), *cmd]
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, env=env)
        w = dict(child=process, log=log, err=err, boot=boot, index=index); workers.append(w)
        wait(lambda: status(w).get('published') or process.poll() is not None)
        check(f'published-{boot}', process.poll() is None and status(w)['commissioning'] == (0 if paired else 1))
        return w

    def send(w, data):
        w['child'].stdin.write(data); w['child'].stdin.flush()

    def stop(w, eof=False):
        if not eof:
            send(w, b'stop\n')
        w['child'].stdin.close()
        check(f'clean-stop-{w["boot"]}', w['child'].wait(timeout=40) == 0)
        check(f'stderr-empty-{w["boot"]}', not w['err'].read_text())
        if a.memcheck:
            data = (out / f'memcheck-{w["boot"]}.log').read_text()
            check(f'memcheck-clean-{w["boot"]}', 'ERROR SUMMARY: 0 errors' in data and 'in use at exit: 0 bytes in 0 blocks' in data)

    def command(c, argv, pattern='SuppressResponse = true'):
        ok, data = c.command(argv, pattern, timeout=50)
        assert ok, (argv[:3], data[-700:])
        return data

    def power(c):
        data = command(c, ['electricalpowermeasurement', 'read', 'active-power', 1, 1])
        return integer(next(f['body'] for f in frames(data) if f['path'] == (1, 0x90, 8)), 'ActivePower')

    def identity(c):
        data = command(c, ['basicinformation', 'read', 'unique-id', 1, 0])
        return re.search(r'UniqueID: (.+)', data)[1]

    try:
        alpha, beta = start(0), start(1)
        for index, w in enumerate((alpha, beta)):
            c = Client(Path(a.chip_tool), Path(a.paa), out, f'controller-{index}', advertise=False); clients.append(c)
            for pin, disc, vid, pid in ((20202021,3850 + index,65521,32769), (1,0,0,0), (99999998,4095,65524,65535)):
                expected = command(c, ['payload','generate-qrcode','--setup-pin-code',pin,'--discriminator',disc,
                    '--rendezvous',4,'--vendor-id',vid,'--product-id',pid], 'QR Code: MT:')
                expected = re.search(r'QR Code: (MT:[A-Z0-9.\-]+)', expected)[1]
                actual = subprocess.check_output([a.payload_exe, str(pin), str(disc), str(vid), str(pid)], text=True, env=env).strip()
                check(f'qr-CHIP-oracle-{index}-{pin}', actual == expected)
                if pin == 20202021:
                    code = actual
            data = command(c, ['pairing','code',1,code,'--use-only-onnetwork-discovery',1,'--timeout',60], 'Device commissioning completed with success')
            check(f'commission-and-attestation-{index}', "Successfully finished commissioning step 'AttestationVerification'" in data)
            wait(lambda: status(w).get('commissioning') == 0 and status(w).get('fabrics') == 1)
            check(f'QR-hidden-after-complete-{index}', status(w)['commissioning'] == 0)
        ca, cb = clients
        unique = identity(ca)
        check('independent-node-identities', unique != identity(cb))
        data = command(ca, ['descriptor','read','server-list',1,1])
        check('exact-power-sensor-clusters', set(ids(next(f['body'] for f in frames(data) if f['path']==(1,0x1d,1)), 'ServerList')) == {0x1d,0x90,0x9c})
        command(ca, ['electricalpowermeasurement','subscribe','active-power',0,1,1,1,'--keepSubscriptions',1], 'Subscription established')
        send(beta,b'power 222000\n'); wait(lambda: status(beta).get('power_mw') == 222000)
        for value in (-10000000, 10000000, 0, -123000):
            offset = len(ca.text()); send(alpha, f'power {value}\n'.encode())
            wait(lambda: any(f['kind']=='Attribute' and f['path']==(1,0x90,8) and integer(f['body'],'ActivePower')==value for f in frames(ca.text()[offset:])))
            check(f'signed-subscription-{value}', power(ca) == value and power(cb) == 222000)
        before = status(alpha)['generation']
        send(alpha,b'power 10000001\npower -10000001\npower 999999999999999999999999999\npower +5\nnope\n' + b'X'*200 + b'\n')
        wait(lambda: 'command-too-long' in alpha['log'].read_text())
        check('invalid-and-oversize-input-preserve-state', status(alpha)['generation'] == before and power(ca) == -123000)
        send(alpha,b'power 45'); time.sleep(.7)
        check('partial-line-not-an-event', status(alpha)['generation'] == before)
        send(alpha,b'6000\n'); wait(lambda: status(alpha).get('power_mw') == 456000)
        check('partial-line-completion', power(ca) == 456000)
        stop(alpha); ca.close(); clients.remove(ca)
        alpha = start(0, paired=True)
        # Restored commissioned nodes have no initial pairing window.
        check('restart-pairing-retained', status(alpha)['commissioning'] == 0 and status(alpha)['fabrics'] == 1)
        ca = Client(Path(a.chip_tool),Path(a.paa),out,'controller-restart',source=out/'controller-0/storage',advertise=False); clients.append(ca)
        check('stable-identity-fresh-CASE', identity(ca) == unique)
        send(alpha,b'power -765000\n'); wait(lambda: status(alpha).get('power_mw') == -765000)
        check('post-restart-power', power(ca) == -765000)
        command(ca,['operationalcredentials','remove-fabric',1,1,0], r'statusCode: 0\b')
        check('last-fabric-response-and-exit', alpha['child'].wait(timeout=40) == 0)
        # stop() also inspects Memcheck and diagnostics for this already exited boot.
        stop(alpha, eof=True)
        check('peer-remains-alive', power(cb) == 222000)
        stop(beta, eof=True)
        report['result']='PASS'
    finally:
        for c in clients:
            c.close()
        for w in workers:
            if w['child'].poll() is None:
                w['child'].stdin.close()
                try:
                    w['child'].wait(timeout=40)
                except subprocess.TimeoutExpired:
                    w['child'].kill(); w['child'].wait()
        for log in logs:
            log.close()
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__':
    main()
