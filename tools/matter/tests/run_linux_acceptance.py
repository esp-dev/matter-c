"""Start Linux DUT, inject IPv6 negatives, run existing chip-tool acceptance,
then restart and require operational rediscovery/CASE/Read. Disposable state only.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'credentials', 'chip-tool', 'paa', 'injector', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    p.add_argument('--interface', required=True, type=int)
    p.add_argument('--address', required=True, help='DUT link-local address without scope suffix')
    p.add_argument('--port', default=5544, type=int)
    p.add_argument('--discriminator', default=3844, type=int)
    p.add_argument('--ota-requestor', action='store_true')
    p.add_argument('--test-switch', action='store_true')
    p.add_argument('--mdns-reprobe', action='store_true', help='inject an operational DNS conflict before a fresh CASE/Read')
    p.add_argument('--no-controller-advertising', action='store_true', help='Avoid MAC-derived DNS hostname collision with a colocated chip-tool server')
    p.add_argument('--case-resumption', action='store_true', help='Require same-controller resumption, full CASE for fresh processes and after restart')
    p.add_argument('--case-resumption-profile', choices=('spec','chip'), default='spec')
    p.add_argument('--case-packet-faults', choices=('drop','duplicate','data-loss','resume-ack-loss'))
    p.add_argument('--fault-asan-runtime', type=Path, help='libasan.so first in DUT-only LD_PRELOAD')
    p.add_argument('--valgrind', action='store_true', help='Memcheck the normal DUT build; never combine with a sanitized binary')
    a = p.parse_args()
    if a.case_packet_faults and not a.case_resumption: p.error('CASE packet faults require --case-resumption')
    out=a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    scripts=Path(__file__).resolve().parent
    env=dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    report={'case_packet_faults':a.case_packet_faults,'case_resumption_profile':a.case_resumption_profile,'checks':[], 'scope':'M13q CASE packet faults' if a.case_packet_faults else 'Linux smoke; not CSA certification'}
    def check(name, ok):
        report['checks'].append({'name':name, 'status':'PASS' if ok else 'FAIL'})
        (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print(('PASS ' if ok else 'FAIL ')+name, flush=True)
        if not ok: raise RuntimeError(name)
    def run(args, log):
        args=[str(x) for x in args]
        (out/(log+'.command')).write_text(shlex.join(args)+'\n')
        with (out/(log+'.log')).open('w') as f:
            r=subprocess.run(args, stdout=f, stderr=subprocess.STDOUT, env=env, timeout=300)
        check(log,r.returncode==0)
    shim=out/'case-faults.so'
    if a.case_packet_faults:
        repo=scripts.parents[2]
        subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-fPIC','-shared',*(['-fsanitize=address,undefined','-fno-sanitize-recover=all'] if a.fault_asan_runtime else []),'-I',str(repo/'main/apps/matter'),
                        str(scripts/'case_packet_faults_linux.c'),str(repo/'main/apps/matter/codec/matter_message_header.c'),
                        str(repo/'main/apps/matter/codec/matter_protocol_header.c'),'-ldl','-o',str(shim)],check=True)
    for phase in ('first', 'restart'):
        args=[str(a.node.resolve()), '--interface',str(a.interface), '--port',str(a.port),
              '--discriminator',str(a.discriminator), '--credentials',str(a.credentials.resolve()),
              '--state',str(out/'state.tlv'), '--seconds','600' if a.valgrind else '300',
              '--case-resumption-profile',a.case_resumption_profile]
        if a.test_switch: args+=['--test-switch']
        if a.valgrind:
            args=['valgrind','--leak-check=full','--show-leak-kinds=all','--track-origins=yes',
                  '--errors-for-leak-kinds=definite,indirect,possible','--error-exitcode=99',
                  '--log-file='+str(out/(phase+'-valgrind.log')),*args]
        (out/(phase+'-node.command')).write_text(shlex.join(args)+'\n')
        with (out/(phase+'-node.log')).open('w') as log, (out/(phase+'-node.err')).open('w') as err:
            node_env=dict(env)
            if a.case_packet_faults:
                node_env.update(LD_PRELOAD=(str(a.fault_asan_runtime.resolve())+':' if a.fault_asan_runtime else '')+str(shim),
                                MATTER_CASE_FAULTS=a.case_packet_faults, MATTER_CASE_FAULT_PORT=str(a.port),
                                MATTER_CASE_FAULT_LOG=str(out/(phase+'-faults.log')))
            child=subprocess.Popen(args,stdout=log,stderr=err,env=node_env)
            try:
                until=time.monotonic()+30
                while time.monotonic()<until and child.poll() is None:
                    if 'PUBLISHED' in (out/(phase+'-node.log')).read_text(): break
                    time.sleep(.05)
                check(phase+'-published',child.poll() is None and 'PUBLISHED' in (out/(phase+'-node.log')).read_text())
                with (out/(phase+'-injection.log')).open('w') as injection:
                    for which in range(14):
                        subprocess.run([str(a.injector.resolve()),a.address,str(a.interface),str(a.port),str(which)],check=True,stdout=injection,stderr=subprocess.STDOUT,timeout=5)
                        time.sleep(.03)
                check(phase+'-alive-after-ipv6', child.poll() is None)
                command=[sys.executable,scripts/'chip_tool_acceptance.py','--chip-tool',a.chip_tool.resolve(),
                         '--paa',a.paa.resolve(),'--output',out/phase,'--discriminator',a.discriminator]
                if phase=='first':
                    # Fault timing can evict historical boot/ACL events from the
                    # bounded log. Keep this run focused on CASE and fresh Read.
                    if not a.case_packet_faults: command+=['--root-events','--vid-verification','--list-subscriptions','--selector-subscriptions']
                else: command+=['--restart-read',out/'first/storage']
                controller_args=['--no-controller-advertising'] if a.no_controller_advertising else []
                command+=controller_args
                if a.test_switch: command+=['--test-switch']
                if a.ota_requestor: command += ['--ota-requestor']
                if a.case_resumption:
                    command+=['--expect-case','full']
                    if phase=='first': command+=['--case-resumption']
                run(command,phase+'-chip')
                if a.ota_requestor:
                    data=(out/(phase+'-node.log')).read_text()
                    check(phase+'-ota-default-selection', 'OTA_SELECTED fabric=1 node=112233 endpoint=0 source=default' in data)
                    if phase=='first': check('ota-announcement-selection', 'OTA_SELECTED fabric=1 node=222333 endpoint=1 source=announcement reason=2' in data)
                if phase=='first' and a.mdns_reprobe:
                    run([sys.executable,scripts/'test_mdns_conflicts_linux.py','--live',
                         '--interface',a.interface,'--port',a.port,'--output',out/'mdns-reprobe'],'mdns-reprobe')
                    run([sys.executable,scripts/'chip_tool_acceptance.py','--chip-tool',a.chip_tool.resolve(),
                         '--paa',a.paa.resolve(),'--restart-read',out/'first/storage',
                         '--output',out/'reprobe',*controller_args,*(['--expect-case','full'] if a.case_resumption else [])],'reprobe-chip')
            finally:
                if child.poll() is None: child.terminate()
                try: child.wait(timeout=30)
                except subprocess.TimeoutExpired: child.kill(); child.wait(); raise
        check(phase+'-exit',child.returncode==0)
        check(phase+'-stderr-empty',not (out/(phase+'-node.err')).stat().st_size)
        if a.case_packet_faults:
            faults=(out/(phase+'-faults.log')).read_text()
            check(phase+'-faults-clean',re.search(r'summary changes=[0-9]+ retries=[0-9]+ errors=0 pending=0',faults) is not None)
            required=['rx opcode=30','tx opcode=31','rx opcode=32','tx opcode=40','rx opcode=10']
            if phase=='first': required+=['tx opcode=33','rx opcode=40','tx opcode=10']
            if a.case_packet_faults=='data-loss': required=[x for x in required if not x.endswith('=10')]
            if a.case_packet_faults=='resume-ack-loss': required=['tx opcode=10'] if phase=='first' else []
            action='duplicate' if a.case_packet_faults=='duplicate' else 'drop'
            check(phase+'-faults-covered',all(action+' '+x in faults for x in required))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
