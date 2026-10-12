"""Focused certificate/profile regression against a freshly built host directory.

Use matching compiler/sanitizer options for that host build. --oom instruments
all certificate/mbedTLS allocations and checks every failure position.
"""
import argparse
import os
from pathlib import Path
import runpy
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--mbedtls', required=True, type=Path)
    p.add_argument('--compiler', default='gcc')
    p.add_argument('--sanitize', action='store_true')
    p.add_argument('--oom', action='store_true')
    a = p.parse_args()
    repo = Path(__file__).resolve().parents[3]
    base = a.build.resolve()
    mbed = a.mbedtls.resolve()
    modules = runpy.run_path(str(repo/'tools/matter/build_host_linux.py'))
    win = os.name == 'nt'
    flags = ['-std=c99', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
             '-ffunction-sections', '-fdata-sections', '-DMATTER_TRANSPORT_CAPACITY=56',
             '-I'+str(repo/'main/apps/matter'), '-I'+str(repo/'tools/matter/host'),
             '-I'+str(mbed/'include'), '-DMBEDTLS_CONFIG_FILE="matter_mbedtls_config.h"']
    if not win:
        flags += ['-D_GNU_SOURCE']
    if a.sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks='+('0' if win else '1'),
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    if Path(a.compiler).is_file():
        env['PATH'] = str(Path(a.compiler).resolve().parent)+os.pathsep+env['PATH']
    def run(command):
        subprocess.run(list(map(str, command)), check=True, env=env)
    host = [x.replace('matter_udp_linux', 'matter_udp_windows').replace('matter_store_file_posix', 'matter_store_file_windows')
            if win else x for x in modules['HOST']]
    objects = [base/(x.replace('/', '_')+'.o') for x in modules['CORE']+host]
    objects += [base/('mbedtls_'+x+'.o') for x in modules['MBED']]
    libs = ['-lws2_32', '-liphlpapi', '-lbcrypt'] if win else []
    for name in ['operational_cert', 'credentials', 'attestation_cert', 'case', 'fabric', 'server_time']:
        exe = base/('test-'+name+('.exe' if win else ''))
        objs = [x for x in objects if name != 'server_time' or x.name != 'runtime_matter_runtime.o']
        run([a.compiler, *flags, repo/'tools/matter/tests'/('test_'+name+'.c'), *objs, '-Wl,--gc-sections', *libs, '-o', exe])
        run([exe])
    if a.oom:
        out = base/'certificate-oom'
        out.mkdir(exist_ok=True)
        objects = []
        sources = [(x, repo/'main/apps/matter'/(x+'.c')) for x in
                   ['codec/matter_tlv', 'crypto/matter_operational_cert', 'crypto/matter_crypto_mbedtls']]
        sources += [('mbedtls_'+x, mbed/'library'/(x+'.c')) for x in modules['MBED']]
        for name, source in sources:
            obj = out/(name.replace('/', '_')+'.o')
            run([a.compiler, *flags, '-DMATTER_TEST_ALLOC_REPLACE', '-include', repo/'tools/matter/tests/alloc.h',
                 '-c', source, '-o', obj])
            objects.append(obj)
        exe = out/('test-operational-alloc'+('.exe' if win else ''))
        run([a.compiler, *flags, '-DMATTER_TEST_ALLOC', repo/'tools/matter/tests/test_operational_cert.c',
             *objects, '-Wl,--gc-sections', *libs, '-o', exe])
        run([exe])
    print('PASS certificate regression', base)


if __name__ == '__main__':
    main()
