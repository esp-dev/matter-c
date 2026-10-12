"""Compile/run NOCs/PASE and access-control regressions against a freshly built host object set."""
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
    p.add_argument('--tests', nargs='+', default=['im_read', 'fabric', 'acl', 'groupkey', 'im_write', 'im_invoke', 'im_subscribe'])
    a = p.parse_args()
    repo = Path(__file__).resolve().parents[3]
    modules = runpy.run_path(str(repo/'tools/matter/build_host_linux.py'))
    win = os.name == 'nt'
    flags = ['-std=c99', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
             '-ffunction-sections', '-fdata-sections', '-DMATTER_TRANSPORT_CAPACITY=56',
             '-I'+str(repo/'main/apps/matter'), '-I'+str(repo/'tools/matter/host'),
             '-I'+str(a.mbedtls.resolve()/'include'), '-DMBEDTLS_CONFIG_FILE="matter_mbedtls_config.h"']
    if not win: flags += ['-D_GNU_SOURCE']
    if a.sanitize: flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks='+('0' if win else '1'), UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    if Path(a.compiler).is_file(): env['PATH'] = str(Path(a.compiler).resolve().parent)+os.pathsep+env['PATH']
    host = [x.replace('matter_udp_linux', 'matter_udp_windows').replace('matter_store_file_posix', 'matter_store_file_windows') if win else x for x in modules['HOST']]
    objects = [a.build.resolve()/(x.replace('/', '_')+'.o') for x in modules['CORE']+host]
    objects += [a.build.resolve()/('mbedtls_'+x+'.o') for x in modules['MBED']]
    for name in a.tests:
        if name not in ('im_read', 'fabric', 'acl', 'groupkey', 'im_write', 'im_invoke', 'im_subscribe', 'root', 'ota_requestor', 'server_window', 'dispatch', 'diagnostics', 'energy_sim'):
            p.error('Unknown regression: '+name)
        exe = a.build.resolve()/('test-'+name+('.exe' if win else ''))
        command = [a.compiler, *flags, repo/'tools/matter/tests'/('test_'+name+'.c'),
                   *[x for x in objects if not ((name == 'server_window' and x.name == 'runtime_matter_runtime.o') or
                                                (name == 'dispatch' and x.name == 'runtime_matter_dispatch.o'))], '-Wl,--gc-sections',
                   *(['-lws2_32', '-liphlpapi', '-lbcrypt', '-Wl,--stack,8388608'] if win else []), '-o', exe]
        subprocess.run(list(map(str, command)), check=True, env=env)
        subprocess.run([str(exe)], check=True, env=env)
    print('PASS NOCs/PASE regression', a.build)


if __name__ == '__main__': main()
