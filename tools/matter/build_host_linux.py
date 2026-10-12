#!/usr/bin/env python3
"""Linux host build with pinned official upstream mbedTLS."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

# Shared with CMake and the Windows host builder; variant subsets stay local.
import json
_SOURCES = json.loads((Path(__file__).resolve().parents[2] / 'cmake/sources.json').read_text())
CORE = _SOURCES['core'] + _SOURCES['runtime']
HOST, MBED = (_SOURCES[k] for k in ('host_linux', 'mbedtls'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mbedtls', type=Path, default=Path(__file__).resolve().parents[2] / 'third_party/mbedtls')
    p.add_argument('--compiler', default='gcc')
    p.add_argument('--vendor-name', default='Matter C')
    p.add_argument('--product-name', default='Matter C host simulation')
    p.add_argument('--sanitize', action='store_true')
    p.add_argument('--test', action='store_true')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    identity = []
    for field, value in (('VENDOR_NAME', a.vendor_name), ('PRODUCT_NAME', a.product_name)):
        if not 1 <= len(value.encode('utf-8')) <= 32 or any(c in value for c in ('\0', '\r', '\n', ';')):
            p.error(field + ' must contain 1..32 UTF-8 bytes without NUL, line breaks or semicolons')
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        identity.append('-DMATTER_HOST_' + field + '="' + escaped + '"')
    if a.test and not Path(os.environ.get('MATTER_IPV6_INJECTOR', '')).is_file():
        p.error('--test requires MATTER_IPV6_INJECTOR pointing to the CAP_NET_RAW fixed-case helper')
    repo = Path(__file__).resolve().parents[2]
    mbed = a.mbedtls.resolve()
    revision = subprocess.check_output(['git', '-C', str(mbed), 'rev-parse', 'HEAD'], text=True).strip()
    dependency = json.loads((repo/'cmake/dependencies.json').read_bytes())['mbedtls']
    if revision != dependency['revision']:
        p.error('Unexpected mbedTLS revision')
    subprocess.run(['git', '-C', str(mbed), 'diff', '--exit-code', 'HEAD', '--', 'include', 'library'], check=True)
    out = (a.output or repo / 'build/matter-host' / ('linux-sanitize' if a.sanitize else 'linux-gcc')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    flags = ['-std=c99', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror', '-g', '-O1',
             '-ffunction-sections', '-fdata-sections', '-DMATTER_TRANSPORT_CAPACITY=56', '-DMATTER_EVENTS_CAPACITY=128',
             '-I'+str(repo/'main/apps/matter'), '-I'+str(repo/'tools/matter/host'),
             '-I'+str(mbed/'include'), '-DMBEDTLS_CONFIG_FILE="matter_mbedtls_config.h"']
    if a.sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    def run(args):
        subprocess.run([str(x) for x in args], check=True)
    objects = []
    for folder, names, prefix in [(repo/'main/apps/matter', CORE, ''),
                                  (repo/'tools/matter/host', HOST, ''), (mbed/'library', MBED, 'mbedtls_')]:
        for name in names:
            obj = out/(prefix+name.replace('/', '_')+'.o')
            source_flags = [f for f in flags if f != '-D_GNU_SOURCE'] if prefix == 'mbedtls_' else flags
            run([a.compiler, *source_flags, '-c', folder/(name+'.c'), '-o', obj])
            objects.append(obj)
    run([a.compiler, *flags, *identity, repo/'tools/matter/host/matter_node.c', *objects,
         '-Wl,--gc-sections', '-o', out/'matter-node'])
    print('Host executable:', out/'matter-node', flush=True)
    if a.test:
        env = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        def test(name, sources, objs, args=()):
            exe = out/name
            run([a.compiler, *flags, *sources, *objs, '-Wl,--gc-sections', '-o', exe])
            subprocess.run([str(exe), *args], check=True, env=env)
        test('test-ota-update', [repo/'tools/matter/tests/test_ota_update.c'], objects, [str(out/'ota-update.tlv')])
        with tempfile.TemporaryDirectory(prefix='matter-ota-crash-') as directory:
            subprocess.run([sys.executable, str(repo/'tools/matter/tests/test_ota_rollback_store.py'),
                            '--exe', str(out/'test-ota-update'), '--output', str(Path(directory)/'cases')], check=True)
        test('test-root', [repo/'tools/matter/tests/test_root.c'], objects)
        test('test-switch-sim', [repo/'tools/matter/tests/test_switch_sim.c'], objects)
        test('test-server-time', [repo/'tools/matter/tests/test_server_time.c'],
             [x for x in objects if x.name != 'runtime_matter_runtime.o'])
        update_alloc = [x for x in objects if x.name not in ('clusters_matter_ota_update.o','matter_ota_file.o')]
        for source, name in ((repo/'main/apps/matter/clusters/matter_ota_update.c','update'), (repo/'tools/matter/host/matter_ota_file.c','update-file')):
            obj=out/(name+'-alloc.o')
            run([a.compiler,*flags,'-Dcalloc=matter_test_calloc','-Dmalloc=matter_test_malloc','-Dfree=matter_test_free','-c',source,'-o',obj])
            update_alloc.append(obj)
        test('test-ota-update-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_ota_update.c'], update_alloc, [str(out/'ota-update.tlv')])
        test('test-ota-apply', [repo/'tools/matter/tests/test_ota_apply.c'], objects)
        apply_alloc = [x for x in objects if x.name!='clusters_matter_ota_apply.o']
        obj=out/'alloc_clusters_matter_ota_apply.o'
        run([a.compiler,*flags,'-DMATTER_TEST_ALLOC_REPLACE','-include',repo/'tools/matter/tests/alloc.h',
             '-c',repo/'main/apps/matter/clusters/matter_ota_apply.c','-o',obj])
        test('test-ota-apply-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_ota_apply.c'], [*apply_alloc,obj])
        test('test-ota-query', [repo/'tools/matter/tests/test_ota_query.c'], objects)
        test('test-bdx', [repo/'tools/matter/tests/test_bdx.c'], objects, [str(out/'bdx-test.ota')])
        bdx_alloc = [x for x in objects if x.name not in ('transport_matter_bdx.o','matter_ota_file.o')]
        for source, name in ((repo/'main/apps/matter/transport/matter_bdx.c', 'bdx'), (repo/'tools/matter/host/matter_ota_file.c', 'ota-file')):
            obj = out/(name+'-alloc.o')
            run([a.compiler, *flags, '-Dcalloc=matter_test_calloc', '-Dmalloc=matter_test_malloc', '-Dfree=matter_test_free', '-c', source, '-o', obj])
            bdx_alloc.append(obj)
        test('test-bdx-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_bdx.c'], bdx_alloc, [str(out/'bdx-test.ota')])
        query_alloc = [x for x in objects if x.name not in ('clusters_matter_ota_query.o','model_matter_im_client.o')]
        for name in ('clusters/matter_ota_query','model/matter_im_client'):
            obj=out/('alloc_'+name.replace('/','_')+'.o')
            run([a.compiler,*flags,'-DMATTER_TEST_ALLOC_REPLACE','-include',repo/'tools/matter/tests/alloc.h',
                 '-c',repo/'main/apps/matter'/(name+'.c'),'-o',obj])
            query_alloc.append(obj)
        test('test-ota-query-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_ota_query.c'], query_alloc)
        test('test-im-write', [repo/'tools/matter/tests/test_im_write.c'], objects)
        test('test-ota', [repo/'tools/matter/tests/test_ota_requestor.c'], objects)
        ota_alloc = [x for x in objects if x.name not in ('clusters_matter_ota_requestor.o','model_matter_cluster.o','model_matter_events.o')]
        for name in ('clusters/matter_ota_requestor','model/matter_cluster','model/matter_events'):
            obj=out/('alloc_'+name.replace('/','_')+'.o')
            run([a.compiler,*flags,'-DMATTER_TEST_ALLOC_REPLACE','-include',repo/'tools/matter/tests/alloc.h',
                 '-c',repo/'main/apps/matter'/(name+'.c'),'-o',obj])
            ota_alloc.append(obj)
        test('test-ota-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_ota_requestor.c'], ota_alloc)
        test('test-case-mrp', [repo/'tools/matter/tests/test_case_mrp.c'], objects)
        test('test-dispatch', [repo/'tools/matter/tests/test_dispatch.c'], [x for x in objects if x.name!='runtime_matter_dispatch.o'])
        test('test-discovery', [repo/'tools/matter/tests/test_discovery.c'], [out/(x+'.o') for x in ('matter','matter_mdns','matter_discovery')])
        test('test-udp', [repo/'tools/matter/tests/test_udp_windows.c'], [out/(x+'.o') for x in ('matter','matter_udp','matter_udp_linux')])
        # Fault-injection builds only for the newly added allocation ownership.
        alloc_objects=[]
        for name, folder in [('matter',repo/'main/apps/matter'),('matter_udp',repo/'main/apps/matter'),
                             ('matter_udp_linux',repo/'tools/matter/host')]:
            obj=out/('alloc_'+name+'.o')
            run([a.compiler,*flags,'-DMATTER_TEST_ALLOC_REPLACE','-include',repo/'tools/matter/tests/alloc.h',
                 '-c',folder/(name+'.c'),'-o',obj])
            alloc_objects.append(obj)
        test('test-udp-alloc', ['-DMATTER_TEST_ALLOC',repo/'tools/matter/tests/test_udp_windows.c'],alloc_objects)
        test('test-udp-ipv6', [repo/'tools/matter/tests/test_udp_linux.c'], [out/(x+'.o') for x in ('matter','matter_udp','matter_udp_linux')])
        test('test-file', [repo/'tools/matter/tests/test_store_file_posix.c'], [out/'matter_store_file_posix.o'])
        store = out/'test-store'
        run([a.compiler, *flags, repo/'tools/matter/tests/test_store.c', *objects, '-Wl,--gc-sections', '-o', store])
        with tempfile.TemporaryDirectory(prefix='matter-store-') as directory:
            for mode in ('committed', 'pending'):
                for phase in ('seed', 'load'):
                    subprocess.run([str(store), phase, str(Path(directory)/mode), mode], check=True, env=env)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
