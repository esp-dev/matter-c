"""Install, relocate, and consume the package without build/source include paths."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--cmake', required=True)
p.add_argument('--ctest', required=True)
p.add_argument('--compiler', required=True)
p.add_argument('--generator', required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='matter-package-', dir=a.build.resolve()) as temp:
    work = Path(temp)
    def run(*args):
        subprocess.run(list(map(str, args)), check=True, timeout=180)
    run(a.cmake, '--install', a.build, '--prefix', work/'original')
    # Native rename of a known child of our freshly created build directory.
    # Windows scanners can briefly retain a directory handle after cmake exits.
    # Retry only sharing/access denial, for at most two seconds; still fail closed.
    for attempt in range(21):
        try:
            (work/'original').rename(work/'relocated')
            break
        except PermissionError:
            if attempt == 20:
                raise
            time.sleep(0.1)
    shutil.copytree(root/'examples/consumer', work/'consumer')
    # Compile the full callback-only composition outside the source/build tree.
    # Fixture bytes are explicit test inputs, never installed library headers.
    shutil.copyfile(root/'tools/matter/tests/test_runtime.c', work/'consumer/runtime.c')
    shutil.copyfile(root/'tools/matter/tests/test_opcreds_vectors.h', work/'consumer/test_opcreds_vectors.h')
    manifest = json.loads((root/'cmake/sources.json').read_bytes())
    headers = ''.join('#include <'+h+'>\n' for h in manifest['public_headers'])
    (work/'consumer/headers.c').write_text(headers, encoding='utf-8')
    with (work/'consumer/CMakeLists.txt').open('a', encoding='utf-8') as out:
        out.write('\ntarget_sources(consumer PRIVATE headers.c)\n')
        out.write('add_executable(runtime_consumer runtime.c)\n'
                  'target_link_libraries(runtime_consumer PRIVATE MatterC::Runtime)\n'
                  'add_test(NAME runtime_consumer COMMAND runtime_consumer)\n')
    run(a.cmake, '-S', work/'consumer', '-B', work/'consumer-build', '-G', a.generator,
        '-DCMAKE_C_COMPILER='+a.compiler, '-DCMAKE_PREFIX_PATH='+str(work/'relocated'),
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run(a.cmake, '--build', work/'consumer-build', '-j', '2')
    commands = (work/'consumer-build/compile_commands.json').read_text().replace('\\\\', '/')
    assert '/main/apps/matter' not in commands and '/tools/matter/host' not in commands
    installed = {x.relative_to(work/'relocated/include/matter').as_posix()
                 for x in (work/'relocated/include/matter').rglob('*.h')}
    assert installed == set(manifest['public_headers']), 'Private or missing installed headers'
    run(a.ctest, '--test-dir', work/'consumer-build', '--output-on-failure')
    print('PASS relocated installed package, all public headers, lifecycle/crypto and two-full-runtime consumers')
