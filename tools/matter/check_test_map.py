"""Check that packaging has not silently dropped sources, headers or tests."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
sources = json.loads((root / 'cmake/sources.json').read_bytes())
mapping = json.loads((root / 'doc/oss/test-map.json').read_bytes())
cases = json.loads((root / 'cmake/test-cases.json').read_bytes())
actual = {p.relative_to(root).as_posix() for folder in mapping['scope_roots']
          for p in (root / folder).rglob('*') if p.is_file()
          and not {'node_modules', '__pycache__'}.intersection(p.parts)}
# Captured fixtures may remain locally; public builds must not depend on them.
local_only = set(mapping.get('local_only_files', []))
actual -= local_only
listed = [row['path'] for row in mapping['files']]
assert local_only.isdisjoint(listed), 'Private fixture listed for export'
assert len(listed) == len(set(listed)), 'Duplicate test-map row'
assert set(listed) == actual, ('Test inventory drift', actual-set(listed), set(listed)-actual)
assert len({x['name'] for x in cases}) == len(cases), 'Duplicate CTest case'
for row in mapping['files']:
    expected = {x['name'] for x in cases if x['source'] == row['path']}
    if row['path'].endswith('/test_ota_rollback_store.py'):
        expected.add('ota_crash_recovery')
    assert set(row['ctest']) == expected, row['path']
    assert row['entrypoint'] and row['kind'], row['path']
    for owner in row['referenced_by']:
        assert (root / owner).is_file(), owner
core = root / 'main/apps/matter'
assert {p.relative_to(core).with_suffix('').as_posix() for p in core.rglob('*.c')} == set(sources['core'] + sources['runtime'])
private = {'crypto/matter_spake2p_points.h', 'session/matter_case_resumption.h'}
headers = {p.relative_to(core).as_posix() for p in core.rglob('*.h')
           if not p.name.endswith('_internal.h') and p.relative_to(core).as_posix() not in private}
assert headers == set(sources['public_headers'])
assert headers.isdisjoint(sources['private_headers'])
assert headers | set(sources['private_headers']) == {p.relative_to(core).as_posix() for p in core.rglob('*.h')}
for header in sources['public_headers']:
    for name in re.findall(r'#include\s*"([^"]+)"', (core/header).read_text()):
        target = ((core/header).parent/name).resolve().relative_to(core.resolve()).as_posix()
        assert target in headers, ('Public header requires non-public header', header, target)
for key in ('core', 'runtime', 'host_linux', 'host_windows', 'mbedtls', 'public_headers'):
    assert len(sources[key]) == len(set(sources[key])), key
dependency = json.loads((root/'cmake/dependencies.json').read_bytes())['mbedtls']
assert {f'library/{name}.c' for name in sources['mbedtls']} == {x['path'] for x in dependency['evidence'] if x['path'].startswith('library/') and x['path'].endswith('.c')}
print(f'PASS inventory: {len(listed)} mapped test/fixture/controller files, {len(cases)} native definitions, '
      f'{len(sources["core"])} core sources, {len(headers)} closed public headers')
