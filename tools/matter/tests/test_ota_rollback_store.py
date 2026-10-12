"""Kill the journal owner before/after atomic replace; recover in a NEW process.

Injected _Exit intentionally skips cleanup. Run clean shutdown/leak checks in
test_ota_update and the complete node separately, not on these killed processes.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--exe',required=True)
p.add_argument('--output',required=True)
a=p.parse_args()
base=Path(a.output);base.mkdir(parents=True,exist_ok=False)
env=dict(os.environ,ASAN_OPTIONS='halt_on_error=1:detect_leaks=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
def run(path,action,boundary='none',expected=0):
    r=subprocess.run([a.exe,str(path),action,boundary],capture_output=True,text=True,env=env)
    assert r.returncode==expected and not r.stderr,(action,boundary,r.returncode,r.stdout,r.stderr)
    return tuple(map(int,re.search(r'RECOVER (\d+) (\d+) (\d+) (\d+)',r.stdout).groups())) if expected==0 else None
cases=[('seed',[],(1,0,0,0),(2,1,0,0)),
       ('boot',['seed'],(2,1,0,0),(1,0,1,0)),
       ('confirm',['seed'],(1,0,1,0),(2,0,0,1)),
       ('rollback',['seed','boot'],(1,0,1,0),(1,0,0,0)),
       ('claim',['seed','confirm'],(2,0,0,1),(2,0,0,0))]
for action,setup,before,after in cases:
    for boundary,code,expected in [('before',86,before),('after',87,after)]:
        path=base/(action+'-'+boundary+'.tlv')
        for step in setup: run(path,step)
        run(path,'boot' if action=='rollback' else action,boundary,code)
        assert run(path,'inspect')==expected,(action,boundary,expected)
        print('PASS process crash',action,boundary,expected,flush=True)
