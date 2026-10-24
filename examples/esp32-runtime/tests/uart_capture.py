"""Private UART capture and serialized file-based controls for the soak oracle.

Requires pyserial. Raw logs may contain private device/application information;
always choose an ignored output directory. No credentials are copied by this tool.
"""
import argparse,json,time
from pathlib import Path
import serial

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',required=True)
    p.add_argument('--baud',type=int,default=115200)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--duration',type=int,default=10800)
    p.add_argument('--reset',action='store_true')
    args=p.parse_args()
    if args.duration<60: p.error('duration must be at least 60 seconds')
    if args.baud<=0: p.error('baud must be positive')
    args.output.mkdir(parents=True,exist_ok=True)
    request=args.output/'control-request.json'
    request.unlink(missing_ok=True)
    pending=None; ready=False; timer_sample=None; started=time.monotonic()
    with serial.Serial(args.port,args.baud,timeout=.1) as uart, (args.output/'uart.log').open('wb') as raw, (args.output/'events.jsonl').open('w',encoding='utf-8') as events, (args.output/'control-replies.jsonl').open('a',encoding='utf-8') as replies:
        uart.dtr=False
        if args.reset:
            uart.rts=True; time.sleep(.12); uart.reset_input_buffer()
        uart.rts=False
        while time.monotonic()-started<args.duration:
            if request.exists() and pending is None:
                pending=json.loads(request.read_text(encoding='utf-8')); request.unlink()
                command=pending['command']
                if command not in 'mhdfaw123456789q' or len(command)!=1:
                    raise ValueError('Unsupported local laboratory command')
                uart.write(command.encode('ascii')); uart.flush()
            line=uart.readline()
            if not line: continue
            raw.write(line); raw.flush()
            text=line.decode('utf-8',errors='replace').strip()
            record=None
            for prefix in ('SOAK ','MEMORY ','TASK_MEMORY ','HEAP_SAMPLE ','HEAP_STATE ','HEAP_BLOCK ','HEAP_MAP ','HEAP_OWNER ','RX_DROP ','RX_BLOCK '):
                if text.startswith(prefix):
                    record=dict(kind=prefix.strip(),data=json.loads(text[len(prefix):]))
                    break
            if text.startswith('NETWORK '):
                record=dict(kind='NETWORK',data={k:int(v) for k,v in (x.split('=') for x in text[8:].split())})
            if text.startswith('TRACE26 '):
                try:
                    event,*fields=text[8:].split()
                    record=dict(kind='TRACE26',data=dict(event=event,
                        **{k:int(v) for k,v in (x.split('=') for x in fields)}))
                except ValueError:
                    record=dict(kind='TRACE_PARSE_ERROR')
            if 'RUNTIME_READY' in text:
                ready=True; record=dict(kind='READY'); print(json.dumps(record),flush=True)
            if any(mark in text for mark in ('RUNTIME_FAIL','Guru Meditation','abort() was called','task_wdt:')):
                print(json.dumps(dict(failed=True,ready=ready)),flush=True)
                return 1
            if 'RUNTIME_PASS' in text: record=dict(kind='PASS')
            if record:
                if record['kind']=='HEAP_SAMPLE': timer_sample=record['data']
                record['unix_ms']=int(time.time()*1000)
                events.write(json.dumps(record)+'\n'); events.flush()
                matches=pending and ((record['kind']=='SOAK' and record['data']['command']==pending['command']) or
                    (record['kind']=='PASS' and pending['command']=='q'))
                if matches:
                    if pending['command']=='m' and timer_sample and timer_sample['phase']=='checkpoint':
                        record['data']['timer_sample']=timer_sample
                    # Append acknowledgements: replacing a file concurrently
                    # opened by Node can fail with Windows sharing violation.
                    replies.write(json.dumps(dict(id=pending['id'],record=record))+'\n')
                    replies.flush(); pending=None
                if record['kind']=='PASS':
                    print(json.dumps(dict(pass_=True,elapsed_seconds=time.monotonic()-started)),flush=True)
                    return 0
    print(json.dumps(dict(timeout=True,ready=ready)),flush=True)
    return 2

if __name__=='__main__': raise SystemExit(main())
