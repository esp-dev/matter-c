"""Private 1 Mbaud user-case capture shared by both C6 images (pyserial).

Serialized ignored control-request.json accepts one UART byte m/u/x/q/0..9,
'reset', or 'stop' to release the port. No shell command or credential provisioning.
Keeps capturing real OTA restarts. Use ignored build/local output only.
"""
import argparse
import json
from pathlib import Path
import time
import serial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reset', action='store_true')
    parser.add_argument('--duration', type=int, default=10800)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    request = args.output / 'control-request.json'
    request.unlink(missing_ok=True)
    started = time.monotonic()
    with serial.Serial(args.port, 1000000, timeout=.05) as uart, \
            (args.output / 'uart.log').open('wb') as raw, \
            (args.output / 'events.jsonl').open('w', encoding='utf8') as events:
        uart.dtr = False
        if args.reset:
            uart.rts = True
            time.sleep(.12)
            uart.reset_input_buffer()
        uart.rts = False
        while time.monotonic() - started < args.duration:
            if request.exists():
                control = json.loads(request.read_text(encoding='utf8'))
                request.unlink()
                command = control['command']
                if command == 'stop':
                    return
                if command == 'reset':
                    uart.rts = True
                    time.sleep(.12)
                    uart.rts = False
                    continue
                if len(command) != 1 or command not in 'muxq0123456789':
                    raise ValueError('Unsupported user-case UART control')
                uart.write(command.encode('ascii'))
                uart.flush()
            line = uart.readline()
            if not line:
                continue
            raw.write(line)
            raw.flush()
            text = line.decode('utf8', errors='replace').strip()
            record = {'text': text, 'unix_ms': int(time.time()*1000)}
            if text.startswith('USERCASE_MEMORY '):
                record['memory'] = json.loads(text[len('USERCASE_MEMORY '):])
            if text.startswith('LIFECYCLE_MEMORY '):
                record['lifecycle'] = json.loads(text[len('LIFECYCLE_MEMORY '):])
            events.write(json.dumps(record) + '\n')
            events.flush()
            if any(marker in text for marker in ('REFERENCE_READY', 'RUNTIME_READY',
                                                 'NATIVE_OTA_', 'Guru Meditation', 'RUNTIME_FAIL')):
                print(text, flush=True)


if __name__ == '__main__':
    main()
