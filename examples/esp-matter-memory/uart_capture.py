"""Private ESP-Matter UART capture/checkpoints. Provisioning values stay local.

Choose an ignored output directory. The optional private Wi-Fi header uses the
same two JSON string macros as the C6 runtime lab. Neither value is logged.
File controls accept only memory checkpoints and a collector stop operation.
"""
import argparse
import json
from pathlib import Path
import re
import time

import serial


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', required=True)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--wifi-header', type=Path)
    p.add_argument('--reset', action='store_true')
    p.add_argument('--duration', type=int, default=3600)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    secrets = []
    if a.wifi_header:
        header = a.wifi_header.read_text(encoding='utf-8')
        secrets = [json.loads(re.search(r'^#define ' + name + r' (".*")$', header, re.M)[1])
                   for name in ('MATTER_LAB_WIFI_SSID', 'MATTER_LAB_WIFI_PASSWORD')]
        # Console tokenization: no silently corrupted credential quoting.
        if any(any(c in value for c in '\r\n"\\') for value in secrets):
            p.error('Header values require unsupported console escaping')
    request = a.output / 'control-request.json'
    request.unlink(missing_ok=True)
    pending = None
    partial_line = bytearray()
    ready = provisioned = False
    start = time.monotonic()
    with serial.Serial(a.port, 115200, timeout=.1) as uart, \
            (a.output / 'uart.log').open('w', encoding='utf-8') as raw, \
            (a.output / 'events.jsonl').open('w', encoding='utf-8') as events, \
            (a.output / 'control-replies.jsonl').open('a', encoding='utf-8') as replies:
        uart.dtr = False
        if a.reset:
            uart.rts = True
            time.sleep(.12)
            uart.reset_input_buffer()
        uart.rts = False
        while time.monotonic() - start < a.duration:
            if ready and secrets and not provisioned:
                uart.write(('matter esp wifi connect "' + secrets[0] + '" "' + secrets[1] + '"\n').encode())
                uart.flush()
                provisioned = True
            if request.exists() and pending is None:
                pending = json.loads(request.read_text(encoding='utf-8'))
                request.unlink()
                if pending['command'] == 'stop':
                    replies.write(json.dumps(dict(id=pending['id'], record=dict(kind='STOP'))) + '\n')
                    replies.flush()
                    return 0
                if pending['command'] != 'checkpoint' or not re.fullmatch('[a-z0-9-]{1,48}', pending['label']):
                    raise ValueError('Unsupported reference control')
                uart.write(('memstat ' + pending['label'] + '\n').encode())
                uart.flush()
            data = uart.readline()
            if not data:
                continue
            # Serial timeout can split an echoed credential across reads.
            # Redact only complete lines; never persist an unredacted fragment.
            partial_line.extend(data)
            if not partial_line.endswith(b'\n'):
                continue
            text = partial_line.decode('utf-8', errors='replace')
            partial_line.clear()
            for secret in sorted(secrets, key=len, reverse=True):
                if secret:
                    text = text.replace(secret, '[REDACTED]')
            raw.write(text)
            raw.flush()
            if any(mark in text for mark in ('Guru Meditation', 'abort() was called', 'task_wdt:')):
                print('REFERENCE_FAILED', flush=True)
                return 1
            if 'REFERENCE_READY' in text:
                ready = True
                print('REFERENCE_READY', flush=True)
            for prefix in ('REF_MEMORY ', 'REF_TASK '):
                index = text.find(prefix)
                if index < 0:
                    continue
                record = dict(kind=prefix.strip(), data=json.JSONDecoder().raw_decode(text[index + len(prefix):])[0],
                              unix_ms=int(time.time() * 1000))
                events.write(json.dumps(record) + '\n')
                events.flush()
                if pending and prefix == 'REF_MEMORY ' and record['data']['phase'] == pending['label']:
                    replies.write(json.dumps(dict(id=pending['id'], record=record)) + '\n')
                    replies.flush()
                    pending = None
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
