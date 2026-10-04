# SPDX-License-Identifier: GPL-3.0-or-later
"""Collect device-timed performance windows; write one JSON object per sample."""
import argparse
import json
import time
from pathlib import Path
from vita_client import VitaClient, ClientError, private_json

def collect(client, *, window_ms=None, duration_s=None):
    op, args = ('performance.measure', {'window_ms': window_ms}) if window_ms is not None else ('performance.watch', {'duration_s': duration_s})
    def call(op, args=None):
        reply = client.call(op, args or {})
        if reply.get('status') != 'ok':
            raise ClientError(f'{op} failed: {reply.get("error")}')
        return reply['result']
    start = call(op, args)
    watch_id, after = start['watch_id'], 0
    try:
        while True:
            page = call('performance.read', {'after': after})
            if page['watch_id'] != watch_id:
                raise ClientError('Performance watch was replaced.')
            if page['dropped_samples']:
                yield {'watch_id': watch_id, 'dropped_samples': page['dropped_samples']}
            for sample in page['samples']:
                yield {'watch_id': watch_id, **sample}
            after = page['next_after']
            if page['more']:
                continue
            if not page['active']:
                break
            time.sleep(min((window_ms or 1000)/1000, 1))
    except BaseException:
        # Stop local measurement on an interrupted collection; no reconnect loop.
        try:
            call('performance.cancel')
        except Exception:
            pass
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--window-ms', type=int)
    mode.add_argument('--watch-seconds', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    client = VitaClient(private_json(args.credentials), args.state, timeout=20)
    output = args.output.open('w') if args.output else None
    try:
        for sample in collect(client, window_ms=args.window_ms, duration_s=args.watch_seconds):
            line = json.dumps(sample, ensure_ascii=False)
            print(line, flush=True)
            if output:
                output.write(line+'\n')
                output.flush()
    finally:
        client.close()
        if output:
            output.close()

if __name__ == '__main__':
    main()
