# SPDX-License-Identifier: GPL-3.0-or-later
"""Read a native snapshot and sequentially collect categorized plugin metadata."""
import argparse
import json
from pathlib import Path
from vita_client import VitaClient, ClientError, private_json

def collect(client):
    snapshot = client.call('system.snapshot')
    if snapshot.get('status') != 'ok':
        raise ClientError('Snapshot failed.')
    sections = {}
    offset = 0
    config_path = None
    for _ in range(8192):
        reply = client.call('plugins.list', {'offset': offset})
        if reply.get('status') != 'ok':
            raise ClientError('Plugin inventory failed: ' + str(reply.get('error_code')))
        page = reply['result']
        if config_path is not None and page['config_path'] != config_path:
            raise ClientError('Active taiHEN config changed during inventory.')
        config_path = page['config_path']
        for entry in page['entries']:
            if entry.get('configured_enabled') is False:
                continue
            sections.setdefault(entry['section'], []).append(entry)
        if not page['more']:
            break
        if page['next_offset'] <= offset:
            raise ClientError('Plugin inventory cursor did not advance.')
        offset = page['next_offset']
    else:
        raise ClientError('Plugin inventory exceeded its bounded config limit.')
    result = snapshot['result']
    result['plugins'] = {'config_path': config_path, 'source': 'native_module_lists', 'snapshot': False, 'sections': sections}
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    client = VitaClient(private_json(args.credentials), args.state, timeout=20)
    try:
        result = collect(client)
    finally:
        client.close()
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(encoded + '\n')
    print(encoded)

if __name__ == '__main__':
    main()
