# SPDX-License-Identifier: GPL-3.0-or-later
"""Request a persistent scoped WRITE ACL through physical native OK on Vita."""
import argparse
import json
from pathlib import Path
import time
import uuid
from vita_client import VitaClient, ClientError, private_json, durable_json


def sync_audit(client, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    offset = output.stat().st_size if output.exists() else 0
    with output.open('ab') as stream:
        while True:
            reply = client.call('acl.audit', {'offset': offset})
            if reply['status'] != 'ok':
                raise ClientError('ACL audit export failed: ' + json.dumps(reply))
            page = reply['result']
            data = page['data'].encode('utf-8')
            if page['offset'] != offset or page['next_offset'] != offset + len(data):
                raise ClientError('ACL audit export offset mismatch.')
            if not data:
                break
            stream.write(data)
            stream.flush()
            offset += len(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device-dir', type=Path, required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--request-id', default=None, help='Resume an earlier request instead of opening another prompt.')
    args = parser.parse_args()
    root = args.device_dir.resolve()
    request_id = args.request_id or uuid.uuid4().hex
    client = VitaClient(private_json(root / 'pc/credentials.json'), root / 'pc/state.json')
    try:
        reply = client.call('acl.status', {'request_id': request_id}) if args.request_id else client.call('acl.request', {'request_id': request_id, 'path': args.path})
        print(json.dumps(reply), flush=True)
        if reply.get('status') != 'ok':
            raise ClientError('ACL request rejected before approval.')
        print('Use the Vita touchscreen to select OK or Cancel. No agent input is sent.', flush=True)
        deadline = time.monotonic() + 90
        while reply['result']['state'] == 'pending':
            if time.monotonic() >= deadline:
                raise ClientError('Decision is still pending; resume with --request-id ' + request_id)
            time.sleep(1)
            reply = client.call('acl.status', {'request_id': request_id})
            if reply.get('status') != 'ok':
                raise ClientError('ACL status unavailable; resume with --request-id ' + request_id)
        durable_json(root / ('acl-' + request_id + '.json'), {'path': args.path, 'reply': reply})
        sync_audit(client, root / 'acl-audit.jsonl')
        print(json.dumps(reply), flush=True)
    finally:
        client.close()


if __name__ == '__main__':
    main()
