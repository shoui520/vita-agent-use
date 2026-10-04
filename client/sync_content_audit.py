# SPDX-License-Identifier: GPL-3.0-or-later
"""Mirror native Content Manager audit events and complete path snapshots."""
import argparse
import json
from pathlib import Path
from content_delete import ContentAuditMirror
from vita_client import VitaClient, private_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-pages', type=int)
    args = parser.parse_args()
    client = VitaClient(private_json(args.credentials), args.state)
    mirror = None
    try:
        mirror = ContentAuditMirror(args.output, client.pin)
        print(json.dumps(mirror.sync(client, args.max_pages)))
    finally:
        if mirror is not None:
            mirror.close()
        client.close()


if __name__ == '__main__':
    main()
