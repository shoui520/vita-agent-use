# SPDX-License-Identifier: GPL-3.0-or-later
"""Native directory listings, mkdir, same-partition move, trash and provenance-bound purge through vita-agent-use."""
import argparse
import json
from pathlib import Path
import uuid
from vita_client import VitaClient, private_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list', help='Show the complete directory by default.')
    listing.add_argument('path')
    listing.add_argument('--sort-by', choices=('name', 'modified', 'date', 'size'), default='name')
    listing.add_argument('--order', choices=('asc', 'desc', 'dsc'), default='asc')
    listing.add_argument('--json', action='store_true', help='Return the full structured tool response.')
    listing.add_argument('--limit', type=int, help='Maximum entries per displayed page; omitted means all entries.')
    listing.add_argument('--page', type=int, help='Page number starting at 1; requires --limit.')
    for name in ('mkdir', 'move', 'trash', 'purge'):
        command = commands.add_parser(name)
        command.add_argument('path')
        if name == 'move':command.add_argument('destination')
        if name == 'purge':command.add_argument('--trash-id', required=True, help='Completed trash operation ID; path must be its original path.')
        command.add_argument('--yes', action='store_true', help='Explicit intent for an already ACL-granted risky path.')
        command.add_argument('--operation-id', help='Reuse the original operation identity after response loss/reconnect.')
    commands.add_parser('recover', help='Recover the exact pending PC command; never generates a new operation identity.')
    args = parser.parse_args()
    if args.command == 'list':
        if args.page is not None and args.limit is None:parser.error('--page requires --limit')
        if args.limit is not None and args.limit < 1:parser.error('--limit must be positive')
        if args.page is not None and args.page < 1:parser.error('--page must be at least 1')
    client = VitaClient(private_json(args.credentials), args.state)
    try:
        if args.command == 'list':
            request = {'path': args.path, 'sort_by': args.sort_by, 'order': args.order}
            if args.limit is not None:request['limit'] = args.limit
            if args.page is not None:request['page'] = args.page
            result = client.call('fs.list', request)
        elif args.command == 'recover':
            result = client.recover()
        else:
            request = {'operation_id': args.operation_id or uuid.uuid4().hex, 'path': args.path, 'yes': args.yes}
            if args.command == 'move':request['destination'] = args.destination
            if args.command == 'purge':request['trash_id'] = args.trash_id
            # VitaClient persists this exact request before the network call.
            result = client.call('fs.' + args.command, request)
        if args.command == 'list' and not args.json and result.get('status') == 'ok':
            info = result['result']
            print(info['path'])
            print('Filename                                  Date modified                 Size')
            for entry in info['entries']:
                size = 'folder' if entry['kind'] == 'directory' else str(int(entry['bytes'])) + ' B'
                print(f"{entry['name']:<42}{entry.get('modified') or 'unknown':<30}{size}")
            print(str(info['entry_count']) + ' entries')
            if 'pagination' in info:
                page = info['pagination']
                print(f"Page {page['page']}, limit {page['limit']}, more: {page['has_more']}")
        else:
            print(json.dumps(result, ensure_ascii=False))
        if result['status'] == 'error':raise SystemExit(1)
    finally:
        client.close()


if __name__ == '__main__':
    main()
