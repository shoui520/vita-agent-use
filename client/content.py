# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only media export using native catalog identities and native file reads."""
import hashlib
import os
from pathlib import Path
import re
from vita_client import ClientError

ROOTS = {'photo': ('photo0:', 'ux0:picture'),
         'music': ('music0:', 'ux0:music'),
         'video': ('video0:', 'ux0:video')}

def physical_path(category, stored):
    """Alias mapping used by the local content-manager implementation."""
    alias, root = ROOTS[category]
    if not isinstance(stored, str):
        raise ClientError('Media catalog path is not text.')
    prefix = next((p for p in (alias, root + '/') if stored.startswith(p)), None)
    if prefix is None:
        raise ClientError('Media path is outside its registered category root.')
    suffix = stored[len(prefix):]
    if prefix == alias:
        suffix = suffix.removeprefix('/')
    # Catalogs may store the native ux0:/ spelling.
    parts = suffix.split('/')
    if (not suffix or any(p in ('', '.', '..') for p in parts) or
            any(ord(c) < 32 or c in ':\\' for c in suffix)):
        raise ClientError('Media catalog path contains an invalid component.')
    path = root + '/' + suffix
    if len(path.encode('utf-8')) >= 512:
        raise ClientError('Media catalog path exceeds the native path budget.')
    return path

def catalog_entry(client, category, identifier):
    response = client.call('content.list', {'category': category, 'after': str(int(identifier)-1)})
    if response.get('status') != 'ok':
        raise ClientError('Native media catalog could not be read.')
    rows = response.get('result', {}).get('entries')
    if not isinstance(rows, list) or not rows or rows[0].get('id') != identifier:
        raise ClientError('The requested media ID is not registered in this category.')
    return rows[0]

def export_media(client, args):
    if (not isinstance(args, dict) or set(args) != {'category', 'id', 'output'} or
            not isinstance(args.get('category'), str) or args['category'] not in ROOTS or not isinstance(args.get('id'), str) or
            not re.fullmatch('[1-9][0-9]{0,18}', args['id']) or int(args['id']) > 2**63-1 or
            not isinstance(args.get('output'), str) or not args['output']):
        raise ClientError('content.export requires photo/music/video category, positive ID string and host output.')
    category, identifier = args['category'], args['id']
    before = catalog_entry(client, category, identifier)
    stored = before.get('path')
    # Normalize only the native optional slash after ux0:, not arbitrary paths.
    if isinstance(stored, str) and stored.startswith('ux0:/'):
        stored = 'ux0:' + stored[5:]
    path = physical_path(category, stored)
    output = Path(args['output'])
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    offset, revision = 0, None
    try:
        with os.fdopen(fd, 'wb') as stream:
            while True:
                data, metadata = client.file_chunk(path, offset, 16384)
                current = (metadata['file_bytes'], metadata['modified'])
                if (type(current[0]) is not int or current[0] < offset or
                        not isinstance(data, bytes) or len(data) > min(16384, current[0]-offset) or
                        (not data and offset != current[0]) or
                        (revision is not None and current != revision)):
                    raise ClientError('Media file changed or did not advance during export.')
                revision = current
                stream.write(data)
                digest.update(data)
                offset += len(data)
                if offset == current[0]:
                    break
            after = catalog_entry(client, category, identifier)
            if after.get('path') != before.get('path') or after.get('bytes') != before.get('bytes'):
                raise ClientError('Media catalog identity changed during export.')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink()
        raise
    return {'status': 'ok', 'result': {
        'source': 'native_content_database_and_filesystem', 'category': category, 'id': identifier,
        'title': before.get('title'), 'catalog_path': before['path'], 'path': path,
        'file': str(output), 'bytes': str(offset), 'catalog_bytes': before.get('bytes'),
        'modified': revision[1], 'sha256': digest.hexdigest(), 'snapshot': False,
        'representation': 'original_on_disk_file', 'sidecars_included': False}}
