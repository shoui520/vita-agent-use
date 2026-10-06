# SPDX-License-Identifier: GPL-3.0-or-later
"""Incrementally mirror the Vita write journal into a private PC SQLite file."""
import argparse
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from vita_client import VitaClient, ClientError, private_json


def number(value):
    if not isinstance(value, str) or not re.fullmatch('0|[1-9][0-9]{0,18}', value) or int(value) > 2**63-1:
        raise ClientError('Invalid audit integer.')
    return int(value)


def validate_page(page, after):
    if not isinstance(page, dict) or set(page) != {'v', 'after', 'next_sequence', 'more', 'events'}:
        raise ClientError('Invalid audit page.')
    if type(page['v']) is not int or page['v'] != 1 or number(page['after']) != after or type(page['more']) is not bool:
        raise ClientError('Audit page does not match the cursor.')
    events = page['events']
    if not isinstance(events, list) or len(events) > 2 or (page['more'] and not events):
        raise ClientError('Invalid audit page size.')
    cursor = after
    fields = {'sequence', 'subject', 'operation_id', 'path', 'destination', 'sha256', 'expected_sha256',
              'detail', 'phase', 'operation', 'yes', 'recursive', 'overwrite', 'bytes', 'result',
              'effect_started', 'readback_required', 'observed_us', 'offset', 'trash_id', 'detail_path', 'effect_path', 'changes'}
    for event in events:
        if not isinstance(event, dict) or set(event) != fields:
            raise ClientError('Invalid audit event fields.')
        sequence = number(event['sequence'])
        if sequence <= cursor:
            raise ClientError('Audit events are out of order.')
        cursor = sequence
        for key, size in [('subject', 64), ('operation_id', 32)]:
            if not isinstance(event[key], str) or not re.fullmatch('[0-9a-f]{%d}' % size, event[key]):
                raise ClientError('Invalid audit identity.')
        for key in ('sha256', 'expected_sha256'):
            if not isinstance(event[key], str) or not re.fullmatch('(?:[0-9a-f]{64})?', event[key]):
                raise ClientError('Invalid audit digest.')
        for key, limit in [('path', 512), ('destination', 512), ('detail', 32), ('detail_path',512), ('effect_path',512)]:
            if not isinstance(event[key], str) or '\0' in event[key] or len(event[key].encode('utf-8')) >= limit:
                raise ClientError('Invalid audit text.')
        if not isinstance(event['trash_id'], str) or not re.fullmatch('(?:[0-9a-f]{32})?', event['trash_id']):
            raise ClientError('Invalid trash provenance.')
        if not isinstance(event['changes'], list) or len(event['changes']) > 2:
            raise ClientError('Invalid affected path list.')
        for change in event['changes']:
            if not isinstance(change, dict) or set(change) != {'path','before','after'} or not isinstance(change['path'], str) or '\0' in change['path'] or len(change['path'].encode('utf-8')) >= 512:
                raise ClientError('Invalid affected path.')
            for state in (change['before'], change['after']):
                if not isinstance(state, dict) or type(state.get('known')) is not bool:
                    raise ClientError('Invalid path observation.')
                if not state['known']:
                    if set(state) != {'known','exists'} or state['exists'] is not None:raise ClientError('Invalid unknown observation.')
                elif type(state.get('exists')) is not bool:
                    raise ClientError('Invalid existence observation.')
                elif not state['exists']:
                    if set(state) != {'known','exists'}:raise ClientError('Invalid missing observation.')
                else:
                    if set(state) != {'known','exists','kind','bytes'} or state['kind'] not in ('file','directory','other'):raise ClientError('Invalid file observation.')
                    number(state['bytes'])
        for key in ('bytes', 'observed_us', 'offset'):
            number(event[key])
        for key in ('yes', 'recursive', 'overwrite', 'effect_started', 'readback_required'):
            if type(event[key]) is not bool:
                raise ClientError('Invalid audit flag.')
        if type(event['phase']) is not int or not 0 <= event['phase'] <= 3:
            raise ClientError('Invalid audit phase.')
        if type(event['operation']) is not int or not 0 <= event['operation'] <= 8:
            raise ClientError('Invalid audit operation.')
        if type(event['result']) is not int or not -2**31 <= event['result'] <= 0:
            raise ClientError('Invalid audit result.')
    if number(page['next_sequence']) != cursor:
        raise ClientError('Audit cursor skips events.')
    return cursor


class AuditMirror:
    def __init__(self, path, device):
        if not isinstance(device, str) or not re.fullmatch('[0-9a-f]{64}', device):
            raise ClientError('Invalid device certificate identity.')
        path = Path(path).absolute()
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ClientError('Audit mirror must be a private user-owned regular file.')
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path)
        self.device = device
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            with self.db:
                self.db.execute('CREATE TABLE IF NOT EXISTS cursor(device TEXT PRIMARY KEY, sequence INTEGER NOT NULL)')
                self.db.execute('CREATE TABLE IF NOT EXISTS events(device TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(device,sequence))')
                self.db.execute('INSERT OR IGNORE INTO cursor VALUES(?,0)', (device,))
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            self.db.close()
            raise

    def cursor(self):
        return self.db.execute('SELECT sequence FROM cursor WHERE device=?', (self.device,)).fetchone()[0]

    def store(self, page, after):
        next_sequence = validate_page(page, after)
        # One durable transaction: a crash cannot commit the cursor without
        # its events. BEGIN IMMEDIATE serializes separate sync processes.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.cursor() != after:
                raise ClientError('Another sync advanced the cursor; retry from the saved cursor.')
            for event in page['events']:
                self.db.execute('INSERT INTO events VALUES(?,?,?)',
                                (self.device, number(event['sequence']), json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True)))
            self.db.execute('UPDATE cursor SET sequence=? WHERE device=?', (next_sequence, self.device))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return len(page['events'])

    def sync(self, client, max_pages=1000):
        if type(max_pages) is not int or max_pages <= 0:
            raise ClientError('Invalid page limit.')
        count = 0
        for _ in range(max_pages):
            after = self.cursor()
            page = client.audit_page(after)
            count += self.store(page, after)
            if not page['more']:
                return {'events_saved': count, 'next_sequence': str(self.cursor()), 'more': False}
        return {'events_saved': count, 'next_sequence': str(self.cursor()), 'more': True}

    def close(self):
        self.db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-pages', type=int, default=1000)
    args = parser.parse_args()
    client = VitaClient(private_json(args.credentials), args.state)
    mirror = AuditMirror(args.output, client.pin)
    try:
        print(json.dumps(mirror.sync(client, args.max_pages)))
    finally:
        mirror.close()
        client.close()


if __name__ == '__main__':
    main()
