# SPDX-License-Identifier: GPL-3.0-or-later
"""Native deletion plans, complete snapshot/change reads and private audit sync."""
import json
import re
from audit_sync import AuditMirror, number
from vita_client import ClientError


def result(reply):
    if not isinstance(reply, dict) or reply.get('status') != 'ok' or not isinstance(reply.get('result'), dict):
        raise ClientError('Native content request failed: ' + json.dumps(reply))
    return reply['result']

def target(data):
    kind=data.get('kind','application');user=data.get('user')
    if kind=='application' and 'user' not in data:return kind,None
    if kind in ('photo','music','video') and 'user' not in data:
        media_id=data.get('media_id')
        if not isinstance(media_id,str) or not re.fullmatch('[1-9][0-9]*',media_id) or int(media_id)>2**63-1:
            raise ClientError('Invalid native media target identity.')
        return kind,media_id
    if kind!='vita_savedata' or type(user) is not int or not 0<=user<64:
        raise ClientError('Invalid native content target kind/user.')
    return kind,user

def target_keys(data):
    target(data)
    return set(data)&{'kind','user','media_id'}


def validate_media_scope(page):
    """Observed status/counts do not imply native completion or permission."""
    kind, media_id = target(page)
    source = page.get('source_observation')
    albums = page.get('album_observation')
    if not isinstance(source,dict) or type(source.get('known')) is not bool:
        raise ClientError('Invalid media source observation.')
    if source['known'] and type(source.get('exists')) is not bool:
        raise ClientError('Invalid known media source existence.')
    if source['known'] and source.get('exists') is True:
        if set(source) != {'known','exists','category','media_id','status','bytes','path'} or source['media_id'] != media_id or type(source['category']) is not int or source['category'] != {'photo':1,'music':2,'video':3}[kind] or type(source['status']) is not int or not 0<=source['status']<=2**32-1 or not isinstance(source['path'],str) or not source['path'] or '\0' in source['path'] or len(source['path'].encode('utf-8'))>1023:
            raise ClientError('Invalid present media source record.')
        if source['bytes'] is not None:
            number(source['bytes'])
    elif source['known']:
        if source != {'known':True,'exists':False}:
            raise ClientError('Invalid absent media source observation.')
    elif set(source) != {'known','exists','native_error'} or source['exists'] is not None or type(source['native_error']) is not int or not -2**31<=source['native_error']<0:
        raise ClientError('Invalid unknown media source observation.')
    if not isinstance(albums,dict) or type(albums.get('known')) is not bool:
        raise ClientError('Invalid album observation.')
    if albums['known']:
        if set(albums) != {'known','link_count','list_count'}:
            raise ClientError('Invalid album observation counts.')
        number(albums['link_count']);number(albums['list_count'])
    elif albums != {'known':False,'reason':'not_observed'}:
        raise ClientError('Invalid unobserved album metadata.')


def collect(client, op, args):
    """Consume internal transport cursors; callers see every path by default."""
    required = {'operation_id', 'scope_sequence'} if op == 'content.scope' else {'operation_id', 'before_scope', 'after_scope'}
    if not isinstance(args, dict) or set(args) != required:
        raise ClientError('Invalid content snapshot/change arguments.')
    key = 'entries' if op == 'content.scope' else 'changes'
    cursor, entries, seen, header = 0, [], set(), None
    while True:
        reply = client._call_raw(op, {**args, 'cursor': str(cursor)})
        page = result(reply)
        expected = required | ({'phase', 'observed_us', 'path_count'} if key == 'entries' else {'before_phase'})
        expected|=target_keys(page)
        if key == 'entries' and target(page)[0] in ('photo','music','video'):
            validate_media_scope(page)
            expected |= {'source_observation','album_observation'}
        if set(page) != expected | {key, 'next_cursor', 'more'} or any(page[k] != args[k] for k in required):
            raise ClientError('Native content snapshot identity changed.')
        current = {k: page[k] for k in expected}
        if header is not None and current != header:
            raise ClientError('Immutable content snapshot header changed.')
        header = current
        if type(page['more']) is not bool or not isinstance(page[key], list) or len(page[key]) > 1:
            raise ClientError('Invalid native content page.')
        for entry in page[key]:
            if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or not entry['path'] or entry['path'] in seen:
                raise ClientError('Invalid or repeated content path.')
            if not isinstance(entry.get('before'), dict) or not isinstance(entry.get('after'), dict):
                raise ClientError('Missing native before/after observation.')
            seen.add(entry['path']); entries.append(entry)
        next_cursor = number(page['next_cursor'])
        if (page[key] and next_cursor <= cursor) or (not page[key] and (next_cursor != cursor or page['more'])):
            raise ClientError('Native content cursor did not advance correctly.')
        cursor = next_cursor
        if not page['more']:
            break
    if key == 'entries' and (header['phase'] not in ('preview', 'before', 'after') or number(header['path_count']) != len(entries)):
        raise ClientError('Incomplete native content snapshot.')
    if key=='entries' and target(header)[0] in ('photo','music','video'):
        albums=collect_albums(client,args)['result']
        summary=header['album_observation']
        if target(albums)!=target(header) or albums['known']!=summary['known'] or (summary['known'] and any(albums[k]!=summary[k] for k in ('link_count','list_count'))):
            raise ClientError('Album details do not match the saved scope summary.')
        header['albums']={k:albums[k] for k in ('known','links','lists')}
    return {**reply, 'result': {**header, key: entries, 'next_cursor': str(cursor), 'more': False}}


def collect_albums(client, args):
    """Return all saved native album rows; transport limits stay internal."""
    if not isinstance(args,dict) or set(args) != {'operation_id','scope_sequence'}:
        raise ClientError('Album reads require operation_id and scope_sequence.')
    cursors=[0,0];rows=[[],[]];seen=[set(),set()];header=None
    while True:
        reply=client._call_raw('content.albums',{**args,'cursor':str(cursors[0]),'list_cursor':str(cursors[1])})
        page=result(reply)
        expected={'operation_id','scope_sequence','kind','media_id','known','link_count','list_count','links','lists','next_cursor','next_list_cursor','more'}
        if set(page)!=expected or any(page[k]!=args[k] for k in args) or target(page)[0] not in ('photo','music','video') or type(page['known']) is not bool or type(page['more']) is not bool:
            raise ClientError('Invalid album snapshot identity.')
        current={k:page[k] for k in expected-{'links','lists','next_cursor','next_list_cursor','more'}}
        if header is not None and current!=header:
            raise ClientError('Immutable album snapshot changed.')
        header=current
        totals=[number(page['link_count']),number(page['list_count'])]
        advanced=False
        for side,key in enumerate(('links','lists')):
            chunk=page[key]
            if not isinstance(chunk,list) or len(chunk)>8:
                raise ClientError('Invalid album transport chunk.')
            for row in chunk:
                keys={'id','list_id','item_type'} if side==0 else {'id','registered','items','target_items'}
                if not isinstance(row,dict) or set(row)!=keys:
                    raise ClientError('Invalid album row fields.')
                identity=number(row['id'])
                if identity in seen[side] or (side==0 and not identity):
                    raise ClientError('Repeated or invalid album row identity.')
                if side==0:
                    number(row['list_id'])
                    if type(row['item_type']) is not int or not 0<=row['item_type']<=2**32-1:
                        raise ClientError('Invalid album membership type.')
                else:
                    if type(row['registered']) is not bool or number(row['target_items'])>number(row['items']):
                        raise ClientError('Invalid album list observation.')
                seen[side].add(identity);rows[side].append(row)
            following=number(page['next_cursor' if side==0 else 'next_list_cursor'])
            if (chunk and following<=cursors[side]) or (not chunk and following!=cursors[side]):
                raise ClientError('Album cursor did not advance correctly.')
            advanced |= following>cursors[side]
            cursors[side]=following
            if len(rows[side])>totals[side]:
                raise ClientError('Album snapshot exceeds its saved counts.')
        if not page['known'] and (totals!=[0,0] or rows!=[[],[]] or page['more']):
            raise ClientError('Unobserved albums contain invented observations.')
        if not page['more']:break
        if not advanced:raise ClientError('Album cursor stalled.')
        # Once a side is complete, seek beyond all rows on subsequent chunks.
        # This avoids scanning unrelated later scopes repeatedly.
        for side in range(2):
            if len(rows[side])==totals[side]:cursors[side]=2**63-1
    if [len(r) for r in rows]!=totals:
        raise ClientError('Incomplete album snapshot.')
    counts={}
    for row in rows[0]:counts[row['list_id']]=counts.get(row['list_id'],0)+1
    lists={row['id']:row for row in rows[1]}
    if not set(counts)<=set(lists) or any(number(row['target_items'])!=counts.get(identity,0) for identity,row in lists.items()):
        raise ClientError('Inconsistent album membership observations.')
    return {**reply,'result':{**header,'links':rows[0],'lists':rows[1],
        'next_cursor':str(cursors[0]),'next_list_cursor':str(cursors[1]),'more':False}}


def preview(client, args):
    reply = client._call_raw('content.delete.preview', args)
    plan = result(reply)
    media=target(plan)[0] in ('photo','music','video')
    extra={'execution_supported'} if media else set()
    if media and (plan.get('execution_supported') is not False or plan.get('title_id') is not None):
        raise ClientError('Invalid read-only native media preview.')
    if set(plan) != {'operation_id', 'title_id', 'before_scope', 'after_scope', 'path_count', 'observed_us', 'execution_started'}|target_keys(plan)|extra or plan['execution_started'] is not False or plan['after_scope'] != '0':
        raise ClientError('Invalid native deletion preview.')
    if any(plan[k] != args[k] for k in (('operation_id','media_id') if media else ('operation_id', 'title_id'))):
        raise ClientError('Deletion preview identity changed.')
    if target(plan)!=target(args):raise ClientError('Deletion preview target changed.')
    paths = collect(client, 'content.delete.changes', {k: plan[k] for k in ('operation_id', 'before_scope', 'after_scope')})['result']
    if target(paths)!=target(plan) or paths['before_phase'] != 'preview' or number(plan['path_count']) != len(paths['changes']):
        raise ClientError('Incomplete deletion preview.')
    if media:
        scope=collect(client,'content.scope',{'operation_id':plan['operation_id'],'scope_sequence':plan['before_scope']})['result']
        if target(scope)!=target(plan) or scope['phase']!='preview' or scope['path_count']!=plan['path_count'] or scope['observed_us']!=plan['observed_us']:
            raise ClientError('Media preview scope changed.')
        plan={**plan,**{k:scope[k] for k in ('source_observation','album_observation','albums')}}
    return {**reply, 'result': {**plan, 'changes': paths['changes']}}


def validate_record(record):
    keys={'subject','operation_id','title_id','state','effect_started','native_result','persisted','observed_us','scope_sequence','preview_scope','registration'}
    if not isinstance(record,dict) or set(record)!=keys|target_keys(record) or record['persisted'] is not True:
        raise ClientError('Invalid native audit record.')
    if not isinstance(record['subject'],str) or not re.fullmatch('[0-9a-f]{64}',record['subject']) or not isinstance(record['title_id'],str) or not re.fullmatch('[A-Z0-9]{9}',record['title_id']) or record['title_id'].startswith('NPXS'):
        raise ClientError('Invalid native audit identity.')
    if not isinstance(record['operation_id'],str) or not re.fullmatch('[0-9a-f]{32}',record['operation_id']):
        raise ClientError('Invalid native audit operation ID.')
    if record['state'] not in ('approval_pending','running','complete','denied','failed','uncertain') or type(record['effect_started']) is not bool or type(record['native_result']) is not int or not -2**31<=record['native_result']<2**31:
        raise ClientError('Invalid native audit state.')
    number(record['observed_us']);number(record['scope_sequence']);number(record['preview_scope'])
    registration=record['registration']
    if not isinstance(registration,dict) or set(registration)!={'before','after'} or registration['before']!={'registered':True,'application_present':True}:
        raise ClientError('Invalid native registration observation.')
    after=registration['after']
    if after is not None and (not isinstance(after,dict) or set(after)!={'registered','application_present'} or any(type(v) is not bool for v in after.values())):
        raise ClientError('Invalid native after registration.')
    expected_after={'registered':target(record)[0]=='vita_savedata','application_present':target(record)[0]=='vita_savedata'}
    if record['state']=='complete' and (not record['effect_started'] or record['native_result'] or after!=expected_after):
        raise ClientError('Unproven native completion.')


class ContentAuditMirror(AuditMirror):
    """Commit audit events and their complete immutable path scopes together."""
    def __init__(self, path, device):
        super().__init__(path, device)
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS content_cursor(device TEXT PRIMARY KEY, sequence INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS content_events(device TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(device,sequence))')
            self.db.execute('CREATE TABLE IF NOT EXISTS content_scopes(device TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(device,sequence))')
            self.db.execute('INSERT OR IGNORE INTO content_cursor VALUES(?,0)', (device,))

    def cursor(self):
        return self.db.execute('SELECT sequence FROM content_cursor WHERE device=?', (self.device,)).fetchone()[0]

    def sync(self, client, max_pages=None):
        if max_pages is not None and (type(max_pages) is not int or max_pages < 1):
            raise ClientError('Invalid content audit page limit.')
        count, pages = 0, 0
        while max_pages is None or pages < max_pages:
            after = self.cursor()
            page = result(client._call_raw('content.audit', {'cursor': str(after)}))
            if set(page) != {'events', 'next_cursor', 'more'} or type(page['more']) is not bool or not isinstance(page['events'], list) or len(page['events']) > 2:
                raise ClientError('Invalid native content audit page.')
            cursor, scopes = after, {}
            for event in page['events']:
                if not isinstance(event, dict) or set(event) != {'sequence', 'record'}:
                    raise ClientError('Invalid native content audit event.')
                seq = number(event['sequence']); record = event['record']
                if seq <= cursor or not isinstance(record, dict) or record.get('persisted') is not True:
                    raise ClientError('Invalid native content audit ordering or durability.')
                validate_record(record)
                cursor = seq
                operation = record.get('operation_id')
                # Validate IDs before using them in a native snapshot request.
                client._command('content.delete.status', {'operation_id': operation})
                for scope in {number(record['scope_sequence']),number(record['preview_scope'])}:
                    cached = self.db.execute('SELECT payload FROM content_scopes WHERE device=? AND sequence=?', (self.device, scope)).fetchone() if scope else None
                    if scope in scopes and (scopes[scope]['operation_id'] != operation or target(scopes[scope])!=target(record)):
                        raise ClientError('Content scope was rebound to another operation.')
                    if cached and (json.loads(cached[0])['operation_id'] != operation or target(json.loads(cached[0]))!=target(record)):
                        raise ClientError('Cached content scope was rebound to another operation.')
                    if scope and scope not in scopes and not cached:
                        snapshot = collect(client, 'content.scope', {'operation_id': operation, 'scope_sequence': str(scope)})['result']
                        if target(snapshot)!=target(record):raise ClientError('Content audit scope target changed.')
                        scopes[scope] = snapshot
            if number(page['next_cursor']) != cursor or (page['more'] and cursor == after):
                raise ClientError('Native audit cursor skipped or repeated events.')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if self.cursor() != after:
                    raise ClientError('Another content sync advanced the saved cursor.')
                for seq, payload in scopes.items():
                    self.db.execute('INSERT INTO content_scopes VALUES(?,?,?)', (self.device, seq, json.dumps(payload, ensure_ascii=True, sort_keys=True)))
                for event in page['events']:
                    self.db.execute('INSERT INTO content_events VALUES(?,?,?)', (self.device, number(event['sequence']), json.dumps(event, ensure_ascii=True, sort_keys=True)))
                self.db.execute('UPDATE content_cursor SET sequence=? WHERE device=?', (cursor, self.device))
                self.db.commit()
            except BaseException:
                self.db.rollback(); raise
            count += len(page['events']); pages += 1
            if not page['more']:
                return {'events_saved': count, 'next_sequence': str(cursor), 'more': False}
        return {'events_saved': count, 'next_sequence': str(self.cursor()), 'more': True}


def request_delete(client, plan, yes=False, wait=False, timeout_s=180, clock=None, sleep=None):
    """Ask for physical approval; neither yes nor polling supplies that decision."""
    import math
    import time
    if yes is not True:
        raise ClientError('Deletion needs --yes and physical OK on the Vita.')
    if type(wait) is not bool or type(timeout_s) not in (int,float) or not math.isfinite(timeout_s) or not 0<timeout_s<=86400:
        raise ClientError('Invalid native deletion wait interval.')
    plan=result(plan) if isinstance(plan,dict) and 'result' in plan else plan
    if not isinstance(plan,dict) or plan.get('execution_started') is not False or not isinstance(plan.get('changes'),list) or number(plan.get('path_count'))!=len(plan['changes']):
        raise ClientError('Request needs a complete native preview plan.')
    if plan.get('execution_supported') is False:
        raise ClientError('This native media preview does not support execution yet.')
    args={'operation_id':plan.get('operation_id'),'title_id':plan.get('title_id'),'preview_scope':plan.get('before_scope'),'yes':True}
    args.update({k:plan[k] for k in target_keys(plan)})
    client._command('content.delete.request',args)
    reply=client._call_raw('content.delete.request',args)
    now=clock or time.monotonic;pause=sleep or time.sleep;deadline=now()+timeout_s
    while True:
        record=result(reply)
        base={k:v for k,v in record.items() if k not in ('before_scope','after_scope')}
        # Event validation is stricter about persistence. Live replies can be
        # honest about a terminal result whose audit write is still pending.
        persisted=base.get('persisted');base['persisted']=True;validate_record(base)
        if type(persisted) is not bool or target(record)!=target(plan) or record['title_id']!=args['title_id'] or record['operation_id']!=args['operation_id'] or record['preview_scope']!=args['preview_scope']:
            raise ClientError('Native deletion request/result binding changed.')
        terminal=record['state'] in ('complete','denied','failed','uncertain')
        if terminal and persisted:
            before=record.get('before_scope','0');after=record.get('after_scope','0')
            number(before);number(after)
            if before!='0':
                paths=collect(client,'content.delete.changes',{'operation_id':args['operation_id'],'before_scope':before,'after_scope':after})['result']
                if target(paths)!=target(record):raise ClientError('Native deletion outcome target changed.')
                changes=paths['changes']
                reply={**reply,'result':{**record,'changes':changes}}
            return reply
        if not wait or now()>=deadline:
            return reply
        pause(min(1.0,max(0.0,deadline-now())))
        reply=client._call_raw('content.delete.status',{'operation_id':args['operation_id']})


def status(client, args):
    reply=client._call_raw('content.delete.status',args)
    if reply.get('status')!='ok':return reply
    record=result(reply)
    if record.get('state') not in ('complete','denied','failed','uncertain'):
        return reply
    before=record.get('before_scope','0')
    if before=='0':before=record.get('preview_scope','0')
    if before=='0':return reply
    paths=collect(client,'content.delete.changes',{'operation_id':args['operation_id'],'before_scope':before,'after_scope':record.get('after_scope','0')})['result']
    if target(paths)!=target(record):raise ClientError('Native deletion status target changed.')
    return {**reply,'result':{**record,'changes':paths['changes'],'changes_before_phase':paths['before_phase']}}
