# SPDX-License-Identifier: GPL-3.0-or-later
"""Agent-facing client for Vita command protocol v1 (Linux/macOS host).

Credentials and certificate pin come from trusted on-device pairing. This client
cannot issue grants, approve operations or bypass the Vita policy engine.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
from input_sequence import validate as validate_readable_events


class ClientError(Exception):
    pass


def connection_refused_message():
    return ('Vita refused the connection. It may still hold an active session from this PC after serve stopped. '
            'Start serve to reuse the saved session, or wait for that session to expire. '
            'Also check the Vita is awake, its IP is correct, and the plugin is running. '
            'Keep the saved identity, credentials and recovery state.')


def screen_off_if_idle(client):
    """Leave the display on until applications and outstanding work are idle."""
    busy=getattr(client,'automatic_screen_busy',None)
    if busy is not None and busy():
        return False
    installs=getattr(client,'_screen_installs',set())
    for operation_id in list(installs):
        reply=client.call('app.install.status',{'operation_id':operation_id})
        if reply.get('status')!='ok' or reply.get('result',{}).get('running') is not False:
            return False
    reply=client.call('app.running')
    result=reply.get('result')
    if reply.get('status')!='ok' or not isinstance(result,dict) or not isinstance(result.get('entries'),list):
        raise ClientError('Cannot confirm app termination; automatic screen-off withheld.')
    if result['entries']:
        return False
    reply=client.call('screen.off')
    if reply.get('status')=='error' and reply.get('error',{}).get('code')==-2:
        # The native worker is still busy. This is deferred cleanup, not an
        # installation failure, and must not replace the command's result.
        return False
    if reply.get('status') not in ('accepted','ok'):
        raise ClientError('Screen-off was rejected.')
    return True


class UploadError(ClientError):
    """Upload failure with confirmed progress, never an inferred remote outcome."""
    def __init__(self, message, progress):
        self.progress = dict(progress)
        received = progress.get('received')
        count = 'unknown' if received is None else received
        total = progress.get('bytes') or 'unknown'
        super().__init__(f"Upload failed during {progress.get('phase', 'unknown')}: {message}. "
                         f"Confirmed bytes: {count}/{total}. "
                         'Rerun the identical command with the same --transfer-state file to resume; '
                         'do not change the source or operation ID.')

    def as_result(self):
        return {'status':'client_error','message':str(self),'result':self.progress,
                'resume':{'transfer_state':self.progress.get('transfer_state'),
                          'instruction':'Rerun the identical command with the same transfer state and source.'}}


def validate_agent_name(name):
    if not isinstance(name, str) or not name.strip() or any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or 0xd800 <= ord(c) <= 0xdfff or 0x2028 <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in name) or len(name.encode('utf-8')) > 128:
        raise ClientError('Agent name must be a single-line UTF-8 label of at most 128 bytes.')


def validate_host(host):
    if not isinstance(host, str) or not host or len(host) > 253 or any(ord(c) < 33 or c in '/\\?#@' for c in host):
        raise ClientError('Invalid device host.')


class NativeFrameError(ClientError):
    def __init__(self, status, code, stage=None, display=None, name=None, message=None):
        self.display = display
        self.stage = stage
        self.status = status
        self.native_result = code
        self.name,self.message=name,message
        super().__init__((message+' '+name+'. ' if message and name else '')+'Native frame capture failed (HTTP %d, native result %d / 0x%08X).' %
                         (status, code, code & 0xffffffff) + (' Stage: ' + stage + '.' if stage else ''))

    def as_result(self):
        result={'status':'error','error':'frame_unavailable','code':self.native_result}
        for field in ('stage','display','name','message'):
            value=getattr(self,field)
            if value is not None:result[field]=value
        return result


def valid_display_observation(display):
    if not isinstance(display, dict) or set(display) != {'width', 'height', 'pitch', 'pixel_format', 'process'}:
        return False
    return (all(type(display[k]) is int and 0 <= display[k] <= 2**32-1
                for k in ('width', 'height', 'pitch', 'pixel_format')) and
            type(display['process']) is int and 0 < display['process'] < 2**31)


def strict_json(data):
    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate key')
            obj[key] = value
        return obj
    return json.loads(data, object_pairs_hook=object_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite number')))


def private_json(path, max_bytes=524288):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ClientError('Credential/state files must be owned by this user and private (mode 600).')
        data = stream.read(max_bytes+1)
        if len(data) > max_bytes:
            raise ClientError('Credential/state file exceeds its 512 KiB size limit.')
        return strict_json(data)


@contextmanager
def private_pem(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid() or not 0 < info.st_size <= 16384:
            raise ClientError('TLS identity files must be private, user-owned regular files of at most 16 KiB.')
        # Load from the validated open descriptor, avoiding a path replacement
        # between checking permissions and OpenSSL reading the private key.
        yield '/dev/fd/' + str(fd)


def durable_json(path, value, *, max_bytes=524288):
    encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()
    if len(encoded) > max_bytes:
        raise ClientError('State exceeds its size limit.')
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class VitaClient:
    def __init__(self, credentials, state_path, timeout=10, retry_disconnect=True, manage_screen=True, screen_off_when_done=True, host=None, agent_name=None):
        self._request_guard = threading.RLock()
        self.manage_screen = manage_screen
        if type(screen_off_when_done) is not bool:
            raise ClientError("screen_off_when_done must be a boolean.")
        self.screen_off_when_done = screen_off_when_done
        self._screen_owned = False
        self._screen_cleanup_error = None
        self.retry_disconnect = retry_disconnect
        required = {'host', 'port', 'token', 'certificate_sha256', 'client_certificate', 'client_key'}
        if not required <= set(credentials) or set(credentials) - (required | {'agent_name', 'session_expires_at'}):
            raise ClientError('Invalid credential fields.')
        for field in ('client_certificate', 'client_key'):
            if not isinstance(credentials[field], str) or not Path(credentials[field]).is_absolute():
                raise ClientError('TLS identity file paths must be absolute.')
        self.client_certificate = credentials['client_certificate']
        self.client_key = credentials['client_key']
        self.agent_name = credentials.get('agent_name', 'Agent') if agent_name is None else agent_name
        validate_agent_name(self.agent_name)
        self.host = credentials['host'] if host is None else host
        self.port = credentials['port']
        self.token = credentials['token']
        self.pin = credentials['certificate_sha256']
        validate_host(self.host)
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ClientError('Invalid device port.')
        if any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
               for v in (self.token, self.pin)):
            raise ClientError('Invalid pairing token or certificate fingerprint.')
        if not 0 < timeout <= 60:
            raise ClientError('Timeout must be between zero and 60 seconds.')
        self.session_expires_at = credentials.get('session_expires_at')
        if self.session_expires_at is not None and (type(self.session_expires_at) not in (int,float) or not math.isfinite(self.session_expires_at) or self.session_expires_at <= 0):
            raise ClientError('Invalid session expiry timestamp.')
        self.session_deadline = None if self.session_expires_at is None else time.monotonic()+max(0,self.session_expires_at-time.time())
        self.timeout = timeout
        self._connection = None
        self._upload_chunk_bytes = None
        self.path = Path(state_path)
        self.identity = hashlib.sha256(json.dumps({k: v for k, v in credentials.items() if k not in ('agent_name', 'session_expires_at')}, sort_keys=True).encode()).hexdigest()

    @contextmanager
    def _locked_state(self):
        # Threads in this harness share one connection; other processes still fail fast.
        with self._request_guard:
            # Separate lock inode survives replacement of the durable state file.
            fd = os.open(str(self.path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                    raise ClientError('State lock must be a private regular file.')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ClientError('Another client request is using this session.') from None
                if self.path.exists():
                    state = private_json(self.path)
                    if not isinstance(state, dict) or state.get('identity') != self.identity:
                        raise ClientError('State belongs to different pairing credentials; do not reuse it.')
                    if set(state) != {'identity', 'next_id', 'pending', 'last'} or type(state['next_id']) is not int or not 1 <= state['next_id'] <= 2**64:
                        raise ClientError('Invalid session state.')
                    if state['pending'] is not None and not isinstance(state['pending'], dict):
                        raise ClientError('Invalid pending request state.')
                    if state['last'] is not None and (not isinstance(state['last'], dict) or set(state['last']) != {'request', 'response'}):
                        raise ClientError('Invalid recovery state.')
                else:
                    state = {'identity': self.identity, 'next_id': 1, 'pending': None, 'last': None}
                yield state
            finally:
                os.close(fd)

    @staticmethod
    def _command(op, args):
        if op not in ('events.subscribe', 'run.begin', 'run.update', 'run.end', 'run.status', 'capabilities', 'system.snapshot', 'app.launch', 'app.close', 'app.install', 'app.install.status', 'screen.on', 'screen.off', 'system.reboot',
                      'input.acquire', 'input.heartbeat', 'input.cancel', 'input.release', 'input.status', 'input.submit', 'fs.stat', 'fs.list', 'touch.panels', 'app.list', 'fs.mkdir', 'fs.move', 'fs.trash', 'fs.purge', 'acl.request', 'acl.status', 'acl.audit', 'macro.acquire', 'plugins.list', 'performance.measure', 'performance.watch', 'performance.read', 'performance.cancel', 'app.running', 'events.start', 'events.read', 'events.stop', 'livearea.schema', 'log.start', 'log.read', 'log.stop', 'content.list', 'livearea.layout', 'livearea.blob', 'dialog.events.start', 'dialog.events.read', 'dialog.events.stop', 'macro.enqueue', 'content.delete.status', 'content.delete.changes', 'content.audit', 'content.delete.preview', 'content.scope', 'content.delete.request', 'content.albums'):
            raise ClientError('Unsupported operation.')
        if not isinstance(args, dict):
            raise ClientError('Arguments must be an object.')
        if op in ('run.begin','run.update','run.end'):
            expected={'run_id','title_id' if op=='run.begin' else 'phase'}
            if set(args)!=expected or not isinstance(args['run_id'],str) or not re.fullmatch('[0-9a-f]{32}',args['run_id']):
                raise ClientError('Run commands require a 32-digit run_id.')
            if op=='run.begin':VitaClient._command('app.launch',{'title_id':args['title_id']})
            elif args['phase'] not in ('preparing','armed','launching','running','closing','completed','cancelled','failed','connection_lost'):
                raise ClientError('Invalid run phase.')
            elif op=='run.end' and args['phase'] not in ('completed','cancelled','failed','connection_lost'):
                raise ClientError('run.end needs a terminal phase.')
            elif op=='run.update' and args['phase'] in ('completed','cancelled','failed','connection_lost'):
                raise ClientError('Use run.end for terminal phases.')
            return {'op':op,'args':dict(args)}
        elif op in ('events.read','dialog.events.read'):
            if set(args) != {'after'} or type(args['after']) is not int or not 0 <= args['after'] <= 2**32-1:
                raise ClientError('events.read requires a uint32 after cursor.')
        elif op in ('input.submit','macro.enqueue'):
            if op=='macro.enqueue' and args.get('start_us')!='0':
                raise ClientError('macro.enqueue derives its start on device; start_us must be 0.')
            required = {'duration_us','repeats','max_lateness_us','events'}
            timing = set(args) & {'start_us','start_delay_us'}
            if len(timing)!=1 or not required<=set(args) or set(args)-(required|timing|{'touch'}):
                raise ClientError('Input sequence needs exactly one of start_us or start_delay_us.')
            if 'start_us' in timing:
                start=args['start_us']
                if not isinstance(start,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',start) or int(start)>2**64-1:
                    raise ClientError('start_us must be a device-clock timestamp encoded as a decimal string.')
            else:
                if type(args['start_delay_us']) is not int or not 10000<=args['start_delay_us']<=1000000:
                    raise ClientError('start_delay_us must be 10000..1000000; resolved on-device after receipt.')
                start=str(args['start_delay_us'])
            for key, maximum in (('duration_us', 3600000000), ('repeats', 1000000), ('max_lateness_us', 1000000)):
                if type(args[key]) is not int or not 1 <= args[key] <= maximum:
                    raise ClientError('Invalid input sequence ' + key + '.')
            if int(start) + args['duration_us'] * args['repeats'] > 2**64-1:
                raise ClientError('Input sequence time overflows.')
            events = args['events']
            if not isinstance(events, list) or not events or (not isinstance(events[0], dict) and len(events) > 1024):
                raise ClientError('Input sequences need between 1 and 1024 timed states.')
            if events and isinstance(events[0], dict):
                if 'touch' in args:
                    raise ClientError('Readable events embed front/back contacts; do not supply a separate touch array.')
                try:
                    validated = validate_readable_events(events, args['duration_us'])
                except ValueError as exc:
                    raise ClientError(str(exc)) from None
                return {'op': op, 'args': {**args, 'events': validated}}
            previous = -1
            for event in events:
                if not isinstance(event, list) or len(event) != 6 or any(type(v) is not int for v in event):
                    raise ClientError('Each input event is [at_us, buttons, lx, ly, rx, ry].')
                at, buttons, *axes = event
                if not previous < at < args['duration_us'] or (previous == -1 and at != 0) or buttons < 0 or buttons & ~0xf3f9 or any(not 0 <= v <= 255 for v in axes):
                    raise ClientError('Invalid input event timing or pad state.')
                previous = at
            result = {**args, 'events': [list(event) for event in events]}
            if 'touch' in args:
                states = args['touch']
                if not isinstance(states, list) or len(states) != len(events):
                    raise ClientError('touch must contain one state per event.')
                copied = []
                for state in states:
                    if not isinstance(state, list) or len(state) != 3 or type(state[0]) is not int or not 0 <= state[0] <= 3:
                        raise ClientError('Touch state is [enabled, front_contacts, back_contacts].')
                    ports = []
                    for port, maximum in ((0, 6), (1, 4)):
                        contacts = state[port + 1]
                        if not isinstance(contacts, list) or len(contacts) > maximum or (contacts and not state[0] & (1 << port)):
                            raise ClientError('Invalid touch panel state.')
                        ids = set()
                        for contact in contacts:
                            if not isinstance(contact, list) or len(contact) != 4 or any(type(v) is not int for v in contact):
                                raise ClientError('Touch contact is [id, force, x, y].')
                            identifier, force, x, y = contact
                            if not 0 <= identifier <= 127 or identifier in ids or not 0 <= force <= 255 or not 0 <= x <= 32767 or not 0 <= y <= 32767:
                                raise ClientError('Invalid touch contact.')
                            ids.add(identifier)
                        ports.append([list(contact) for contact in contacts])
                    copied.append([state[0], *ports])
                result['touch'] = copied
            return {'op': op, 'args': result}
        if op == 'log.start':
            if set(args) != {'path','marker'} or not isinstance(args['path'],str) or not args['path'] or len(args['path'].encode('utf-8')) >= 512 or any(ord(c)<32 for c in args['path']):
                raise ClientError('Log watch requires a Vita file path.')
            if not isinstance(args['marker'],str) or not 1 <= len(args['marker'].encode('utf-8')) <= 128 or '\0' in args['marker']:
                raise ClientError('Log marker requires 1..128 UTF-8 bytes.')
        elif op in ('log.read','log.stop'):
            if set(args) != {'watch_id'} or type(args['watch_id']) is not int or not 1 <= args['watch_id'] <= 2**32-1:
                raise ClientError('Log operation requires watch_id.')
        elif op=='livearea.blob':
            if set(args)!={'section','page_id','position','column','offset'} or args['section'] not in ('pages','icons') or args['column'] not in ('reserved01','reserved02','reserved03','reserved04','reserved05'):
                raise ClientError('Blob read requires a pages/icons section and reserved column.')
            page=args['page_id']
            if not isinstance(page,str) or not re.fullmatch('-?(0|[1-9][0-9]{0,18})',page) or page=='-0' or not -(2**63)<=int(page)<=2**63-1:
                raise ClientError('Blob page_id must be a canonical signed native integer string.')
            if any(type(args[k]) is not int or not 0<=args[k]<=2**31-1 for k in ('position','offset')):
                raise ClientError('Blob position and offset must be nonnegative native int32 values.')
        elif op == 'livearea.layout':
            if set(args)!={'section','offset'} or args['section'] not in ('pages','icons') or type(args['offset']) is not int or not 0<=args['offset']<=100000:
                raise ClientError('Native layout requires pages/icons section and offset.')
        elif op in ('content.delete.status','content.delete.changes','content.audit','content.delete.preview','content.scope','content.delete.request','content.albums'):
            required={'content.delete.status': {'operation_id'}, 'content.delete.changes': {'operation_id','before_scope','after_scope','cursor'},
                      'content.audit': {'cursor'}, 'content.delete.preview': {'operation_id','title_id'},
                      'content.scope': {'operation_id','scope_sequence','cursor'}, 'content.albums': {'operation_id','scope_sequence','cursor','list_cursor'}, 'content.delete.request': {'operation_id','title_id','preview_scope','yes'}}[op]
            optional={'kind','user'} if op in ('content.delete.preview','content.delete.request') else set()
            if op=='content.delete.preview' and args.get('kind') in ('photo','music','video'):
                required={'operation_id','kind','media_id'}
                optional=set()
            if not required<=set(args) or set(args)-required-optional:
                raise ClientError('Invalid native content arguments.')
            kind=args.get('kind','application')
            if kind in ('photo','music','video') and op=='content.delete.preview':
                value=args['media_id']
                if not isinstance(value,str) or not re.fullmatch('[1-9][0-9]{0,18}',value) or int(value)>2**63-1:
                    raise ClientError('Media previews require a positive native MRID string.')
            elif kind not in ('application','vita_savedata') or (kind=='application' and 'user' in args) or (kind=='vita_savedata' and (set(args)&optional!=optional or type(args['user']) is not int or not 0<=args['user']<64)):
                raise ClientError('Savedata requires kind vita_savedata and user ID 0..63; applications have no user selector.')
            if 'operation_id' in args and (not isinstance(args['operation_id'],str) or not re.fullmatch('[0-9a-f]{32}',args['operation_id'])):
                raise ClientError('Content operation_id must be 32 lowercase hex digits.')
            for key in ('cursor','list_cursor','before_scope','after_scope','scope_sequence','preview_scope'):
                if key in args and (not isinstance(args[key],str) or not re.fullmatch('0|[1-9][0-9]{0,18}',args[key]) or int(args[key])>2**63-1 or (key in ('before_scope','scope_sequence','preview_scope') and args[key]=='0')):
                    raise ClientError('Content cursors and snapshot IDs must be canonical integer strings.')
            if op=='content.delete.request' and args['yes'] is not True:
                raise ClientError('Native deletion requires explicit yes and physical OK on the Vita.')
            if 'title_id' in args and (not isinstance(args['title_id'],str) or not re.fullmatch('[A-Z0-9]{9}',args['title_id']) or args['title_id'].startswith('NPXS')):
                raise ClientError('Native content preview requires a non-system title ID.')
        elif op == 'content.list':
            after=args.get('after','')
            if set(args)-{'category','after'} or args.get('category') not in ('photo','music','video','theme','psp_application','playstation_application','psp_savedata','playstation_savedata') or not isinstance(after,str) or (after and (not re.fullmatch('0|[1-9][0-9]{0,18}',after) or int(after)>2**63-1)):
                raise ClientError('Content inventory requires a supported category and optional numeric after cursor.')
        elif op == 'livearea.schema':
            if set(args)-{'after'} or not isinstance(args.get('after',''),str) or len(args.get('after',''))>=32 or any(ord(c)<32 or ord(c)>126 for c in args.get('after','')):
                raise ClientError('Invalid schema cursor.')
        elif op in ('events.read','dialog.events.read'):
            pass
        elif op == 'input.acquire':
            if args:
                raise ClientError('Ordinary input acquisition takes no title or process binding.')
        elif op == 'macro.acquire':
            if set(args) != {'title_id'} or not isinstance(args['title_id'], str) or not re.fullmatch('[A-Z0-9]{9}', args['title_id']):
                raise ClientError('Macro acquisition requires its title_id.')
        elif op in ('acl.request', 'acl.status'):
            required = {'request_id', 'path'} if op == 'acl.request' else {'request_id'}
            if set(args) != required or not isinstance(args.get('request_id'), str) or not re.fullmatch('[0-9a-f]{32}', args['request_id']):
                raise ClientError('ACL requests require a stable 32-digit request_id; approval comes from the Vita only.')
            if op == 'acl.request':
                path = args['path']
                if not isinstance(path, str) or not path or len(path.encode('utf-8')) >= 512 or any(ord(c) < 32 or ord(c) == 127 or 0xd800 <= ord(c) <= 0xdfff for c in path):
                    raise ClientError('ACL scope must be an existing Vita path.')
        elif op in ('performance.measure', 'performance.watch', 'performance.read'):
            key, lo, hi = {'performance.measure': ('window_ms', 100, 60000),
                           'performance.watch': ('duration_s', 1, 3600),
                           'performance.read': ('after', 0, 2**32-1)}[op]
            unexpected=set(args)-{key,'interval_ms'} if op=='performance.watch' else set(args)!={key}
            if unexpected:
                raise ClientError('Unexpected performance arguments.')
            if key not in args or type(args[key]) is not int or not lo <= args[key] <= hi:
                raise ClientError(f'{op} requires {key} in {lo}..{hi}.')
            if 'interval_ms' in args and (type(args['interval_ms']) is not int or not 100<=args['interval_ms']<=min(60000,args[key]*1000)):
                raise ClientError('Invalid performance interval_ms.')
        elif op == 'performance.cancel':
            if args:
                raise ClientError('performance.cancel takes no arguments.')
        elif op in ('acl.audit', 'plugins.list'):
            if set(args) != {'offset'} or type(args['offset']) is not int or not 0 <= args['offset'] <= 2**32-1025:
                raise ClientError('ACL audit offset must be a nonnegative byte offset.')
        elif op == 'app.list':
            if set(args) - {'after', 'query'}:
                raise ClientError('Application inventory accepts only after and query.')
            after, query = args.get('after', ''), args.get('query', '')
            if not isinstance(after, str) or len(after) >= 32 or not after.isascii() or '\x00' in after:
                raise ClientError('Invalid application inventory cursor.')
            if not isinstance(query, str) or '\x00' in query or any(0xd800 <= ord(c) <= 0xdfff for c in query) or len(query.encode('utf-8')) >= 128:
                raise ClientError('Application query must be fewer than128 UTF-8 bytes.')
        elif op in ('app.install', 'app.install.status'):
            expected={'operation_id','path','yes'} if op=='app.install' else {'operation_id'}
            if set(args)!=expected or not isinstance(args['operation_id'],str) or not re.fullmatch('[0-9a-f]{32}',args['operation_id']):
                raise ClientError('Installation requires a stable 32-digit operation_id.')
            if op=='app.install':
                if args['yes'] is not True:raise ClientError('VPK installation requires --yes.')
                VitaClient._command('fs.stat',{'path':args['path']})
                if not args['path'].endswith('.vpk'):raise ClientError('Installation requires a Vita-side .vpk path.')
        elif op in ('app.launch', 'app.close'):
            if set(args) != {'title_id'} or not isinstance(args['title_id'], str) or not re.fullmatch('[A-Z0-9]{9}', args['title_id']):
                raise ClientError('A nine-character uppercase title_id is required.')
        elif op in ('fs.mkdir', 'fs.move', 'fs.trash', 'fs.purge'):
            required = {'operation_id', 'path', 'yes'} | ({'destination'} if op == 'fs.move' else {'trash_id'} if op == 'fs.purge' else set())
            if set(args) != required or not isinstance(args['operation_id'], str) or not re.fullmatch('[0-9a-f]{32}', args['operation_id']) or type(args['yes']) is not bool:
                raise ClientError('Write commands require a stable 32-digit operation_id and boolean yes intent.')
            if op == 'fs.purge' and (not isinstance(args['trash_id'], str) or not re.fullmatch('[0-9a-f]{32}', args['trash_id']) or args['trash_id'] == args['operation_id']):
                raise ClientError('Purge requires the completed trash operation ID and a separate new operation ID.')
            for key in ('path', 'destination') if op == 'fs.move' else ('path',):
                path = args[key]
                if not isinstance(path, str) or not path or any(ord(c) < 32 or ord(c) == 127 or 0xd800 <= ord(c) <= 0xdfff for c in path) or len(path.encode('utf-8')) >= 512:
                    raise ClientError('Invalid write path.')
        elif op in ('fs.stat', 'fs.list'):
            path = args.get('path')
            if set(args) != ({'path', 'offset'} if op == 'fs.list' else {'path'}) or not isinstance(path, str) or not path or any(ord(c) < 32 or ord(c) == 127 or 0xd800 <= ord(c) <= 0xdfff for c in path) or len(path.encode('utf-8')) >= 512:
                raise ClientError('Filesystem commands require a Vita path of at most 511 UTF-8 bytes.')
            if op == 'fs.list' and (type(args['offset']) is not int or not 0 <= args['offset'] <= 2**32-1):
                raise ClientError('Directory offset must be an unsigned 32-bit integer.')
        elif args:
            raise ClientError('This operation takes no arguments.')
        return {'op': op, 'args': dict(args)}

    def _ensure_screen(self):
        if self.manage_screen and not self._screen_owned:
            reply = self._call_raw('screen.on', {})
            if reply.get('status') != 'accepted':
                raise ClientError('Screen-on was rejected; access session did not start.')

    def close(self):
        """Finish the access session, then close transport. Reconnects use only transport cleanup."""
        had_error = sys.exc_info()[0] is not None
        try:
            if self._screen_owned and self.screen_off_when_done:
                screen_off_if_idle(self)
        except Exception as exc:
            self._screen_cleanup_error = exc
            if not had_error:
                raise
            # Preserve the original operation's exception, but expose cleanup failure.
            print('Vita screen cleanup failed: ' + str(exc), file=sys.stderr)
        finally:
            self._screen_owned = False
            self._close_transport()

    def _close_transport(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # The exact certificate obtained through trusted pairing is the trust
        # anchor, rather than a public CA. Check it BEFORE sending HTTP/token.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with private_pem(self.client_certificate) as certificate, private_pem(self.client_key) as key:
            context.load_cert_chain(certificate, key, password=lambda: '')
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
        try:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), self.pin):
                raise ClientError('Device certificate does not match the paired fingerprint; no token sent.')
        except ConnectionRefusedError as exc:
            connection.close()
            raise ConnectionRefusedError(connection_refused_message()) from exc
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        return connection

    def _exchange(self, request):
        try:
            return self._exchange_once(request)
        except ClientError as exc:
            # Replay the exact retained command ID once after a dead socket.
            # The Vita cache prevents duplicate effects; no new pairing/grant.
            if not self.retry_disconnect or not isinstance(exc.__cause__,
                    (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError)):
                raise
            import time
            time.sleep(1)
            return self._exchange_once(request)

    def _exchange_once(self, request):
        payload = json.dumps(request, separators=(',', ':'), ensure_ascii=True).encode()
        if len(payload) > 131072:
            raise ClientError('Request exceeds device limit.')
        try:
            # Never let HTTPSConnection implicitly reconnect: every new socket
            # must pass the pin check before receiving the bearer credential.
            connection = self._connection
            if connection is None or connection.sock is None:
                self._close_transport()
                connection = self._connect()
            connection.request('POST', '/v1/command', body=payload, headers={
                'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token,
                'Connection': 'keep-alive'})
            response = connection.getresponse()
            lengths = response.headers.get_all('Content-Length', [])
            if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                raise ClientError('Unsupported response framing.')
            if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 4096:
                raise ClientError('Invalid response length.')
            size = int(lengths[0])
            data = response.read(size + 1)
            if len(data) != size:
                raise ClientError('Truncated or oversized response.')
            if response.status == 401:
                raise ClientError('Pairing grant is unknown, expired or revoked.')
            if response.status != 200:
                raise ClientError('Device rejected the HTTP request (status %d).' % response.status)
            if response.headers.get('Content-Type', '').lower() != 'application/json':
                raise ClientError('Unexpected response content type.')
            result = strict_json(data)
            if not isinstance(result, dict) or type(result.get('v')) is not int or result.get('v') != 1 or result.get('id') != request['id'] or result.get('status') not in ('ok', 'accepted', 'error'):
                raise ClientError('Response does not match the pending command.')
            if response.will_close:
                self._close_transport()
            return result
        except (OSError, http.client.HTTPException, ValueError, RecursionError) as exc:
            self.last_transport_error = type(exc).__name__
            self._close_transport()
            detail=str(exc) or type(exc).__name__
            raise ClientError('Transport/response failed (%s: %s); pending command retained for recovery.' % (type(exc).__name__,detail)) from exc
        except BaseException:
            self._close_transport()
            raise

    def frame(self):
        """Return (JPEG bytes, metadata) without consuming a command sequence ID."""
        self._ensure_screen()
        with self._locked_state():
            try:
                connection = self._connection
                if connection is None or connection.sock is None:
                    self._close_transport()
                    connection = self._connect()
                connection.request('POST', '/v1/frame', body=b'{}', headers={
                    'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token,
                    'Connection': 'keep-alive'})
                response = connection.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported frame response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 2187264:
                    raise ClientError('Invalid frame length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated frame response.')
                if response.status == 401:
                    raise ClientError('Pairing grant is unknown, expired or revoked.')
                if response.status != 200:
                    if response.headers.get('Content-Type', '').lower() == 'application/json' and len(data) <= 1024:
                        try:
                            error = strict_json(data)
                        except (ValueError, UnicodeError):
                            error = None
                        if (isinstance(error, dict) and {'error', 'code'} <= set(error) and
                                not set(error) - {'error', 'code', 'stage', 'display', 'name', 'message'} and
                                ('name' not in error or isinstance(error['name'],str) and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',error['name'])) and
                                ('message' not in error or isinstance(error['message'],str) and 0<len(error['message'])<=512) and
                                ('display' not in error or valid_display_observation(error['display'])) and
                                ('stage' not in error or error['stage'] in ('pool', 'capture', 'jpeg_init', 'jpeg_region', 'jpeg_encode', 'cleanup')) and
                                error['error'] == 'frame_unavailable' and type(error['code']) is int and
                                -(2**31) <= error['code'] < 2**31):
                            raise NativeFrameError(response.status, error['code'], error.get('stage'), error.get('display'),error.get('name'),error.get('message'))
                    raise ClientError('Frame capture rejected (status %d).' % response.status)
                if response.headers.get('Content-Type', '').lower() != 'image/jpeg' or not data.startswith(b'\xff\xd8') or not data.endswith(b'\xff\xd9'):
                    raise ClientError('Invalid JPEG frame response.')
                metadata = {}
                for key, maximum in (('Width', 960), ('Height', 544), ('Process', 2**31-1),
                                     ('Capture-Start', 2**64-1), ('Capture-End', 2**64-1)):
                    values = response.headers.get_all('X-Vita-' + key, [])
                    if len(values) != 1 or not re.fullmatch('[0-9]{1,20}', values[0]) or int(values[0]) > maximum:
                        raise ClientError('Invalid frame metadata.')
                    metadata[key.lower().replace('-', '_')] = int(values[0])
                if not metadata['width'] or not metadata['height'] or not metadata['process'] or metadata['capture_end'] < metadata['capture_start']:
                    raise ClientError('Invalid frame metadata.')
                if response.will_close:
                    self._close_transport()
                return data, metadata
            except NativeFrameError:
                # The full, validated error response has been consumed. A
                # missing framebuffer does not invalidate the event channel.
                if response.will_close:
                    self._close_transport()
                raise
            except (OSError, http.client.HTTPException, ValueError):
                self._close_transport()
                raise ClientError('Frame transport failed; request a fresh frame.') from None
            except BaseException:
                self._close_transport()
                raise

    def file_chunk(self, path, offset=0, length=16384):
        """Read a bounded raw file range; no command ID or shell/FTP transport."""
        self._command('fs.stat', {'path': path})
        if type(offset) is not int or not 0 <= offset <= 2**63-1 or type(length) is not int or not 1 <= length <= 16384:
            raise ClientError('Invalid file range.')
        payload = json.dumps({'path': path, 'offset': str(offset), 'length': length}, separators=(',', ':')).encode()
        self._ensure_screen()
        with self._locked_state():
            try:
                connection = self._connection
                if connection is None or connection.sock is None:
                    self._close_transport()
                    connection = self._connect()
                connection.request('POST', '/v1/file/read', body=payload, headers={
                    'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token,
                    'Connection': 'keep-alive'})
                response = connection.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported file response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 <= int(lengths[0]) <= 16384:
                    raise ClientError('Invalid file response length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated file response.')
                if response.status != 200:
                    detail = strict_json(data)
                    code = detail.get('code') if isinstance(detail, dict) else None
                    raise ClientError('File read rejected (HTTP %d, native code %s).' % (response.status, code))
                if response.headers.get('Content-Type', '').lower() != 'application/octet-stream':
                    raise ClientError('Unexpected file response content type.')
                metadata = {}
                for key in ('Offset', 'File-Bytes'):
                    values = response.headers.get_all('X-Vita-' + key, [])
                    if len(values) != 1 or not re.fullmatch('0|[1-9][0-9]{0,18}', values[0]) or int(values[0]) > 2**63-1:
                        raise ClientError('Invalid file response metadata.')
                    metadata[key.lower().replace('-', '_')] = int(values[0])
                modified = response.headers.get_all('X-Vita-Modified', [])
                if len(modified) != 1 or not re.fullmatch(r'[0-9]{1,5}-[0-9]{1,5}-[0-9]{1,5}T[0-9]{1,5}:[0-9]{1,5}:[0-9]{1,5}\.[0-9]{1,10}', modified[0]):
                    raise ClientError('Invalid file modification metadata.')
                metadata['modified'] = modified[0]
                if metadata['offset'] != offset or offset > metadata['file_bytes'] or len(data) != min(length, metadata['file_bytes'] - offset):
                    raise ClientError('File response does not match the requested range.')
                if response.will_close:
                    self._close_transport()
                return data, metadata
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self.last_transport_error = type(exc).__name__
                self._close_transport()
                raise ClientError('File transport failed; download is incomplete.') from exc
            except BaseException:
                self._close_transport()
                raise

    def upload_chunk_size(self):
        """Negotiate once per client; old plugins retain their 12 KiB limit."""
        if self._upload_chunk_bytes is None:
            reply=self.call('capabilities')
            if reply.get('status')!='ok':raise ClientError('Cannot query upload capabilities.')
            upload=reply.get('result',{}).get('upload',{})
            limit=upload.get('chunk_bytes_max',12288)
            if type(limit) is not int or not 1<=limit<=122880:
                raise ClientError('Invalid advertised upload chunk limit.')
            self._upload_chunk_bytes=limit
        return self._upload_chunk_bytes

    def upload_step(self, request, action, offset=0, data=b''):
        """One sequential upload step; workflow must persist request first."""
        fields = {'operation_id', 'path', 'bytes', 'sha256', 'expected_sha256', 'overwrite', 'yes'}
        actions = ('begin', 'chunk', 'verify', 'commit', 'recover')
        if not isinstance(request, dict) or set(request) != fields or action not in actions:
            raise ClientError('Invalid upload metadata.')
        self._command('fs.mkdir', {key: request[key] for key in ('operation_id', 'path', 'yes')})
        if type(request['overwrite']) is not bool or not isinstance(request['bytes'], str) or not re.fullmatch('0|[1-9][0-9]{0,18}', request['bytes']) or int(request['bytes']) > 2**63-1:
            raise ClientError('Invalid upload size or overwrite flag.')
        if not isinstance(request['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', request['sha256']) or not isinstance(request['expected_sha256'], str) or not re.fullmatch('(?:[0-9a-f]{64})?' if request['overwrite'] else '', request['expected_sha256']):
            raise ClientError('Invalid upload content digest.')
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes) or len(data) > 122880:
            raise ClientError('Invalid upload chunk.')
        if len(data)>12288 and len(data)>self.upload_chunk_size():
            raise ClientError('Upload chunk exceeds the installed plugin limit.')
        if action == 'chunk':
            if not data or offset + len(data) > int(request['bytes']):raise ClientError('Chunk is outside the upload.')
        elif offset or data:
            raise ClientError('Only chunk steps carry an offset and data.')
        metadata = json.dumps({**request, 'action': action, 'offset': str(offset)}, ensure_ascii=True, separators=(',', ':')).encode()
        if len(metadata) > 3072:
            raise ClientError('Upload metadata exceeds its limit.')
        payload = struct.pack('!I', len(metadata)) + metadata + data
        self._ensure_screen()
        with self._locked_state() as state:
            if state['pending'] is not None:
                raise ClientError('Recover the pending command before uploading.')
            try:
                connection = self._connection
                if connection is None or connection.sock is None:
                    self._close_transport()
                    connection = self._connect()
                connection.request('POST', '/v1/file/upload', body=payload, headers={
                    'Content-Type': 'application/octet-stream', 'Authorization': 'Bearer ' + self.token,
                    'Connection': 'keep-alive'})
                response = connection.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported upload response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 2048:
                    raise ClientError('Invalid upload response length.')
                raw = response.read(int(lengths[0]) + 1)
                if len(raw) != int(lengths[0]) or response.status != 200 or response.headers.get('Content-Type', '').lower() != 'application/json':
                    raise ClientError('Upload response rejected or truncated (HTTP %d).' % response.status)
                result = strict_json(raw)
                required = {'v', 'operation_id', 'action', 'code', 'received', 'verified', 'complete', 'sequence', 'effect_started', 'readback_required'}
                if not isinstance(result, dict) or set(result) != required or type(result['v']) is not int or result['v'] != 1 or result['operation_id'] != request['operation_id'] or type(result['action']) is not int or result['action'] != actions.index(action):
                    raise ClientError('Upload response does not match the operation.')
                if type(result['code']) is not int or not -2**31 <= result['code'] <= 0:
                    raise ClientError('Invalid upload result.')
                for key in ('received', 'sequence'):
                    if not isinstance(result[key], str) or not re.fullmatch('0|[1-9][0-9]{0,18}', result[key]) or int(result[key]) > 2**63-1:
                        raise ClientError('Invalid upload progress.')
                timing_headers={name:response.headers.get_all('X-Vita-Upload-'+header,[]) for name,header in
                                (('journal_open','Journal-Open-Us'),('work','Work-Us'),('journal_close','Journal-Close-Us'))}
                if any(timing_headers.values()):
                    if any(len(values)!=1 or not re.fullmatch('0|[1-9][0-9]{0,19}',values[0]) or int(values[0])>2**64-1 for values in timing_headers.values()):
                        raise ClientError('Invalid upload timings.')
                    result['timings_us']={name:values[0] for name,values in timing_headers.items()}
                if int(result['received']) > int(request['bytes']) or any(type(result[k]) is not bool for k in ('verified', 'complete', 'effect_started', 'readback_required')):
                    raise ClientError('Invalid upload flags or progress.')
                if response.will_close:self._close_transport()
                return result
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self._close_transport()
                raise ClientError('Upload transport failed (%s: %s); resume using the saved transfer state.' % (type(exc).__name__,str(exc) or type(exc).__name__)) from exc
            except BaseException:
                self._close_transport()
                raise

    def audit_page(self, after=0):
        """Read bounded journal events without changing the device journal."""
        if type(after) is not int or not 0 <= after <= 2**63-1:
            raise ClientError('Invalid audit cursor.')
        payload = json.dumps({'after': str(after)}, separators=(',', ':')).encode()
        self._ensure_screen()
        with self._locked_state():
            try:
                connection = self._connection
                if connection is None or connection.sock is None:
                    self._close_transport()
                    connection = self._connect()
                connection.request('POST', '/v1/audit', body=payload, headers={
                    'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token,
                    'Connection': 'keep-alive'})
                response = connection.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported audit response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 16384:
                    raise ClientError('Invalid audit response length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated audit response.')
                if response.status != 200:
                    raise ClientError('Audit export rejected (HTTP %d).' % response.status)
                if response.headers.get('Content-Type', '').lower() != 'application/json':
                    raise ClientError('Unexpected audit content type.')
                result = strict_json(data)
                if response.will_close:
                    self._close_transport()
                return result
            except (OSError, http.client.HTTPException, ValueError):
                self._close_transport()
                raise ClientError('Audit transport failed; saved cursor is unchanged.') from None
            except BaseException:
                self._close_transport()
                raise

    def download(self, path, output):
        """Stream to a new private host file; remove incomplete output on failure."""
        self._command('fs.stat', {'path': path})
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        offset, revision = 0, None
        try:
            with os.fdopen(fd, 'wb') as stream:
                while True:
                    data, metadata = self.file_chunk(path, offset)
                    current = (metadata['file_bytes'], metadata['modified'])
                    if revision is not None and current != revision:
                        raise ClientError('File changed during download.')
                    revision = current
                    stream.write(data)
                    offset += len(data)
                    if offset == metadata['file_bytes']:
                        break
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(output)
            raise
        return {'status': 'ok', 'file': str(output), 'bytes': str(offset), 'modified': revision[1]}

    def _finish(self, state):
        request = state['pending']
        if not isinstance(request, dict) or set(request) != {'v', 'id', 'op', 'args'} or request['v'] != 1 or request['id'] != str(state['next_id'] - 1):
            raise ClientError('Invalid pending request state.')
        self._command(request['op'], request['args'])
        result = self._exchange(request)
        state['last'] = {'request': request, 'response': result}
        state['pending'] = None
        durable_json(self.path, state)
        return result

    def list_entries(self, op, args=None):
        """Complete listings by default; limit/page are presentation options."""
        args = {} if args is None else args
        allowed = {'fs.list': {'path', 'sort_by', 'order'}, 'app.list': {'query'}, 'plugins.list': set(), 'livearea.schema': set(), 'content.list': {'category'}, 'livearea.layout': {'section'}}
        if op not in allowed or not isinstance(args, dict) or set(args) - allowed[op] - {'limit', 'page'}:
            raise ClientError('Invalid listing arguments.')
        limit, page = args.get('limit'), args.get('page', 1)
        if 'limit' in args and (type(limit) is not int or limit < 1):
            raise ClientError('limit must be a positive integer.')
        if 'page' in args and limit is None:
            raise ClientError('page requires limit.')
        if type(page) is not int or page < 1:
            raise ClientError('page must be a positive integer (first page is 1).')
        sort_by = args.get('sort_by') if op == 'fs.list' else None
        order = args.get('order', 'asc')
        if sort_by is not None and sort_by not in ('name', 'modified', 'date', 'size'):
            raise ClientError('sort_by must be name, modified or size.')
        if order not in ('asc', 'desc', 'dsc') or ('order' in args and sort_by is None):
            raise ClientError('order requires sort_by and must be asc or desc (dsc).')
        base = {key: value for key, value in args.items() if key in allowed[op] and key not in ('sort_by', 'order')}
        cursor_key, cursor = ('after', '') if op in ('app.list','livearea.schema','content.list') else ('offset', 0)
        # Validate native arguments before contacting the console.
        self._command(op, {**base, cursor_key: cursor})
        skip = (page - 1) * limit if limit is not None else 0
        entries, metadata, first_observed = [], None, None
        consumed, more = 0, False
        visited = set()
        restarts = 0
        while True:
            if cursor in visited:
                raise ClientError('Native listing cursor repeated; listing is incomplete.')
            visited.add(cursor)
            reply = self._call_raw(op, {**base, cursor_key: cursor})
            if reply.get('status') != 'ok':
                error = reply.get('error')
                if (cursor and restarts < 2 and isinstance(error, dict) and
                        ((op == 'fs.list' and error.get('source') == 'filesystem') or
                         (op == 'content.list' and base.get('category') in
                          ('psp_application','playstation_application','psp_savedata','playstation_savedata') and
                          error.get('source') in ('native_metadata','protocol'))) and
                        error.get('code') == -5):
                    # The native bounded iterator expired or was replaced by an
                    # interleaved listing/mutation. Discard every old row first.
                    restarts += 1
                    cursor = '' if cursor_key == 'after' else 0
                    entries, metadata, first_observed = [], None, None
                    consumed, more = 0, False
                    visited.clear()
                    continue
                raise ClientError('Listing failed; no partial listing returned: ' + str(error))
            batch = reply.get('result')
            if not isinstance(batch, dict) or not isinstance(batch.get('entries'), list) or type(batch.get('more')) is not bool:
                raise ClientError('Invalid native listing response.')
            current = {key: value for key, value in batch.items() if key not in ('entries', 'more', 'next_offset', 'next_after')}
            if metadata is not None and current.get('config_path') != metadata.get('config_path'):
                raise ClientError('Active plugin configuration changed during listing.')
            metadata = current
            if first_observed is None:
                first_observed = current.get('observed_us')
            for entry in batch['entries']:
                if op == 'plugins.list' and entry.get('configured_enabled') is False:
                    continue
                if sort_by is not None or consumed >= skip:
                    if sort_by is None and limit is not None and len(entries) == limit:
                        more = True
                        break
                    entries.append(entry)
                consumed += 1
            if more or not batch['more']:
                break
            next_cursor = batch.get('next_after' if op in ('app.list','livearea.schema','content.list') else 'next_offset')
            if op in ('app.list','livearea.schema','content.list'):
                valid = isinstance(next_cursor,str) and (int(next_cursor)>int(cursor or '0') if op=='content.list' and re.fullmatch('0|[1-9][0-9]{0,18}',next_cursor) else next_cursor>cursor if op!='content.list' else False)
            else:
                valid = type(next_cursor) is int and next_cursor > cursor
            if not valid:
                raise ClientError('Native listing cursor did not advance; listing is incomplete.')
            cursor = next_cursor
        if sort_by is not None:
            def key(entry):
                name = entry['name'].casefold()
                if sort_by in ('modified', 'date'):
                    return (entry.get('modified') or '', name)
                if sort_by == 'size':
                    # Directory stat byte counts do not measure folder contents.
                    return (0 if entry['kind'] == 'directory' else int(entry['bytes']), name)
                return (name, entry['name'])
            entries.sort(key=key, reverse=order in ('desc', 'dsc'))
            more = limit is not None and len(entries) > skip + limit
            entries = entries[skip:skip+limit] if limit is not None else entries
        result = {**metadata, 'entries': entries, 'entry_count': len(entries),
                  'complete': page == 1 and not more, 'snapshot': False}
        if op == 'fs.list':
            result['path'] = base['path']
            result['begin_observed_us'] = first_observed
        if sort_by is not None:
            result['sort'] = {'by': 'modified' if sort_by == 'date' else sort_by, 'order': 'desc' if order in ('desc', 'dsc') else 'asc'}
        if limit is not None:
            result['pagination'] = {'limit': limit, 'page': page, 'has_more': more}
        return {**reply, 'result': result}

    def call(self, op, args=None):
        args = {} if args is None else args
        if op=='content.delete.status':
            from content_delete import status
            return status(self,args)
        if op=='content.delete.preview':
            from content_delete import preview
            return preview(self,args)
        if op in ('content.delete.changes','content.scope') and isinstance(args,dict) and 'cursor' not in args:
            from content_delete import collect
            return collect(self,op,args)
        if op=='content.albums' and isinstance(args,dict) and not ({'cursor','list_cursor'} & set(args)):
            from content_delete import collect_albums
            return collect_albums(self,args)
        if op=='content.export':
            from content import export_media
            return export_media(self,args)
        if op=='savedata.list':
            from savedata import inventory
            return inventory(self,args)
        if op == 'app.launch':
            self._command(op, args)
            from launch import launch
            return launch(self, args)
        # Explicit native cursors remain supported for internal/legacy callers.
        if op=='livearea.layout' and isinstance(args,dict) and 'section' not in args and 'offset' not in args:
            from livearea import layout
            return layout(self,args)
        if op in ('fs.list', 'plugins.list', 'app.list', 'livearea.schema', 'content.list', 'livearea.layout') and isinstance(args, dict) and not set(args) & {'offset', 'after'}:
            return self.list_entries(op, args)
        return self._call_raw(op, args)

    def _call_raw(self, op, args=None):
        command = self._command(op, {} if args is None else args)
        if op not in ('screen.on', 'screen.off'):
            self._ensure_screen()
        with self._locked_state() as state:
            if state['pending'] is not None:
                if any(state['pending'].get(k) != v for k, v in command.items()):
                    raise ClientError('An uncertain command is pending; recover it before issuing another.')
            else:
                if state['next_id'] == 2**64:
                    raise ClientError('Session request IDs are exhausted.')
                state['pending'] = {'v': 1, 'id': str(state['next_id']), **command}
                state['next_id'] += 1
                # Persist the exact command before any possible remote effect.
                durable_json(self.path, state)
            result = self._finish(state)
            if op in ('app.install','app.install.status') and result.get('status')=='ok':
                operation_id=command['args'].get('operation_id')
                installs=getattr(self,'_screen_installs',set())
                if result.get('result',{}).get('running') is False:
                    installs.discard(operation_id)
                else:
                    installs.add(operation_id)
                self._screen_installs=installs
            self._track_screen_reply(op,result)
            return result

    def _track_screen_reply(self,op,result):
        if result.get('status')!='accepted':
            return
        if op=='screen.on' and self.manage_screen:
            self._screen_owned=True
        elif op in ('screen.off','system.reboot'):
            # Reboot's terminal response closes command access too.
            self._screen_owned=False

    def recover(self):
        with self._locked_state() as state:
            if state['pending'] is not None:
                op=state['pending'].get('op')
                reply=self._finish(state)
                self._track_screen_reply(op,reply)
                return reply
            if state['last'] is not None:
                return state['last']['response']
            raise ClientError('No command is available to recover.')


def main(argv=None, *, screen_off_when_done=True, host=None, agent_name=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', required=True, type=Path)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--macro-store', type=Path, help='Private per-title macro storage (defaults beside state).')
    parser.add_argument('--serve', action='store_true',
                        help='Read one JSON command per line and reuse the authenticated connection.')
    options = parser.parse_args(argv)
    client = None
    runner = None
    listener = None
    output_guard = threading.Lock()
    def emit(value):
        with output_guard:print(json.dumps(value,separators=(',',':')),flush=True)
    try:
        client = VitaClient(private_json(options.credentials), options.state, screen_off_when_done=screen_off_when_done, host=host, agent_name=agent_name)
        while True:
            data = sys.stdin.buffer.readline(131073) if options.serve else sys.stdin.buffer.read(131073)
            if not data and options.serve:
                break
            if len(data) > 131072:
                raise ClientError('Tool input exceeds its size limit.')
            request = strict_json(data)
            if not isinstance(request, dict) or set(request) != {'op', 'args'}:
                raise ClientError('Tool input must contain exactly op and args.')
            if request['op'] in ('watch.start','watch.stop','watch.status'):
                if not isinstance(request['args'],dict) or request['args']:raise ClientError('Watch operations take an empty argument object.')
                if not options.serve:raise ClientError('Asynchronous watches require --serve.')
                from event_listener import EventListener
                if listener is None:
                    listener=EventListener(client,lambda event:emit({'event':event}))
                result={'watch.start':listener.start,'watch.stop':listener.stop,'watch.status':listener.status}[request['op']]()
            elif request['op'] in ('watch.log.start','watch.log.stop'):
                if not options.serve or listener is None:raise ClientError('Log watches require watch.start in --serve mode.')
                args=request['args']
                if request['op']=='watch.log.start':
                    VitaClient._command('log.start',args)
                    result=listener.log_start(args['path'],args['marker'])
                else:
                    VitaClient._command('log.stop',args)
                    result=listener.log_stop(args['watch_id'])
            elif request['op'] in ('macro.save', 'macro.import', 'macro.load', 'macro.run', 'macro.status', 'macro.stop', 'touch.swipe'):
                from macro_runner import MacroRunner
                from swipes import swipe_plan
                if not isinstance(request['args'], dict):raise ClientError('Arguments must be an object.')
                if runner is None:
                    runner = MacroRunner(client, options.macro_store or options.state.parent/'macros')
                op, args = request['op'], request['args']
                if op == 'macro.save':
                    if set(args) != {'macro'}:raise ClientError('macro.save requires macro.')
                    result = {'status': 'ok', 'file': str(runner.store.save(args['macro']))}
                elif op=='macro.import':
                    from macros import MACRO_FILE_BYTES
                    if set(args)!={'file'} or not isinstance(args['file'],str):raise ClientError('macro.import requires a private host JSON file.')
                    result={'status':'ok','file':str(runner.store.save(private_json(Path(args['file']),max_bytes=MACRO_FILE_BYTES)))}
                elif op == 'macro.load':
                    if set(args) != {'title_id', 'name'}:raise ClientError('macro.load requires title_id and name.')
                    result = {'status': 'ok', 'result': runner.store.load(args['title_id'],args['name'])}
                elif op in ('macro.status', 'macro.stop'):
                    if args:raise ClientError('This operation takes no arguments.')
                    result = runner.status() if op == 'macro.status' else runner.stop()
                elif op == 'macro.run':
                    if not options.serve:raise ClientError('Asynchronous macro.run requires --serve.')
                    if not {'title_id','name'}<=set(args) or set(args)-{'title_id','name','repeats'}:raise ClientError('macro.run requires title_id, name and optional repeats.')
                    result = runner.run(args['title_id'],args['name'],args.get('repeats',1))
                else:
                    if not options.serve:raise ClientError('Asynchronous touch.swipe requires --serve.')
                    result = runner.start(swipe_plan(client,args),name='swipe')
            elif request['op'] == 'livearea.blob.download':
                from livearea import download_blob
                result=download_blob(client,request['args'])
            elif request['op'] == 'fs.download':
                args = request['args']
                if not isinstance(args, dict) or set(args) != {'path', 'output'} or not isinstance(args['output'], str):
                    raise ClientError('fs.download requires a Vita path and host output file.')
                result = client.download(args['path'], args['output'])
            elif request['op'] == 'screen.capture':
                args = request['args']
                if not isinstance(args, dict) or set(args) != {'output'} or not isinstance(args['output'], str):
                    raise ClientError('screen.capture requires a host output file path.')
                # Exclusive creation prevents accidental replacement or symlink following.
                fd = os.open(args['output'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        jpeg, metadata = client.frame()
                        stream.write(jpeg)
                except BaseException:
                    os.unlink(args['output'])
                    raise
                result = {'status': 'ok', 'file': args['output'], 'bytes': len(jpeg), **metadata}
            else:
                result = client.recover() if request == {'op': 'client.recover', 'args': {}} else client.call(request['op'], request['args'])
            emit(result)
            if not options.serve:
                break
        return 0
    except (ClientError, OSError, ValueError, TypeError) as exc:
        message = str(exc) if isinstance(exc, ClientError) else 'Invalid local configuration or tool input.'
        result = {'status': 'client_error', 'message': message}
        if isinstance(exc, NativeFrameError):
            result.update(error='frame_unavailable', http_status=exc.status, native_result=exc.native_result)
            if exc.stage is not None:
                result['stage'] = exc.stage
            if exc.display is not None:
                result['display'] = exc.display
        print(json.dumps(result))
        return 1
    finally:
        try:
            if listener is not None:
                listener.stop()
        finally:
            try:
                if runner is not None:
                    runner.stop()
            finally:
                if client is not None:
                    client.close()


if __name__ == '__main__':
    raise SystemExit(main())
