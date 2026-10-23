# SPDX-License-Identifier: GPL-3.0-or-later
"""Agent-facing client for Vita command protocol v1 (Linux/macOS host).

Credentials and certificate pin come from trusted on-device pairing. This client
cannot issue grants, approve operations or bypass the Vita policy engine.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from errors import annotate, path_reason
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
from input_sequence import validate as validate_readable_events

# A TCP connect plus TLS handshake may wait behind the Vita retiring a dead
# connection (up to 30 s), so allow well beyond that before giving up.
CONNECT_TIMEOUT = 60
# Native work is synchronous on the Vita; keepalive notices a dead peer while
# waiting, so a slow reply is waited for rather than abandoned.
RESPONSE_TIMEOUT = 180
# How long one call keeps reconnecting, renewing and replaying before it
# reports failure.
RECOVERY_WINDOW = 90
LOCK_WAIT = 300
# After a network reset the Vita reopens its command listener within about a
# second, keeping the session; a refusal that soon after a drop is waited out
# instead of being taken as a lost session.
LISTENER_RESET_WAIT = 10
# Running these again under a new session has no effect beyond the reply, so
# a lost reply is simply asked for again instead of being recorded unresolved.
REPEATABLE_OPS = frozenset({
    'capabilities', 'system.snapshot', 'app.running', 'app.list', 'fs.stat', 'fs.list',
    'plugins.list', 'touch.panels', 'livearea.schema', 'livearea.layout', 'livearea.blob',
    'performance.read', 'events.read', 'dialog.events.read', 'log.read', 'input.status',
    'input.heartbeat', 'run.status', 'acl.status', 'acl.audit', 'content.list', 'content.scope',
    'content.albums', 'content.audit', 'content.delete.status', 'content.delete.changes',
    'app.install.status', 'decrypt.status', 'screen.on', 'screen.off', 'events.subscribe',
    'session.ping', 'session.extend'})
# The Vita journals these by operation/request ID and answers a repeat with
# the recorded outcome, so they may be resent even under a new session.
DEDUPED_OPS = frozenset({'fs.mkdir', 'fs.move', 'fs.trash', 'fs.purge', 'app.install',
                         'decrypt.start', 'acl.request', 'content.delete.request',
                         'content.delete.preview'})
# Their effect belongs to the session itself and ended with it.
SESSION_BOUND_OPS = frozenset({
    'log.start', 'log.stop', 'events.start', 'events.stop', 'dialog.events.start',
    'dialog.events.stop', 'performance.measure', 'performance.watch', 'performance.cancel',
    'run.begin', 'run.update', 'run.end', 'input.acquire', 'input.cancel', 'input.release',
    'macro.acquire'})
RESENDABLE_OPS = REPEATABLE_OPS | DEDUPED_OPS | SESSION_BOUND_OPS
# Session upkeep: no screen wake, and never replaces the reply session recover shows.
QUIET_OPS = frozenset({'session.ping', 'session.extend', 'events.subscribe'})


class ClientError(Exception):
    pass


class NotExecutedError(ClientError):
    """The Vita certainly did not run this request; sending it again is safe."""
    retryable = True


class NotSentError(NotExecutedError):
    """No complete request reached the Vita (connect, TLS or send failed)."""
    def __init__(self, message, *, refused=False):
        super().__init__(message)
        self.refused = refused


class PinMismatchError(NotSentError):
    retryable = False


class GrantExpiredError(NotExecutedError):
    """The Vita rejected the token before running anything (HTTP 401)."""


class ServiceBusyError(NotExecutedError):
    """The Vita answered 503: its monitor was not ready, nothing ran."""


class CommandRejected(NotExecutedError):
    """The Vita refused the request before reserving its ID (id null)."""
    def __init__(self, message, reply, *, retryable=False):
        super().__init__(message)
        self.reply, self.retryable = reply, retryable


class UncertainError(ClientError):
    """The request was sent but no complete reply arrived. The exact request
    stays pending and is replayed with the same ID, which never repeats it."""


class UncertainOutcomeError(ClientError):
    """A sent request can no longer be replayed because the Vita lost the
    session it ran under. It is recorded in unresolved.jsonl, never resent."""
    def __init__(self, message, record):
        super().__init__(message)
        self.record = record

    def as_result(self):
        return {'status': 'unconfirmed', 'message': str(self), 'unresolved': self.record}


class UploadTransportError(ClientError):
    """The same durable upload step may be retried after reconnecting."""


def set_keepalive(sock):
    """Notice a peer that vanished (sleep, Wi-Fi loss, NAT reset) in ~40 s."""
    for level, name, value in ((socket.SOL_SOCKET, 'SO_KEEPALIVE', 1),
                               (socket.IPPROTO_TCP, 'TCP_KEEPIDLE', 15),
                               (socket.IPPROTO_TCP, 'TCP_KEEPALIVE', 15),
                               (socket.IPPROTO_TCP, 'TCP_KEEPINTVL', 5),
                               (socket.IPPROTO_TCP, 'TCP_KEEPCNT', 5),
                               (socket.IPPROTO_TCP, 'TCP_USER_TIMEOUT', 60000)):
        option = getattr(socket, name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(level, option, value)
        except OSError:
            pass


def unresolved_path(state_path):
    return Path(state_path).parent / 'unresolved.jsonl'


def record_unresolved(state_path, pending, reason):
    """Append an unreplayable request to the private unresolved journal."""
    op = pending.get('op')
    if op in DEDUPED_OPS:
        instruction = ('Outcome unknown. Repeating the identical command with the same operation/request ID is '
                       'safe: the Vita answers a repeat with the recorded outcome instead of acting twice.')
    elif op in SESSION_BOUND_OPS:
        instruction = 'Its effect ended with the old session; issue it again if it is still needed.'
    elif op == 'system.reboot':
        instruction = ('The session ended after the reboot request, which a reboot does. Check with '
                       'diagnostics status or system snapshot that the Vita restarted.')
    else:
        instruction = ('Outcome unknown: check the resulting Vita state (app running, fs stat/list, input/macro '
                       'status, audit) before repeating this operation.')
    record = {'recorded_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'reason': reason,
              'id': pending.get('id'), 'op': op, 'args': pending.get('args'), 'instruction': instruction}
    path = unresolved_path(state_path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    return record


def archive_pending(state_path, pending, reason):
    """Record a request whose reply can no longer be replayed; reads are dropped."""
    if not isinstance(pending, dict) or pending.get('op') in REPEATABLE_OPS:
        return None
    return record_unresolved(state_path, pending, reason)


def read_unresolved(state_path, limit=20):
    path = unresolved_path(state_path)
    if not path.exists():
        return []
    records = []
    with path.open('rb') as stream:
        stream.seek(0, 2)
        end = stream.tell()
        stream.seek(max(0, end - 262144))
        for line in stream.read().splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records[-limit:]


def upload_wait_timeout(request, action, timeout=20):
    # Whole-file SHA-256 work is synchronous on the Vita. Commit/recovery may
    # hash the stage and destination; chunk deadlines remain short and fixed.
    if action == 'chunk':
        return timeout
    if request.get('skip_hash'):
        return max(timeout,60)
    passes = 3 if action in ('commit', 'recover') else 1
    return max(timeout, min(3600, 60 + passes * int(request['bytes']) / (1024 * 1024)))


def connection_setup_hint():
    return ('Check VITA_AGENT_CONFIG_DIR points to the intended directory containing config.json, '
            'and check device_dir (or explicit credentials/state paths) selects the intended pc/ identity. '
            'Different identity directories can contain different PC certificates; existing certificate files alone do not prove pairing. '
            'Reuse the intended paired identity. Run session pair and tap OK on the Vita once for a new identity. '
            'Keep existing identity files, credentials and recovery state; do not regenerate or delete them.')


def connection_refused_message(port=None):
    if port == 8847:
        return ('Nothing is accepting connections on the Vita pairing port 8847. Check the Vita is awake and on '
                'Wi-Fi, vita_ip in config.json is its current address, and the vita-agent-use plugin is loaded '
                '(diagnostics status shows whether it is running). '+connection_setup_hint())
    if port is None:
        return ('Vita connection was refused. Check the Vita is awake, vita_ip is its current address and the plugin '
                'is running. A session from this PC may still be active; session connect and serve reuse it. '
                +connection_setup_hint())
    return ('The Vita refused the command port: it has no live command session for this PC right now '
            '(it rebooted, the session expired, or it is switching sessions). The client renews it '
            'automatically from the saved pairing; if that keeps failing, check the Vita is awake and run '
            'session connect. '+connection_setup_hint())


APPEND_ONLY_LOGS = ('ur0:data/vita-agent-use/runtime.log', 'ur0:data/vita-agent-use/loader.log')


def screen_hold_path(state_path):
    return Path(state_path).with_name('screen-hold')


def set_screen_hold(state_path, held):
    """Record an explicit screen on, which automatic cleanup then leaves alone."""
    path = screen_hold_path(state_path)
    if held:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600))
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def screen_off_if_idle(client):
    """Leave the display on until applications and outstanding work are idle."""
    path=getattr(client,'path',None)
    if path is not None and screen_hold_path(path).exists():
        return False
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
                         'Rerun the identical command (with the same --transfer-state file, if you gave one) to resume; '
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


class FileReadRejected(ClientError):
    """A complete, valid refusal (missing file, policy); retrying will not help."""
    def __init__(self, message, status, code):
        super().__init__(message)
        self.status, self.code = status, code


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


def ensure_private(fd, path, kind='Credential/state file'):
    """Owned regular files that are merely too permissive are tightened, not rejected."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ClientError(kind + ' must be a regular file owned by this user: ' + str(path))
    if info.st_mode & 0o077:
        os.fchmod(fd, stat.S_IMODE(info.st_mode) & 0o700)
        print('vita-agent: tightened permissions of ' + str(path) + ' to owner-only.', file=sys.stderr)
    return os.fstat(fd)


def private_json(path, max_bytes=524288):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        ensure_private(stream.fileno(), path)
        data = stream.read(max_bytes+1)
        if len(data) > max_bytes:
            raise ClientError('Credential/state file exceeds its 512 KiB size limit.')
        return strict_json(data)


@contextmanager
def private_pem(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = ensure_private(fd, path, 'TLS identity file')
        if not 0 < info.st_size <= 16384:
            raise ClientError('TLS identity files must be at most 16 KiB: ' + str(path))
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
        self._lock_depth = 0
        self._lock_fd = None
        self.manage_screen = manage_screen
        if type(screen_off_when_done) is not bool:
            raise ClientError("screen_off_when_done must be a boolean.")
        self.screen_off_when_done = screen_off_when_done
        self._screen_owned = False
        self._screen_tried = False
        self._screen_cleanup_error = None
        self.retry_disconnect = retry_disconnect
        self._recovery_window = None
        # Optional callable(client, exc) that renews the session or reconnects.
        self.session_hook = None
        # Optional callable(dict) receiving recovered/unresolved notices.
        self.notice = None
        self.notices = []
        self._recovering = False
        self._host_override = host
        self._agent_name_override = agent_name
        if not 0 < timeout <= 60:
            raise ClientError('Timeout must be between zero and 60 seconds.')
        self.timeout = timeout
        self.response_timeout = max(timeout, RESPONSE_TIMEOUT) if retry_disconnect else timeout
        self._connection = None
        self._upload_chunk_bytes = None
        self.path = Path(state_path)
        # Optional saved credentials file, re-read if another process renews.
        self.credentials_path = None
        # Monotonic time until which a refused command port is waited for.
        self.command_ready_until = 0
        self.last_recovery_error = None
        self._extend_unsupported = False
        # Monotonic time of the last complete reply (the server's heartbeat clock).
        self.last_exchange = 0
        self._local = threading.local()
        self._load_credentials(credentials)

    @property
    def recovery_window(self):
        """Seconds one call keeps reconnecting/replaying; 0 makes one attempt."""
        if self._recovery_window is not None:
            return self._recovery_window
        return RECOVERY_WINDOW if self.retry_disconnect else 0

    @recovery_window.setter
    def recovery_window(self, seconds):
        self._recovery_window = seconds

    def _load_credentials(self, credentials):
        required = {'host', 'port', 'token', 'certificate_sha256', 'client_certificate', 'client_key'}
        if not required <= set(credentials) or set(credentials) - (required | {'agent_name', 'session_expires_at'}):
            raise ClientError('Invalid credential fields.')
        for field in ('client_certificate', 'client_key'):
            if not isinstance(credentials[field], str) or not Path(credentials[field]).is_absolute():
                raise ClientError('TLS identity file paths must be absolute.')
        agent_name = credentials.get('agent_name', 'Agent') if self._agent_name_override is None else self._agent_name_override
        validate_agent_name(agent_name)
        host = credentials['host'] if self._host_override is None else self._host_override
        validate_host(host)
        port = credentials['port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise ClientError('Invalid device port.')
        if any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
               for v in (credentials['token'], credentials['certificate_sha256'])):
            raise ClientError('Invalid pairing token or certificate fingerprint.')
        expires = credentials.get('session_expires_at')
        if expires is not None and (type(expires) not in (int,float) or not math.isfinite(expires) or expires <= 0):
            raise ClientError('Invalid session expiry timestamp.')
        self._credentials = dict(credentials)
        self.client_certificate = credentials['client_certificate']
        self.client_key = credentials['client_key']
        self.agent_name, self.host, self.port = agent_name, host, port
        self.token = credentials['token']
        self.pin = credentials['certificate_sha256']
        self.session_expires_at = expires
        self.session_deadline = None if expires is None else time.monotonic()+max(0,expires-time.time())
        self.identity = hashlib.sha256(json.dumps({k: v for k, v in credentials.items() if k not in ('agent_name', 'session_expires_at')}, sort_keys=True).encode()).hexdigest()

    def rebind(self, credentials):
        """Adopt renewed credentials in place; callers keep this same client."""
        with self._request_guard:
            self._close_transport()
            self._load_credentials(credentials)

    def extend_expiry(self, lifetime_s, started_at):
        self.session_expires_at = started_at + lifetime_s
        self.session_deadline = time.monotonic() + max(0, self.session_expires_at - time.time())
        self._credentials['session_expires_at'] = self.session_expires_at
        if self.credentials_path is not None:
            try:
                saved = private_json(self.credentials_path)
                if saved.get('token') == self.token:
                    saved['session_expires_at'] = self.session_expires_at
                    durable_json(Path(self.credentials_path), saved)
            except (OSError, ValueError, ClientError):
                pass

    def extend_session(self):
        """Keep the same token, replay cache and watches for another full lifetime."""
        if self._extend_unsupported:
            return False
        started = time.time()
        reply = self._call_raw('session.extend', {})
        result = reply.get('result') if reply.get('status') == 'ok' else None
        lifetime = result.get('lifetime_us') if isinstance(result, dict) else None
        if not isinstance(lifetime, str) or not re.fullmatch('[1-9][0-9]{0,12}', lifetime):
            # Older plugins: sessions are renewed through the saved pairing instead.
            self._extend_unsupported = True
            return False
        self.extend_expiry(int(lifetime) / 1e6, started)
        return True

    def session_expired(self, margin=0):
        return self.session_deadline is not None and time.monotonic() >= self.session_deadline - margin

    @contextmanager
    def recovery_limit(self, seconds):
        """Shorten this thread's recovery window (cleanup, heartbeats)."""
        previous = getattr(self._local, 'window', None)
        self._local.window = min(self._window(), seconds)
        try:
            yield
        finally:
            self._local.window = previous

    def _window(self):
        override = getattr(self._local, 'window', None)
        return self.recovery_window if override is None else override

    def _emit_notice(self, notice):
        self.notices.append(notice)
        if self.notice is not None:
            try:
                self.notice(notice)
            except Exception:
                pass

    @contextmanager
    def _locked_state(self):
        with self._state_lock():
            yield self._load_state()

    @contextmanager
    def _state_lock(self):
        # Threads in this harness share one connection; other processes wait
        # their turn instead of failing, since commands are short.
        with self._request_guard:
            if self._lock_depth:
                # Same thread already owns the cross-process lock.
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                return
            # Separate lock inode survives replacement of the durable state file.
            fd = os.open(str(self.path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                ensure_private(fd, str(self.path) + '.lock', 'State lock')
                deadline = time.monotonic() + LOCK_WAIT
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise ClientError('Another vita-agent process has held this session for %d s; '
                                              'it is still running a command. Wait for it or stop it.' % LOCK_WAIT) from None
                        time.sleep(0.05)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
            finally:
                os.close(fd)

    def _load_state(self):
        if self.path.exists():
            state = private_json(self.path)
            if isinstance(state, dict) and state.get('identity') != self.identity and self.credentials_path:
                # Another process renewed the session: adopt its saved token.
                try:
                    saved = private_json(self.credentials_path)
                    candidate = hashlib.sha256(json.dumps({k: v for k, v in saved.items() if k not in ('agent_name', 'session_expires_at')}, sort_keys=True).encode()).hexdigest()
                except (OSError, ValueError, ClientError):
                    candidate = None
                if candidate == state.get('identity'):
                    self._close_transport()
                    self._load_credentials(saved)
            if not isinstance(state, dict) or state.get('identity') != self.identity:
                raise ClientError('State belongs to different pairing credentials; do not reuse it.')
            if set(state) != {'identity', 'next_id', 'pending', 'last'} or type(state['next_id']) is not int or not 1 <= state['next_id'] <= 2**64:
                raise ClientError('Invalid session state.')
            if state['pending'] is not None and not isinstance(state['pending'], dict):
                raise ClientError('Invalid pending request state.')
            if state['last'] is not None and (not isinstance(state['last'], dict) or set(state['last']) != {'request', 'response'}):
                raise ClientError('Invalid recovery state.')
            return state
        return {'identity': self.identity, 'next_id': 1, 'pending': None, 'last': None}

    @staticmethod
    def _command(op, args):
        if op not in ('events.subscribe', 'run.begin', 'run.update', 'run.end', 'run.status', 'capabilities', 'system.snapshot', 'app.launch', 'app.close', 'app.install', 'app.install.status', 'decrypt.start', 'decrypt.status', 'screen.on', 'screen.off', 'system.reboot',
                      'input.acquire', 'input.heartbeat', 'input.cancel', 'input.release', 'input.status', 'input.submit', 'fs.stat', 'fs.list', 'touch.panels', 'app.list', 'fs.mkdir', 'fs.move', 'fs.trash', 'fs.purge', 'acl.request', 'acl.status', 'acl.audit', 'macro.acquire', 'plugins.list', 'performance.measure', 'performance.watch', 'performance.read', 'performance.cancel', 'app.running', 'events.start', 'events.read', 'events.stop', 'livearea.schema', 'log.start', 'log.read', 'log.stop', 'content.list', 'livearea.layout', 'livearea.blob', 'dialog.events.start', 'dialog.events.read', 'dialog.events.stop', 'macro.enqueue', 'content.delete.status', 'content.delete.changes', 'content.audit', 'content.delete.preview', 'content.scope', 'content.delete.request', 'content.albums', 'session.ping', 'session.extend'):
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
        elif op in ('decrypt.start', 'decrypt.status'):
            expected={'operation_id','path'} if op=='decrypt.start' else {'operation_id'}
            if set(args)!=expected or not isinstance(args['operation_id'],str) or not re.fullmatch('[0-9a-f]{32}',args['operation_id']):
                raise ClientError('Decryption requires a stable 32-digit operation_id.')
            if op=='decrypt.start':
                VitaClient._command('fs.stat',{'path':args['path']})
                if any(part in ('','.','..') for part in args['path'].split(':',1)[1].split('/')):
                    raise ClientError('Decryption requires a normalized Vita file path.')
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
        # Best effort: most commands work with the display off, and a refused
        # screen-on must not block the command itself.
        if self.manage_screen and not self._screen_owned and not self._screen_tried:
            self._screen_tried = True
            self._call_raw('screen.on', {})

    def close(self):
        """Finish the access session, then close transport. Reconnects use only transport cleanup."""
        had_error = sys.exc_info()[0] is not None
        try:
            if self._screen_owned and self.screen_off_when_done:
                # Cleanup must not hold the caller for a full recovery window.
                with self.recovery_limit(10):
                    screen_off_if_idle(self)
        except Exception as exc:
            self._screen_cleanup_error = exc
            if not had_error:
                raise
            # Preserve the original operation's exception, but expose cleanup failure.
            print('Vita screen cleanup failed: ' + str(exc), file=sys.stderr)
        finally:
            self._screen_owned = False
            self._screen_tried = False
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
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=max(self.timeout, CONNECT_TIMEOUT) if self.retry_disconnect else self.timeout, context=context)
        try:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), self.pin):
                raise PinMismatchError('Device certificate does not match the paired fingerprint; no token sent. '
                                       'Check vita_ip points at the paired Vita.')
            set_keepalive(connection.sock)
            connection.sock.settimeout(self.timeout)
        except ConnectionRefusedError as exc:
            connection.close()
            raise ConnectionRefusedError(connection_refused_message(self.port)) from exc
        except TimeoutError as exc:
            connection.close()
            raise TimeoutError('Vita connection timed out (%s:%d did not complete TCP/TLS setup). Check the Vita is awake '
                               'and on Wi-Fi and vita_ip is current. '%(self.host,self.port)+connection_setup_hint()) from exc
        except ssl.SSLError as exc:
            connection.close()
            raise ssl.SSLError(str(exc)+' '+connection_setup_hint()) from exc
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        return connection

    def _open(self):
        """Return a pinned connection or raise NotSentError (nothing was sent)."""
        connection = self._connection
        if connection is not None and connection.sock is not None:
            return connection
        self._close_transport()
        while True:
            try:
                return self._connect()
            except NotSentError:
                raise
            except ClientError as exc:
                raise NotSentError(str(exc)) from exc
            except ConnectionRefusedError as exc:
                # A fresh session's command listener starts just after its
                # token is issued; wait for it rather than renewing again.
                remaining = self.command_ready_until - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.5, remaining))
                    continue
                raise NotSentError(str(exc), refused=True) from exc
            except (OSError, http.client.HTTPException, ValueError) as exc:
                detail = str(exc) or type(exc).__name__
                if isinstance(exc, OSError) and not isinstance(exc, (TimeoutError, ssl.SSLError)):
                    detail += ' (check the Vita is awake and on the network, and vita_ip is current)'
                raise NotSentError('Could not connect to the Vita (%s: %s); nothing was sent.' % (type(exc).__name__, detail)) from exc

    def _send(self, connection, path, body, content_type):
        """Send one request; failure before the last byte means it never ran."""
        try:
            # Never let HTTPSConnection implicitly reconnect: every new socket
            # must pass the pin check before receiving the bearer credential.
            connection.request('POST', path, body=body, headers={
                'Content-Type': content_type, 'Authorization': 'Bearer ' + self.token,
                'Connection': 'keep-alive'})
        except (OSError, http.client.HTTPException) as exc:
            self._close_transport()
            # The Vita parses a request only once all of it arrived.
            raise NotSentError('Connection dropped before the request was fully sent (%s); nothing ran.' % (str(exc) or type(exc).__name__)) from exc

    def _receive(self, connection, wait=None):
        sock = connection.sock
        previous = None
        if wait is not None and hasattr(sock, 'settimeout') and not hasattr(connection, 'getresponse_wait'):
            previous = sock.gettimeout()
            sock.settimeout(wait)
        try:
            if hasattr(connection, 'getresponse_wait'):
                return connection.getresponse_wait(wait if wait is not None else self.response_timeout)
            return connection.getresponse()
        finally:
            if previous is not None and connection.sock is sock:
                sock.settimeout(previous)

    def _exchange(self, request):
        return self._exchange_once(request)

    def _exchange_once(self, request):
        payload = json.dumps(request, separators=(',', ':'), ensure_ascii=True).encode()
        if len(payload) > 131072:
            raise ClientError('Request exceeds device limit.')
        connection = self._open()
        self._send(connection, '/v1/command', payload, 'application/json')
        try:
            response = self._receive(connection, self.response_timeout)
            lengths = response.headers.get_all('Content-Length', [])
            if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                raise ClientError('Unsupported response framing.')
            if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 4096:
                raise ClientError('Invalid response length.')
            size = int(lengths[0])
            data = response.read(size + 1)
            if len(data) != size:
                raise ClientError('Truncated or oversized response.')
            if response.will_close:
                self._close_transport()
            if response.status == 401:
                self._close_transport()
                raise GrantExpiredError('The Vita session token expired or was revoked; the command did not run.')
            if response.status == 503:
                raise ServiceBusyError('The Vita was not ready to run commands yet (input monitor still starting); nothing ran.')
            if response.status != 200:
                rejected = NotExecutedError('Device rejected the HTTP request (status %d); nothing ran.' % response.status)
                rejected.retryable = False
                raise rejected
            if response.headers.get('Content-Type', '').lower() != 'application/json':
                raise ClientError('Unexpected response content type.')
            result = strict_json(data)
            if isinstance(result, dict) and result.get('v') == 1 and result.get('id') is None and result.get('status') == 'error':
                # Rejected before the ID was reserved: unknown operation on an
                # older plugin, or the protocol workspace was momentarily busy.
                code = result.get('error', {}).get('code') if isinstance(result.get('error'), dict) else None
                raise CommandRejected('The Vita rejected %s before running it: %s' % (request['op'], json.dumps(result.get('error'))),
                                      result, retryable=code == -2)
            if not isinstance(result, dict) or type(result.get('v')) is not int or result.get('v') != 1 or result.get('id') != request['id'] or result.get('status') not in ('ok', 'accepted', 'error'):
                raise ClientError('Response does not match the pending command.')
            self.last_exchange = time.monotonic()
            return result
        except NotExecutedError:
            raise
        except (OSError, http.client.HTTPException, ValueError, RecursionError, ClientError) as exc:
            self.last_transport_error = type(exc).__name__
            self._close_transport()
            detail=str(exc) or type(exc).__name__
            raise UncertainError('Sent %s (id %s) but no complete reply arrived (%s: %s); it stays pending and is '
                                 'replayed with the same ID, which cannot run it twice.' % (request['op'], request['id'], type(exc).__name__, detail)) from exc
        except BaseException:
            self._close_transport()
            raise

    def _read_retry(self, fn):
        """Retry an ID-less read (frame, file, audit) across reconnects."""
        return self._retrying(fn, ())

    def _retrying(self, attempt, uncertain=(UncertainError,)):
        """Run attempt until it succeeds or the trouble outlasts the recovery window.

        The window counts from the first failure, so a long but healthy wait
        does not eat into it. Only failures that leave nothing half-done, or
        whose exact request is replayed by ID, are retried."""
        failing_since = None
        delay = 0.5
        self.last_recovery_error = None
        while True:
            try:
                return attempt()
            except (NotExecutedError,) + tuple(uncertain) as exc:
                if isinstance(exc, NotExecutedError) and not exc.retryable:
                    raise
                now = time.monotonic()
                window = self._window()
                failing_since = now if failing_since is None else failing_since
                if self._recovering or now - failing_since >= window:
                    raise self._final(exc, window)
                self._recover(exc)
                remaining = window - (time.monotonic() - failing_since)
            time.sleep(max(0, min(delay, remaining)))
            delay = min(delay * 2, 5)

    def _final(self, exc, window=None):
        """Name what recovery tried before the caller sees the failure."""
        window = self._window() if window is None else window
        if window and not self._recovering and not getattr(exc, '_reported', False):
            extra = ' Kept retrying for %d s.' % window
            if self.last_recovery_error:
                extra += ' Last session renewal attempt: ' + self.last_recovery_error
            exc.args = ((str(exc) + extra),) + exc.args[1:]
            exc._reported = True
        return exc

    def connection_lost(self):
        """Give a Vita reopening its listener time before renewing the session."""
        self.command_ready_until = max(self.command_ready_until, time.monotonic() + LISTENER_RESET_WAIT)

    def _recover(self, exc):
        """Prepare the next attempt: reconnect, or renew via the session hook."""
        self._close_transport()
        if isinstance(exc, UncertainError) or (isinstance(exc, NotSentError) and not exc.refused):
            self.connection_lost()
        if self.session_hook is None:
            return
        self._recovering = True
        try:
            self.session_hook(self, exc)
            self.last_recovery_error = None
        except Exception as hook_error:
            # Keep trying until the window ends; report the latest cause.
            self.last_recovery_error = str(hook_error) or type(hook_error).__name__
        finally:
            self._recovering = False

    def frame(self):
        """Return (JPEG bytes, metadata) without consuming a command sequence ID."""
        self._ensure_screen()
        # Right after display-on the compositor may not have a frame yet.
        deadline = time.monotonic() + 3
        while True:
            try:
                return self._read_retry(self._frame_once)
            except NativeFrameError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    def _frame_once(self):
        with self._locked_state():
            connection = self._open()
            self._send(connection, '/v1/frame', b'{}', 'application/json')
            try:
                response = self._receive(connection)
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported frame response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 2187264:
                    raise ClientError('Invalid frame length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated frame response.')
                if response.will_close:
                    self._close_transport()
                if response.status == 401:
                    raise GrantExpiredError('The Vita session token expired or was revoked.')
                if response.status == 503:
                    raise ServiceBusyError('The Vita was not ready to capture yet.')
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
                self.last_exchange = time.monotonic()
                return data, metadata
            except (NativeFrameError, NotExecutedError):
                # The full, validated error response has been consumed. A
                # missing framebuffer does not invalidate the event channel.
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self._close_transport()
                # Captures have no effect, so a lost one is simply taken again.
                raise NotExecutedError('Frame transport failed (%s); capturing again.' % (str(exc) or type(exc).__name__)) from None
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
        return self._read_retry(lambda: self._file_chunk_once(payload, offset, length))

    def _file_chunk_once(self, payload, offset, length):
        with self._locked_state():
            connection = self._open()
            self._send(connection, '/v1/file/read', payload, 'application/json')
            try:
                response = self._receive(connection)
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported file response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 <= int(lengths[0]) <= 16384:
                    raise ClientError('Invalid file response length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated file response.')
                if response.will_close:
                    self._close_transport()
                if response.status == 401:
                    raise GrantExpiredError('The Vita session token expired or was revoked.')
                if response.status == 503:
                    raise ServiceBusyError('The Vita was not ready to read files yet.')
                if response.status != 200:
                    try:
                        detail = strict_json(data)
                    except (ValueError, UnicodeError):
                        detail = None
                    code = detail.get('code') if isinstance(detail, dict) else None
                    if response.status == 403:
                        reason = 'denied by file policy. ' + path_reason(json.loads(payload)['path'], write=False)
                    elif type(code) is int and code & 0xffffffff == 0x80010002:
                        reason = 'failed: no such file on the Vita.'
                    else:
                        reason = {500: 'failed: the path does not exist or could not be read.'}.get(response.status, 'rejected.')
                    shown = '0x%08X' % (code & 0xffffffff) if type(code) is int and code < -9 else code
                    raise FileReadRejected('File read %s (HTTP %d, native code %s)' % (reason, response.status, shown), response.status, code)
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
                # The plugin sends this header unpadded; match every other Vita timestamp.
                parts = [int(p) for p in re.split('[-T:.]', modified[0])]
                metadata['modified'] = '%04d-%02d-%02dT%02d:%02d:%02d.%06d' % tuple(parts)
                if metadata['offset'] != offset or offset > metadata['file_bytes'] or len(data) != min(length, metadata['file_bytes'] - offset):
                    raise ClientError('File response does not match the requested range.')
                self.last_exchange = time.monotonic()
                return data, metadata
            except (NotExecutedError, FileReadRejected):
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self.last_transport_error = type(exc).__name__
                self._close_transport()
                raise NotExecutedError('File transport failed (%s); reading this range again.' % (str(exc) or type(exc).__name__)) from exc
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

    def upload_skip_hash_supported(self):
        reply=self.call('capabilities')
        if reply.get('status')!='ok':raise ClientError('Cannot query upload capabilities.')
        return reply.get('result',{}).get('upload',{}).get('skip_hash') is True

    def upload_step(self, request, action, offset=0, data=b'', *, progress=None):
        """One sequential upload step; workflow must persist request first."""
        fields = {'operation_id', 'path', 'bytes', 'sha256', 'expected_sha256', 'overwrite', 'yes'}
        actions = ('begin', 'chunk', 'verify', 'commit', 'recover')
        if not isinstance(request, dict) or set(request) not in (fields,fields|{'skip_hash'}) or action not in actions:
            raise ClientError('Invalid upload metadata.')
        skip_hash=request.get('skip_hash',False)
        if type(skip_hash) is not bool:raise ClientError('Invalid skip_hash flag.')
        self._command('fs.mkdir', {key: request[key] for key in ('operation_id', 'path', 'yes')})
        if type(request['overwrite']) is not bool or not isinstance(request['bytes'], str) or not re.fullmatch('0|[1-9][0-9]{0,18}', request['bytes']) or int(request['bytes']) > 2**63-1:
            raise ClientError('Invalid upload size or overwrite flag.')
        if not isinstance(request['sha256'], str) or not re.fullmatch('' if skip_hash else '[0-9a-f]{64}', request['sha256']) or not isinstance(request['expected_sha256'], str) or not re.fullmatch('(?:[0-9a-f]{64})?' if request['overwrite'] and not skip_hash else '', request['expected_sha256']):
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
        # An earlier command's lost reply is settled first, never left blocking.
        self.settle_pending()
        # Native staging compares overlapping chunks and commit/recover look up
        # this operation's journal, so the same step is safe to send again.
        try:
            return self._retrying(lambda: self._upload_once(request, action, payload, progress), (UploadTransportError,))
        except NotExecutedError as exc:
            raise UploadTransportError(str(exc)) from exc

    def _upload_once(self, request, action, payload, progress):
        actions = ('begin', 'chunk', 'verify', 'commit', 'recover')
        with self._locked_state():
            connection = self._open()
            self._send(connection, '/v1/file/upload', payload, 'application/octet-stream')
            wait_sock = None
            try:
                wait_timeout = upload_wait_timeout(request, action, self.timeout)
                if hasattr(connection, 'getresponse_wait'):
                    response = connection.getresponse_wait(wait_timeout, progress)
                else:
                    wait_sock = connection.sock
                    previous_timeout = wait_sock.gettimeout()
                    wait_sock.settimeout(wait_timeout)
                    response = connection.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported upload response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 2048:
                    raise ClientError('Invalid upload response length.')
                raw = response.read(int(lengths[0]) + 1)
                if len(raw) != int(lengths[0]):
                    raise ClientError('Truncated upload response.')
                if response.will_close:
                    self._close_transport()
                if response.status == 401:
                    raise GrantExpiredError('Upload session expired or was revoked; the step did not run.')
                if response.status == 503:
                    raise ServiceBusyError('The Vita was not ready for the upload step yet; it did not run.')
                if response.status != 200 or response.headers.get('Content-Type', '').lower() != 'application/json':
                    raise ClientError('Upload response rejected (HTTP %d).' % response.status)
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
                self.last_exchange = time.monotonic()
                return result
            except NotExecutedError:
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self._close_transport()
                raise UploadTransportError('Upload transport failed (%s: %s); the same step is sent again from the saved transfer state.' % (type(exc).__name__,str(exc) or type(exc).__name__)) from exc
            except BaseException:
                self._close_transport()
                raise
            finally:
                if wait_sock is not None and connection.sock is wait_sock:
                    wait_sock.settimeout(previous_timeout)

    def audit_page(self, after=0):
        """Read bounded journal events without changing the device journal."""
        if type(after) is not int or not 0 <= after <= 2**63-1:
            raise ClientError('Invalid audit cursor.')
        payload = json.dumps({'after': str(after)}, separators=(',', ':')).encode()
        self._ensure_screen()
        return self._read_retry(lambda: self._audit_once(payload))

    def _audit_once(self, payload):
        with self._locked_state():
            connection = self._open()
            self._send(connection, '/v1/audit', payload, 'application/json')
            try:
                response = self._receive(connection)
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding'):
                    raise ClientError('Unsupported audit response framing.')
                if len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]) or not 0 < int(lengths[0]) <= 16384:
                    raise ClientError('Invalid audit response length.')
                data = response.read(int(lengths[0]) + 1)
                if len(data) != int(lengths[0]):
                    raise ClientError('Truncated audit response.')
                if response.will_close:
                    self._close_transport()
                if response.status == 401:
                    raise GrantExpiredError('The Vita session token expired or was revoked.')
                if response.status == 503:
                    raise ServiceBusyError('The Vita was not ready yet.')
                if response.status != 200:
                    raise ClientError('Audit export rejected (HTTP %d).' % response.status)
                if response.headers.get('Content-Type', '').lower() != 'application/json':
                    raise ClientError('Unexpected audit content type.')
                return strict_json(data)
            except NotExecutedError:
                raise
            except (OSError, http.client.HTTPException, ValueError):
                self._close_transport()
                raise NotExecutedError('Audit transport failed; saved cursor is unchanged, reading again.') from None
            except BaseException:
                self._close_transport()
                raise

    def download(self, path, output, progress=None):
        """Stream to a new private host file; remove incomplete output on failure.
        A file that changes mid-download is fetched again from the start, up to
        three times. The plugin's own logs only ever grow, and grow while being
        read, so they are read up to the size they had when the download began."""
        self._command('fs.stat', {'path': path})
        growing = path.lower() in APPEND_ONLY_LOGS
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        reported = 0.0
        try:
            with os.fdopen(fd, 'wb') as stream:
                for attempt in range(3):
                    stream.seek(0)
                    stream.truncate()
                    offset, revision, size, changed = 0, None, None, False
                    while True:
                        data, metadata = self.file_chunk(path, offset)
                        current = (metadata['file_bytes'], metadata['modified'])
                        size = current[0] if size is None else size
                        if revision is not None and current != revision and not (growing and current[0] >= size):
                            changed = True
                            break
                        revision = current
                        data = data[:size - offset]
                        stream.write(data)
                        offset += len(data)
                        if progress is not None and (time.monotonic()-reported>=1 or offset==size):
                            progress({'status':'progress','result':{'phase':'download','received':str(offset),'bytes':str(size)}})
                            reported=time.monotonic()
                        if offset == size:
                            break
                    if not changed:
                        break
                else:
                    raise ClientError('File kept changing during download (3 tries). Something on the Vita is still writing it; '
                                      'wait for that to finish or close the app writing it, then download again.')
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
        if request['op'] not in QUIET_OPS:
            state['last'] = {'request': request, 'response': result}
        state['pending'] = None
        durable_json(self.path, state)
        return result

    def _abandon(self, state, reason):
        """Retire a pending request whose session is gone; record it first."""
        pending = state['pending']
        record = archive_pending(self.path, pending, reason)
        state['pending'] = None
        durable_json(self.path, state)
        if record is not None:
            self._emit_notice({'type': 'command.unresolved', **record})
        return record

    def _settle(self, state, notify=True):
        """Replay an earlier command's pending request under its own ID."""
        pending = state['pending']
        try:
            reply = self._finish(state)
        except GrantExpiredError:
            # The session that may have run it is gone; its reply cannot be
            # replayed and resending under a new session could repeat it.
            self._abandon(state, 'session_lost')
            raise
        except NotExecutedError as exc:
            if exc.retryable:
                raise
            self._abandon(state, 'replay_rejected: ' + str(exc))
            return None
        if notify and pending['op'] not in QUIET_OPS:
            self._emit_notice({'type': 'command.recovered', 'id': pending['id'], 'op': pending['op'],
                               'args': pending['args'], 'reply': json.loads(json.dumps(reply))})
        self._track_screen_reply(pending['op'], reply)
        return reply

    def _lost(self, pending, record):
        if record is None:
            record = next((r for r in reversed(read_unresolved(self.path, 50))
                           if r.get('id') == pending.get('id') and r.get('op') == pending.get('op')), None)
        if record is None:
            record = {'id': pending.get('id'), 'op': pending.get('op'), 'args': pending.get('args'),
                      'reason': 'session_lost', 'instruction': 'Outcome unknown: check the resulting Vita state before repeating it.'}
        return UncertainOutcomeError(
            '%s (id %s) was sent, but its reply was lost and the Vita session it ran under ended, so its '
            'outcome cannot be recovered. It is recorded in %s and was not resent. %s'
            % (pending.get('op'), pending.get('id'), unresolved_path(self.path), record.get('instruction', '')), record)

    def _attempt(self, command, ctx):
        with self._locked_state() as state:
            sent = ctx.get('sent')
            if sent is not None:
                identity, request = sent
                pending = state['pending']
                if identity != self.identity or pending is None or pending.get('id') != request['id']:
                    # No longer pending under the session it was sent in.
                    last = state['last']
                    if identity == self.identity and last is not None and last['request'].get('id') == request['id']:
                        return last['response']
                    ctx['sent'] = None
                    if command['op'] not in RESENDABLE_OPS:
                        raise self._lost(request, None)
            pending = state['pending']
            if pending is not None and any(pending.get(k) != v for k, v in command.items()):
                self._settle(state)
            if state['pending'] is not None:
                # This same command was sent before without a reply.
                pending = state['pending']
                ctx['sent'] = (self.identity, pending)
                try:
                    return self._finish(state)
                except NotExecutedError as exc:
                    if exc.retryable and not isinstance(exc, GrantExpiredError):
                        raise
                    lost = exc
                ctx['sent'] = None
                if command['op'] in RESENDABLE_OPS:
                    # Safe to ask again under the renewed session.
                    state['pending'] = None
                    durable_json(self.path, state)
                    raise lost
                raise self._lost(pending, self._abandon(state, 'session_lost'))
            if state['next_id'] == 2**64:
                raise ClientError('Session request IDs are exhausted.')
            state['pending'] = {'v': 1, 'id': str(state['next_id']), **command}
            state['next_id'] += 1
            # Persist the exact command before any possible remote effect.
            durable_json(self.path, state)
            ctx['sent'] = (self.identity, state['pending'])
            try:
                return self._finish(state)
            except NotExecutedError:
                # It certainly did not run: forget it so nothing replays it later.
                ctx['sent'] = None
                state['pending'] = None
                durable_json(self.path, state)
                raise

    def settle_pending(self, notify=True):
        """Resolve any pending request now: its reply, or an unresolved record."""
        def attempt():
            with self._locked_state() as state:
                if state['pending'] is None:
                    return None
                return self._settle(state, notify)
        try:
            return self._retrying(attempt)
        except GrantExpiredError:
            # Archived by _settle; the caller's own request renews the session.
            return None

    def _maybe_extend(self):
        """Extend before expiry, so commands never straddle a token change."""
        if self._extend_unsupported or self.session_deadline is None or not self.session_expired(600):
            return
        try:
            self.extend_session()
        except ClientError:
            pass

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
        if op not in ('screen.on', 'screen.off') and op not in QUIET_OPS:
            self._ensure_screen()
        if op not in QUIET_OPS and not self._recovering:
            self._maybe_extend()
        ctx = {}
        try:
            result = self._retrying(lambda: self._attempt(command, ctx))
        except CommandRejected as exc:
            # A complete native rejection is an ordinary error reply.
            result = exc.reply
        if op in ('app.install','app.install.status') and result.get('status')=='ok':
            operation_id=command['args'].get('operation_id')
            installs=getattr(self,'_screen_installs',set())
            if result.get('result',{}).get('running') is False:
                installs.discard(operation_id)
            else:
                installs.add(operation_id)
            self._screen_installs=installs
        self._track_screen_reply(op,result)
        return annotate(op,args,result)

    def _track_screen_reply(self,op,result):
        if result.get('status')!='accepted':
            return
        if op=='screen.on' and self.manage_screen:
            self._screen_owned=True
        elif op in ('screen.off','system.reboot'):
            # Reboot's terminal response closes command access too.
            self._screen_owned=False

    def recover(self):
        """Return the pending command's reply, or the last one if none is pending."""
        with self._locked_state() as state:
            pending = state['pending']
        if pending is not None:
            reply = self.settle_pending(notify=False)
            if reply is not None:
                return reply
            record = next((n for n in reversed(self.notices) if n.get('type') == 'command.unresolved' and n.get('id') == pending.get('id')), None)
            if record is None:
                return {'status': 'ok', 'result': {'pending': None, 'recovered': None,
                                                    'message': 'The pending %s could not be replayed and needs no recovery.' % pending.get('op')}}
            return {'status': 'unconfirmed', 'message': 'The pending command could not be replayed; its outcome is unknown.',
                    'unresolved': record}
        with self._locked_state() as state:
            if state['last'] is not None:
                return state['last']['response']
        unresolved = read_unresolved(self.path, 5)
        result = {'pending': None, 'message': 'Nothing is pending; no recovery needed.'}
        if unresolved:
            result['unresolved_recent'] = unresolved
        return {'status': 'ok', 'result': result}


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
