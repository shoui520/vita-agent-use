# SPDX-License-Identifier: GPL-3.0-or-later
"""Persistent local command server and receiver for native Vita push events.

The paired TLS channel carries both RPC replies and unsolicited event frames.
The local Unix socket is independent of stdin and remains available during runs.
"""
from __future__ import annotations
import contextlib
import copy
import hashlib
import http.client
import io
import json
import math
import os
from pathlib import Path
import queue
import socket
import socketserver
import sys
import threading
import time
import uuid
from vita_client import ClientError, NativeFrameError, VitaClient, durable_json, private_json, strict_json

MAX_IPC = 1024 * 1024
MAX_FRAME = 2 * 1024 * 1024
TERMINAL = {'completed', 'cancelled', 'failed', 'connection_lost'}
# Explicit observations and idempotent transport setup only. Never infer safety
# from a method's spelling, and never replay writes/input/app control here.
RETRYABLE_OPS = frozenset({
    'capabilities', 'system.snapshot', 'app.running', 'app.list', 'fs.stat',
    'fs.list', 'plugins.list', 'touch.panels', 'livearea.schema', 'livearea.layout',
    'performance.read', 'events.read', 'dialog.events.read', 'input.status',
    'run.status', 'acl.status', 'acl.audit', 'content.list', 'content.scope',
    'content.albums', 'content.audit', 'content.delete.status',
    'content.delete.changes', 'livearea.blob', 'app.install.status',
    'screen.on', 'screen.off',
    'events.subscribe',
})


def checked(reply):
    if reply.get('status') not in ('ok', 'accepted'):
        raise ClientError('Vita rejected operation: ' + json.dumps(reply, ensure_ascii=False))
    return reply.get('result', {})


class ReceivedResponse:
    def __init__(self, response, data):
        self.status, self.headers, self.will_close = response.status, response.headers, response.will_close
        self.body = io.BytesIO(data)
    def read(self, size=-1):return self.body.read(size)
    def getheader(self, name, default=None):return self.headers.get(name, default)


class _SharedReader:
    def __init__(self,stream):self.stream=stream
    def makefile(self,*args,**kwargs):return self
    def close(self):pass
    def read(self,*args):return self.stream.read(*args)
    def readline(self,*args):return self.stream.readline(*args)
    def readinto(self,*args):return self.stream.readinto(*args)


class PushTransport:
    """One continuous reader; command callers receive only their RPC responses.

    HTTP event frames are unsolicited, complete, length-delimited messages. They
    never interrupt JPEG/file bodies. No event read RPC or host polling loop.
    """
    def __init__(self, connection, emit, disconnected):
        self.connection, self.sock = connection, connection.sock
        self.timeout = connection.timeout
        self.emit, self.disconnected = emit, disconnected
        self.responses = queue.Queue(maxsize=2)
        self.stopping = threading.Event()
        self.sock.settimeout(None)
        self.stream=self.sock.makefile("rb")
        self.response_socket=_SharedReader(self.stream)
        self.reader = threading.Thread(target=self._read, name='vita-push-receiver', daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while not self.stopping.is_set():
                response = http.client.HTTPResponse(self.response_socket)
                response.begin()
                lengths = response.headers.get_all('Content-Length', [])
                if response.headers.get_all('Transfer-Encoding') or response.headers.get_all('Content-Encoding') or len(lengths)!=1 or not lengths[0].isdigit() or not 0 <= int(lengths[0]) <= MAX_FRAME:
                    raise ClientError('Invalid pushed frame length or encoding.')
                size=int(lengths[0]);data=response.read(size+1)
                if len(data)!=size:raise ClientError('Incomplete pushed frame.')
                event=response.getheader('X-Vita-Event')
                if event:
                    if response.status!=200 or response.getheader('Content-Type')!='application/json':raise ClientError('Invalid event frame.')
                    self.emit({'type':event, 'run_id':response.getheader('X-Vita-Run') or None, 'result':strict_json(data)})
                else:
                    self.responses.put_nowait(ReceivedResponse(response,data))
                if response.will_close:raise ClientError('Vita closed the protected connection.')
        except Exception as exc:
            if not self.stopping.is_set():
                self.disconnected(str(exc))
                with contextlib.suppress(queue.Full):self.responses.put_nowait(exc)
            self.sock=None

    def request(self, method, url, body=None, headers=None):
        if self.sock is None:raise OSError('Vita event channel disconnected.')
        self.connection.request(method,url,body=body,headers=headers or {})
        # The continuous receiver owns HTTPResponse parsing, so HTTPConnection
        # must be ready for the next serialized request after its bytes are sent.
        self.connection._HTTPConnection__state=http.client._CS_IDLE

    def getresponse(self):
        try:result=self.responses.get(timeout=self.timeout)
        except queue.Empty:raise TimeoutError('Vita response timed out.') from None
        if isinstance(result,Exception):raise OSError('Vita connection lost: '+str(result)) from result
        return result

    def close(self):
        self.stopping.set()
        sock=self.connection.sock
        if sock is not None:
            with contextlib.suppress(OSError):sock.shutdown(socket.SHUT_RDWR)
        self.connection.close();self.sock=None
        if self.reader is not threading.current_thread():self.reader.join(timeout=2)
        self.stream.close()


class ServerClient(VitaClient):
    def __init__(self,*args,event_sink,disconnect_sink,**kwargs):
        super().__init__(*args,**kwargs)
        self.event_sink,self.disconnect_sink=event_sink,disconnect_sink
        self.command_ready_until=0
    def _close_transport(self):
        had_connection=self._connection is not None
        super()._close_transport()
        if had_connection:self.disconnect_sink('Protected transport closed; pending effects retain their recovery state.')
    def _connect(self):
        # Saved-session acknowledgement precedes command-listener startup.
        # Only refused TCP connections can be retried here: no command has
        # been sent, and a TLS timeout is a separate failure to diagnose.
        while True:
            try:
                connection=super()._connect()
                break
            except ConnectionRefusedError:
                remaining=self.command_ready_until-time.monotonic()
                if remaining<=0:raise
                time.sleep(min(1,remaining))
        self.command_ready_until=0
        self._connection=PushTransport(connection,self.event_sink,self.disconnect_sink)
        return self._connection


class EventStore:
    def __init__(self, root, retained=4096):
        self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.retained=retained;self.condition=threading.Condition();self.events=[];self.sequence=0
        self.path=self.root/'events.jsonl'
        # Continue the durable sequence without loading an unbounded event log.
        if self.path.exists():
            with self.path.open('rb') as stream:
                stream.seek(0,2);end=stream.tell();stream.seek(max(0,end-MAX_IPC))
                lines=stream.read().splitlines()
                if lines:self.sequence=int(strict_json(lines[-1])['sequence'])
    def append(self,event):
        with self.condition:
            self.sequence+=1
            record={**event,'sequence':self.sequence,'received_at':time.strftime('%Y-%m-%dT%H:%M:%S',time.gmtime())+'Z'}
            fd=os.open(self.path,os.O_APPEND|os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'a',encoding='utf-8') as stream:stream.write(json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n')
            self.events.append(record)
            if len(self.events)>self.retained:del self.events[:len(self.events)-self.retained]
            self.condition.notify_all()
            return record
    def read(self, after=0, timeout=0, limit=256):
        if type(after)is not int or after<0 or type(limit)is not int or not 1<=limit<=1024 or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or not 0<=timeout<=60:raise ClientError('Invalid event cursor, limit or wait.')
        deadline=time.monotonic()+timeout
        with self.condition:
            while self.sequence<=after and time.monotonic()<deadline:self.condition.wait(deadline-time.monotonic())
            if after>self.sequence:raise ClientError('Event cursor is ahead of server history.')
            events=[e for e in self.events if e['sequence']>after][:limit]
            oldest=self.events[0]['sequence'] if self.events else self.sequence+1
            return {'events':events,'next':events[-1]['sequence'] if events else self.sequence,'latest':self.sequence,'lost':max(0,oldest-after-1),'journal':str(self.path)}


class RunCoordinator:
    def __init__(self, server):
        self.server=server;self.guard=threading.RLock();self.active=None;self.thread=None
        self.cancel_event=threading.Event();self.completion=threading.Event();self.dump_complete=threading.Event();self.failure=None;self.watch_id=None
        self.path=server.root/'run.json'
        if self.path.exists():
            self.active=private_json(self.path)
            if self.active['phase'] not in TERMINAL:
                self.active['phase']='connection_lost';self.active['error']='PC server restarted during run; effects were not replayed.'
                durable_json(self.path,self.active)
    def status(self):
        with self.guard:return copy.deepcopy(self.active)
    def busy(self):
        with self.guard:return self.active is not None and (self.active['phase'] not in TERMINAL or self.active.get('coredump',{}).get('state')=='saving')
    @staticmethod
    def validate(spec):
        if not isinstance(spec,dict) or set(spec)-{'title_id','prepare','completion','timeout_s','performance_interval_ms','close_on_completion','yes'}:raise ClientError('Unknown run field.')
        VitaClient._command('app.launch',{'title_id':spec.get('title_id')})
        timeout=spec.get('timeout_s',120)
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or not 1<=timeout<=3600:raise ClientError('Run timeout must be 1..3600 seconds.')
        if type(spec.get('close_on_completion',True))is not bool or type(spec.get('yes',False))is not bool:raise ClientError('Run flags must be booleans.')
        interval=spec.get('performance_interval_ms')
        if interval is not None and (type(interval)is not int or not 100<=interval<=min(60000,timeout*1000)):raise ClientError('Performance interval must be 100..60000ms and fit within the timeout.')
        completion=spec.get('completion')
        if 'completion' in spec:
            if not isinstance(completion,dict) or set(completion)!={'log'} or not isinstance(completion['log'],dict) or set(completion['log'])!={'path','literal'}:raise ClientError('Completion requires log.path and log.literal.')
            VitaClient._command('log.start',{'path':completion['log']['path'],'marker':completion['log']['literal']})
        prepare=spec.get('prepare',{})
        if not isinstance(prepare,dict) or len(prepare)>1 or set(prepare)-{'upload','install'}:raise ClientError('Prepare supports one upload or install.')
        if prepare:
            kind,value=next(iter(prepare.items()))
            if not isinstance(value,dict):raise ClientError('Invalid prepare object.')
            fields={'source','destination','overwrite'} if kind=='upload' else {'source'}
            if set(value)-fields or not value.get('source'):raise ClientError('Invalid prepare fields.')
            source=Path(value['source']).expanduser().resolve()
            if not source.is_file():raise ClientError('Prepare source does not exist.')
            if kind=='upload':
                VitaClient._command('fs.stat',{'path':value.get('destination')})
                if type(value.get('overwrite',False))is not bool:raise ClientError('overwrite must be a boolean.')
            if (kind=='install' or value.get('overwrite')) and not spec.get('yes'):raise ClientError('Installation/overwrite requires run start --yes.')
        return copy.deepcopy(spec)
    def start(self,spec):
        spec=self.validate(spec)
        with self.guard:
            if self.busy():raise ClientError('Another run is in progress.')
            if not self.server.connected:raise ClientError('Vita event connection is unavailable.')
            self.active={'run_id':uuid.uuid4().hex,'title_id':spec['title_id'],'phase':'preparing','spec':spec,'started_at':time.time(),'error':None}
            self.cancel_event.clear();self.completion.clear();self.dump_complete.clear();self.failure=None;self.watch_id=None
            durable_json(self.path,self.active)
            self.thread=threading.Thread(target=self._worker,name='vita-run',daemon=True);self.thread.start()
            return self.status()
    def cancel(self):
        with self.guard:
            if not self.busy():raise ClientError('No active run.')
            self.cancel_event.set();self.completion.set();return self.status()
    def on_event(self,event):
        with self.guard:
            if not self.busy():return
            if event.get('type')=='connection.lost':self.failure='connection_lost';self.completion.set()
            elif event['type'] in ('coredump.saving','coredump.complete') and int(event.get('observed_us','0'))>=int(self.active.get('native_started_us') or '0'):
                pending=self.active.get('coredump')
                matching=pending and event.get('path')==pending['path'].removesuffix('.tmp')
                if event.get('run_id')!=self.active['run_id'] and not matching:return
                if pending and event['type']=='coredump.complete' and not matching:return
                if pending and event['type']=='coredump.saving':return
                self.failure='coredump'
                self.active['coredump']={'state':'saving' if event['type']=='coredump.saving' else 'complete','path':event['path'],'observed_us':event['observed_us']}
                if event['type']=='coredump.saving':self.active['phase']='coredump_saving'
                else:self.dump_complete.set()
                durable_json(self.path,self.active);self.completion.set()
            elif event.get('run_id')==self.active['run_id'] and event['type']=='log.marker' and event.get('watch_id')==self.watch_id:self.completion.set()
    def _phase(self,phase):
        with self.guard:
            self.active['phase']=phase;durable_json(self.path,self.active)
            self.server.event({'type':'run.phase','run_id':self.active['run_id'],'phase':phase})
        checked(self.server.client.call('run.update',{'run_id':self.active['run_id'],'phase':phase}))
    def _check(self):
        if self.cancel_event.is_set():raise InterruptedError('Run cancelled.')
        if self.failure:raise ClientError(self.failure)
    def _close_app(self,title):
        def running():
            return any(e['title_id']==title for e in checked(self.server.client.call('app.running'))['entries'])
        reply=self.server.client.call('app.close',{'title_id':title})
        checked(reply)
        deadline=time.monotonic()+20
        while running():
            if time.monotonic()>=deadline:raise ClientError('Application close was not confirmed.')
            time.sleep(.25)
    def _worker(self):
        c=self.server.client;run=self.status();spec=run['spec'];phase='failed';error=None;begun=False;perf=False;launched=False
        try:
            checked(c.call('screen.on'))
            beginning=checked(c.call('run.begin',{'run_id':run['run_id'],'title_id':run['title_id']}));begun=True
            with self.guard:self.active['native_started_us']=beginning.get('started_us')
            if spec.get('performance_interval_ms'):
                checked(c.call('performance.watch',{'duration_s':math.ceil(spec.get('timeout_s',120)),'interval_ms':spec['performance_interval_ms']}));perf=True
            for entry in checked(c.call('app.running'))['entries']:
                self._check();self._close_app(entry['title_id'])
            self._check()
            prepare=spec.get('prepare',{})
            if prepare:
                from upload import upload
                kind,value=next(iter(prepare.items()));source=Path(value['source']).expanduser().resolve()
                destination=value['destination'] if kind=='upload' else 'ux0:data/vita-agent-install-'+run['run_id']+'.vpk'
                coordinator=self
                class UploadGate:
                    def __getattr__(self,name):return getattr(c,name)
                    def upload_step(self,*args,**kwargs):
                        coordinator._check();return c.upload_step(*args,**kwargs)
                upload(UploadGate(),source,destination,self.server.root/('upload-'+run['run_id']+'.json'),overwrite=value.get('overwrite',False),yes=spec.get('yes',False))
                if kind=='install':
                    op=uuid.uuid4().hex
                    with self.guard:
                        self.active['install_operation_id']=op;durable_json(self.path,self.active)
                    reply=c.call('app.install',{'path':destination,'yes':True,'operation_id':op})
                    while checked(reply).get('running'):
                        self._check();time.sleep(.25);reply=c.call('app.install.status',{'operation_id':op})
                    result=checked(reply)
                    if result.get('state')=='failed' or result.get('code',0) or not result.get('installed') or result.get('title_id')!=run['title_id']:raise ClientError('Native installation failed: '+str(result))
            self._check()
            log=spec.get('completion',{}).get('log')
            if log:
                self.watch_id=checked(c.call('log.start',{'path':log['path'],'marker':log['literal']}))['watch_id']
                self.server.logs[self.watch_id]={'path':log['path'],'marker':log['literal'],'run_id':run['run_id']}
            self._phase('armed');self._phase('launching')
            if self.watch_id:self.server.logs[self.watch_id]['armed']=True
            reply=c.call('app.launch',{'title_id':run['title_id']});launched=True
            checked(reply)
            if not reply.get('result',{}).get('confirmed'):raise ClientError('Launch was not confirmed.')
            self._check();self._phase('running')
            if not self.completion.wait(spec.get('timeout_s',120)):raise TimeoutError('Completion marker timed out.' if log else 'Run timed out.')
            self._check()
            self._phase('closing')
            if spec.get('close_on_completion',True):self._close_app(run['title_id']);launched=False
            phase='completed'
        except InterruptedError as exc:phase,error='cancelled',str(exc)
        except Exception as exc:phase,error=('connection_lost' if not self.server.connected or self.failure=='connection_lost' else 'failed'),str(exc)
        finally:
            cleanup=[]
            # Sony owns dump capture. Destruction or
            # screen cleanup at .tmp creation can abort the writer. Preserve
            # the native run identity and event channel until final rename.
            crashed=bool(self.status().get('coredump'))
            if crashed:
                while not self.dump_complete.wait(.25):
                    if not self.server.connected or self.server.closing.is_set():break
            dump_pending=crashed and not self.dump_complete.is_set()
            if self.server.connected and not dump_pending:
                if self.watch_id:
                    try:checked(c.call('log.stop',{'watch_id':self.watch_id}))
                    except Exception as exc:cleanup.append(str(exc))
                    self.server.logs.pop(self.watch_id,None)
                if launched and spec.get('close_on_completion',True):
                    try:self._close_app(run['title_id'])
                    except Exception as exc:cleanup.append(str(exc))
                if perf:
                    try:checked(c.call('performance.cancel'))
                    except Exception as exc:cleanup.append(str(exc))
                if begun:
                    try:checked(c.call('run.end',{'run_id':run['run_id'],'phase':phase}))
                    except Exception as exc:cleanup.append(str(exc))
                if self.server.screen_off_when_done:
                    try:checked(c.call('screen.off'))
                    except Exception as exc:cleanup.append(str(exc))
            if not self.server.connected and phase=='completed':phase='connection_lost';error='Connection lost during cleanup; final state is uncertain.'
            elif cleanup and phase=='completed':phase='failed';error='Run completed but cleanup failed.'
            with self.guard:
                self.active.update(phase=phase,error=error,cleanup_errors=cleanup,finished_at=time.time())
                durable_json(self.path,self.active)
                self.server.event({'type':'run.finished','run_id':run['run_id'],'phase':phase,'error':error,'cleanup_errors':cleanup})


class AgentServer:
    def __init__(self,options,client=None):
        self.options=options;self.root=options.state.parent/'server';self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.store=EventStore(self.root);self.screen_off_when_done=options.screen_off_when_done
        self.connected=False;self.logs={};self.closing=threading.Event();self.rpc_guard=threading.RLock();self.control_queue=queue.Queue(maxsize=8);self.connection_error=None;self.reconnect_disabled=False;self.native_seen=set();self.native_order=[];self.dropped_counts={}
        self.client=client or ServerClient(private_json(options.credentials),options.state,timeout=20,retry_disconnect=False,manage_screen=False,screen_off_when_done=False,host=options.vita_ip,agent_name=options.agent_name,event_sink=self.receive,disconnect_sink=self.disconnected)
        seen_path=self.root/'native-events.json'
        if seen_path.exists():
            self.native_order=[tuple(item) for item in private_json(seen_path)];self.native_seen=set(self.native_order)
        self.last_activity=time.monotonic()
        self.runs=RunCoordinator(self)
    def event(self,event):
        result=self.store.append(event);self.runs.on_event(result);return result
    def receive(self,frame):
        self.last_activity=time.monotonic()
        kind,result=frame['type'],frame['result'];run=frame.get('run_id')
        if kind in ('coredump.batch','dialog.batch'):
            dropped=result.get('dropped',0);previous=self.dropped_counts.get(kind,0);self.dropped_counts[kind]=dropped
            if result.get('lost') or dropped!=previous:self.event({'type':'events.overflow','source':kind,'run_id':run,'lost':result.get('lost',0),'dropped_since_last':max(0,dropped-previous)})
            for event in result['events']:
                signature=(event.get('type'),event.get('observed_us'),event.get('sequence'),event.get('path'),event.get('code'))
                if signature in self.native_seen:continue
                self.native_seen.add(signature);self.native_order.append(signature)
                if len(self.native_order)>256:self.native_seen.remove(self.native_order.pop(0))
                self.event({**event,'run_id':run,'native_sequence':event.get('sequence')})
                durable_json(self.root/'native-events.json',self.native_order)
        elif kind=='performance.batch':
            if result.get('dropped_samples'):self.event({'type':'performance.overflow','run_id':run,'lost':result['dropped_samples']})
            for sample in result['samples']:self.event({'type':'performance.sample','run_id':run,'sample':sample})
        elif kind=='log.batch':
            watch=self.logs.get(result['watch_id'])
            if watch is None:return
            meta={'watch_id':result['watch_id'],'path':watch.get('path'),'run_id':watch.get('run_id',run)}
            if result['reset']:self.event({'type':'log.reset',**meta,'offset':result['offset']})
            if result['data']:self.event({'type':'log.data',**meta,'offset':result['offset'],'next_offset':result['next_offset'],'encoding':result['encoding'],'data':result['data']})
            if int(result['marker_hits']) and not watch.get('fired'):
                self.event({'type':'log.marker',**meta,'literal':watch.get('marker'),'hits':result['marker_hits'],'ends':result['marker_ends'],'offsets_omitted':result['marker_offsets_omitted']})
                if watch.get('once'):
                    watch['fired']=True;self.control_queue.put_nowait(result['watch_id'])
        else:raise ClientError('Unknown Vita push frame type.')
    def disconnected(self,message):
        if self.connected:
            self.connected=False;self.connection_error=message;self.event({'type':'connection.lost','message':message})
    def connect(self):
        with self.rpc_guard:
            reply=self.client.call('events.subscribe')
            if reply.get('status')=='error':
                self.reconnect_disabled=True
                raise ClientError('Installed plugin rejected native push subscription; install the matching build. '+str(reply.get('error')))
            checked(reply);self.connected=True;self.connection_error=None;self.last_activity=time.monotonic()
            self.event({'type':'connection.ready','transport':'persistent_tls_push'})
    def _pending(self):
        return private_json(self.options.state).get('pending') if self.options.state.exists() else None

    def _session_status(self):
        expires=getattr(self.client,'session_expires_at',None)
        deadline=getattr(self.client,'session_deadline',None)
        remaining=None if expires is None else max(0,deadline-time.monotonic() if deadline is not None else expires-time.time())
        idle_remaining=max(0,30*60-(time.monotonic()-self.last_activity))
        expired=remaining==0 or idle_remaining==0
        return {'expires_at':expires,'expires_in_s':remaining,'idle_expires_in_s':idle_remaining,
                'state':'expired' if expired else ('unknown' if expires is None else 'valid')}

    def _renew_due(self):
        session=self._session_status()
        return (session['state']=='expired' or
                (session['expires_in_s'] is not None and session['expires_in_s']<=60) or
                time.monotonic()-self.last_activity>=29*60 or
                (session['state']=='unknown' and isinstance(self.client,VitaClient) and getattr(self.options,'device_dir',None)))

    def _new_session(self):
        if self.reconnect_disabled or not getattr(self.options,'device_dir',None):
            raise ClientError('Session renewal requires device_dir with its saved pairing identity.')
        pending=self._pending()
        if pending and pending.get('op') not in RETRYABLE_OPS:
            raise ClientError('Uncertain pending command requires session recover.')
        # Close the command channel first: the Vita only exposes the saved-peer
        # listener after relinquishing the previous command connection.
        self.connected=False;self.client.close()
        # Give the native worker time to release the session listener.
        time.sleep(1)
        import pair_vita
        pair_vita.BASE=self.options.device_dir.resolve()
        with contextlib.redirect_stdout(__import__('sys').stderr):
            creds=pair_vita.pair(resume=True,host=getattr(self.options,'vita_ip',None),agent_name=getattr(self.options,'agent_name',None),timeout=5)
        # pair() archives the old state unchanged; effects are gated above.
        self.client=ServerClient(creds,self.options.state,timeout=20,retry_disconnect=False,manage_screen=False,screen_off_when_done=False,event_sink=self.receive,disconnect_sink=self.disconnected)
        self.client.command_ready_until=time.monotonic()+15
        for watch_id in self.logs:
            self.event({'type':'log.interrupted','watch_id':watch_id,'reason':'session renewed; re-register this listener'})
        self.logs.clear();self.connect()
        self.event({'type':'session.renewed'})

    def _reconnect(self):
        pending=self._pending()
        if pending and pending.get('op') not in RETRYABLE_OPS:
            raise ClientError('Uncertain pending command requires session recover.')
        try:
            if pending:self.client.recover()
            self.connect()
        except Exception:
            self._new_session()

    def _supervise(self):
        backoff=2
        while not self.closing.wait(backoff):
            if self.reconnect_disabled:continue
            try:
                with self.rpc_guard:
                    # Do not interrupt a run, including dump finalization, to
                    # renew authentication. Expiry is still visible in status.
                    if self.runs.busy():continue
                    if self.connected and self._renew_due():
                        self._new_session()
                    while self.connected:
                        try:watch_id=self.control_queue.get_nowait()
                        except queue.Empty:break
                        checked(self.client.call('log.stop',{'watch_id':watch_id}));self.logs.pop(watch_id,None)
                        self.last_activity=time.monotonic()
                    if not self.connected:self._reconnect()
                    backoff=2
            except Exception as exc:self.connection_error=str(exc);backoff=min(60,backoff*2)

    def dispatch(self,request):
        method=request.get('method');args=request.get('args',{})
        if not isinstance(args,dict):raise ClientError('Server arguments must be an object.')
        if method=='server.status':return {'status':'ok','result':{'connected':self.connected and self._session_status()['state']!='expired','session':self._session_status(),'connection_error':self.connection_error,'run':self.runs.status(),'latest_event':self.store.sequence,'socket':str(self.socket_path),'event_journal':str(self.store.path)}}
        if method=='events.read':return {'status':'ok','result':self.store.read(**args)}
        if method not in ('run.status','run.cancel'):
            with self.rpc_guard:
                if self.connected and self._renew_due() and not self.runs.busy():self._new_session()
        if method=='run.start':return {'status':'ok','result':self.runs.start(args)}
        if method=='run.status':return {'status':'ok','result':self.runs.status()}
        if method=='run.cancel':return {'status':'ok','result':self.runs.cancel()}
        if method=='performance.start':
            if self.runs.busy():raise ClientError('Performance is controlled by the active run.')
            VitaClient._command('performance.watch',args)
            with self.rpc_guard:return self.client.call('performance.watch',args)
        if method=='performance.stop':
            if self.runs.busy():raise ClientError('Performance is controlled by the active run.')
            with self.rpc_guard:return self.client.call('performance.cancel')
        if method=='watch.log.start':
            if set(args)-{'path','literal','once'} or not {'path','literal'}<=set(args) or type(args.get('once',False))is not bool:raise ClientError('Log watch requires path/literal and optional once.')
            with self.rpc_guard:
                result=checked(self.client.call('log.start',{'path':args['path'],'marker':args['literal']}))
                self.logs[result['watch_id']]={'path':args['path'],'marker':args['literal'],'once':args.get('once',False)}
                return {'status':'ok','result':result}
        if method=='watch.log.stop':
            with self.rpc_guard:
                reply=self.client.call('log.stop',args);checked(reply);self.logs.pop(args['watch_id'],None);return reply
        if method=='execute':
            import argparse
            import vita_agent
            values=args.copy()
            for field in ('source','file','output','transfer_state','candidate','plan','macro_store'):
                if values.get(field) is not None:values[field]=Path(values[field])
            options=argparse.Namespace(**values)
            if self.runs.busy() and (options.group in ('app','input','touch','macro','config','content') or (options.group=='screen' and options.action!='capture') or (options.group=='fs' and options.action not in ('list','stat','download')) or options.group in ('call','session','performance')):raise ClientError('This command conflicts with the active run; status, events, metadata and captures remain available.')
            with self.rpc_guard:
                # Only repeat complete CLI operations that are observations;
                # other commands retain exact-ID recovery even on disconnect.
                observation=(options.group=='system' and options.action=='snapshot') or (options.group=='fs' and options.action in ('list','stat')) or (options.group=='app' and options.action in ('list','running'))
                def execute():
                    if options.group!='screen' or options.action not in ('on','off'):checked(self.client.call('screen.on'))
                    result=vita_agent.execute(options,self.client,emit_result=lambda event:self.event({'type':'command.progress','result':event}))
                    self.last_activity=time.monotonic()
                    return result
                try:
                    try:return execute()
                    except (OSError,ClientError):
                        pending=self._pending()
                        if not observation or not pending or pending.get('op') not in RETRYABLE_OPS or self.runs.busy():raise
                        self._new_session()
                        return execute()
                finally:
                    failed=sys.exc_info()[0] is not None
                    # Preserve the primary failure and any pending request;
                    # local validation errors still get normal screen cleanup.
                    cleanup=self.screen_off_when_done and not self.runs.busy() and getattr(options,'op',None)!='system.reboot' and not (options.group=='screen' and options.action in ('on','off'))
                    if cleanup and (not failed or (self.connected and self._pending() is None)):
                        try:
                            checked(self.client.call('screen.off'));self.last_activity=time.monotonic()
                        except Exception as exc:
                            if not failed:raise
                            self.event({'type':'command.cleanup_failed','message':str(exc)})
        raise ClientError('Unknown server method.')
    @property
    def socket_path(self):return self.root/'server.sock'
    def serve(self):
        path=self.socket_path
        lock=os.open(self.root/'server.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        import fcntl
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:os.close(lock);raise ClientError('PC server is already running.') from None
        server=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(65)
                try:
                    raw=self.rfile.readline(MAX_IPC+1)
                    if len(raw)>MAX_IPC or not raw.endswith(b'\n'):raise ClientError('IPC request exceeds limit or lacks framing.')
                    result=server.dispatch(strict_json(raw))
                except NativeFrameError as exc:result=exc.as_result()
                except Exception as exc:result={'status':'client_error','message':str(exc)}
                encoded=json.dumps(result,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
                if len(encoded)>MAX_IPC:encoded=b'{"status":"client_error","message":"IPC reply exceeds 1 MiB; request a limit."}\n'
                with contextlib.suppress(OSError):self.wfile.write(encoded)
        class Listener(socketserver.ThreadingUnixStreamServer):
            daemon_threads=True
        with contextlib.suppress(FileNotFoundError):path.unlink()
        try:
            with Listener(str(path),Handler) as listener:
                os.chmod(path,0o600)
                try:self.connect()
                except Exception as exc:self.connection_error=str(exc)
                supervisor=threading.Thread(target=self._supervise,name='vita-server-supervisor',daemon=True);supervisor.start()
                print(json.dumps({'status':'ok','result':{'listening':str(path),'connected':self.connected,'transport':'persistent_tls_push'}}),flush=True)
                listener.serve_forever(poll_interval=.25)
        finally:
            self.closing.set()
            if self.runs.busy():
                self.runs.cancel()
                if self.runs.thread:self.runs.thread.join(timeout=25)
            self.client.close()
            if 'supervisor' in locals():supervisor.join(timeout=8)
            with contextlib.suppress(FileNotFoundError):path.unlink()
            os.close(lock)


def request(options,method,args=None):
    path=options.state.parent/'server/server.sock'
    payload=json.dumps({'method':method,'args':args or {}},default=lambda x:str(x) if isinstance(x,Path) else x,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
    if len(payload)>MAX_IPC:raise ClientError('Server request exceeds 1 MiB.')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(65);sock.connect(str(path));sock.sendall(payload)
        with sock.makefile('rb') as stream:raw=stream.readline(MAX_IPC+1)
    if len(raw)>MAX_IPC or not raw.endswith(b'\n'):raise ClientError('Incomplete or oversized PC server reply.')
    return strict_json(raw)


def running(options):return (options.state.parent/'server/server.sock').exists()
