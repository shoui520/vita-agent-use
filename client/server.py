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
import signal
import time
import uuid
from vita_client import ClientError, NativeFrameError, UncertainOutcomeError, UploadError, VitaClient, durable_json, private_json, strict_json, screen_off_if_idle, connection_setup_hint, read_unresolved, unresolved_path

IPC_IDLE_TIMEOUT = 65
# Sent while a command runs, so a long recovery never looks like a hang.
IPC_KEEPALIVE = 10
# Idle heartbeat: keeps the connection from looking dead to the Vita (it
# retires a silent connection after 30 s once another one is waiting).
HEARTBEAT_S = 15
# Extend the token this long before it expires.
EXTEND_MARGIN_S = 600
# A run survives a dropped connection this long when the plugin keeps
# session state across reconnects.
RUN_RECONNECT_WAIT = 90
MAX_IPC = 1024 * 1024
MAX_FRAME = 2 * 1024 * 1024
TERMINAL = {'completed', 'cancelled', 'failed', 'connection_lost'}


@contextlib.contextmanager
def recovery_limit(client, seconds):
    limit = getattr(client, 'recovery_limit', None)
    if limit is None:
        yield
    else:
        with limit(seconds):
            yield


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
        return self.getresponse_wait(self.timeout)

    def getresponse_wait(self,timeout,progress=None):
        deadline=time.monotonic()+timeout
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('Vita response timed out.')
            try:
                result=self.responses.get(timeout=min(5,remaining) if progress is not None else remaining)
                break
            except queue.Empty:
                if progress is not None:progress()
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
    """Every connection is a push transport; the server sees loss and recovery."""
    def __init__(self,*args,event_sink,disconnect_sink,call_sink=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.event_sink,self.disconnect_sink,self.call_sink=event_sink,disconnect_sink,call_sink
    def _close_transport(self):
        had_connection=self._connection is not None
        super()._close_transport()
        if had_connection:self.disconnect_sink('Protected transport closed; pending effects retain their recovery state.')
    def _connect(self):
        connection=super()._connect()
        self._connection=PushTransport(connection,self.event_sink,self.disconnect_sink)
        return self._connection
    def _call_raw(self,op,args=None):
        result=super()._call_raw(op,args)
        if self.call_sink is not None and not self._recovering and op!='events.subscribe':
            self.call_sink()
        return result


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
            if event.get('type')=='connection.lost':
                # With session grace the native run survives a reconnect;
                # the worker gives the connection RUN_RECONNECT_WAIT to return.
                if not self.server.features.get('connection_grace_us'):
                    self.failure='connection_lost';self.completion.set()
            elif event.get('type')=='session.renewed':
                self.failure='connection_lost';self.completion.set()
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
                native=checked(c.call('log.start',{'path':log['path'],'marker':log['literal']}))['watch_id']
                self.watch_id=self.server.register_watch(native,log['path'],log['literal'],run_id=run['run_id'])
            self._phase('armed');self._phase('launching')
            if self.watch_id:self.server.logs[self.watch_id]['armed']=True
            reply=c.call('app.launch',{'title_id':run['title_id']});launched=True
            checked(reply)
            if not reply.get('result',{}).get('confirmed'):raise ClientError('Launch was not confirmed.')
            self._check();self._phase('running')
            deadline=time.monotonic()+spec.get('timeout_s',120)
            while not self.completion.wait(max(0,min(1,deadline-time.monotonic()))):
                lost=self.server.lost_at
                if not self.server.connected and lost is not None and time.monotonic()-lost>=RUN_RECONNECT_WAIT:
                    self.failure='connection_lost';break
                if time.monotonic()>=deadline:raise TimeoutError('Completion marker timed out.' if log else 'Run timed out.')
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
                with recovery_limit(c,15):
                    if self.watch_id:
                        native=self.server.unregister_watch(self.watch_id)
                        try:checked(c.call('log.stop',{'watch_id':native}))
                        except Exception as exc:cleanup.append(str(exc))
                    if launched and spec.get('close_on_completion',True):
                        try:self._close_app(run['title_id'])
                        except Exception as exc:cleanup.append(str(exc))
                    if perf:
                        try:checked(c.call('performance.cancel'))
                        except Exception as exc:cleanup.append(str(exc))
                    if begun:
                        try:checked(c.call('run.end',{'run_id':run['run_id'],'phase':phase}))
                        except Exception as exc:cleanup.append(str(exc))
                    if self.server.screen_off_when_done and not self.server.background_screen_busy():
                        try:screen_off_if_idle(c)
                        except Exception as exc:cleanup.append(str(exc))
            if not self.server.connected and phase=='completed':phase='connection_lost';error='Connection lost during cleanup; final state is uncertain.'
            elif cleanup and phase=='completed':phase='failed';error='Run completed but cleanup failed.'
            with self.guard:
                self.active.update(phase=phase,error=error,cleanup_errors=cleanup,finished_at=time.time())
                durable_json(self.path,self.active)
                self.server.event({'type':'run.finished','run_id':run['run_id'],'phase':phase,'error':error,'cleanup_errors':cleanup})


_MISSING=object()


class AgentServer:
    def __init__(self,options,client=None):
        self.options=options;self.root=options.state.parent/'server';self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.store=EventStore(self.root);self.screen_off_when_done=options.screen_off_when_done
        self.connected=False;self.logs={};self.log_native={};self.closing=threading.Event();self.rpc_guard=threading.RLock();self.control_queue=queue.Queue(maxsize=8);self.connection_error=None;self.reconnect_disabled=False;self.native_seen=set();self.native_order=[];self.dropped_counts={}
        self.saving_dumps=set()
        # Session features advertised by the plugin's subscribe reply.
        self.features={};self.subscribed_token=None;self.lost_at=None;self.perf=None;self.reconnects=0
        self._subscribing=False;self._rearming=False;self.renewer=None
        # Serializes subscription without the server-wide RPC guard, which a
        # long command may hold while a run thread needs its pushes back.
        self._subscribe_lock=threading.RLock()
        if client is None:
            client=ServerClient(private_json(options.credentials),options.state,timeout=20,manage_screen=False,screen_off_when_done=False,host=options.vita_ip,agent_name=options.agent_name,event_sink=self.receive,disconnect_sink=self.disconnected,call_sink=self.after_call)
            client.credentials_path=options.credentials
            if getattr(options,'device_dir',None):
                from renewal import SessionRenewer
                self.renewer=SessionRenewer(options.device_dir,host=getattr(options,'vita_ip',None),agent_name=getattr(options,'agent_name',None),credentials_path=options.credentials,state_path=options.state)
                client.session_hook=self.renewer
            client.notice=self.notice
        self.client=client
        seen_path=self.root/'native-events.json'
        if seen_path.exists():
            self.native_order=[tuple(item) for item in private_json(seen_path)];self.native_seen=set(self.native_order)
        self.last_activity=time.monotonic()
        self.runs=RunCoordinator(self)
    def event(self,event):
        path=event.get('path','')
        if event.get('type')=='coredump.saving':
            self.saving_dumps.add(path.removesuffix('.tmp'))
        elif event.get('type')=='coredump.complete':
            self.saving_dumps.discard(path)
        result=self.store.append(event);self.runs.on_event(result);return result
    def notice(self,notice):
        # Recovered/unresolved commands and renewals belong in the history.
        self.event(dict(notice))
    def background_screen_busy(self):
        return bool(self.logs or self.saving_dumps)
    def register_watch(self,native,path,marker,*,once=False,run_id=None):
        """Watch IDs stay stable for callers even when re-armed under a new session."""
        public=native
        while public in self.logs:public=max(self.logs)+1
        watch={'path':path,'marker':marker,'once':once,'native_id':native}
        if run_id is not None:watch['run_id']=run_id
        self.logs[public]=watch;self.log_native[native]=public
        return public
    def unregister_watch(self,public):
        watch=self.logs.pop(public,None)
        native=watch.get('native_id',public) if watch else public
        self.log_native.pop(native,None)
        return native
    def receive(self,frame):
        self.last_activity=time.monotonic()
        kind,result=frame['type'],frame['result'];run=frame.get('run_id')
        if kind in ('coredump.batch','dialog.batch','tty.batch'):
            dropped=result.get('dropped',0);previous=self.dropped_counts.get(kind,0);self.dropped_counts[kind]=dropped
            if result.get('lost') or dropped!=previous:self.event({'type':'events.overflow','source':kind,'run_id':run,'lost':result.get('lost',0),'dropped_since_last':max(0,dropped-previous)})
            for event in result['events']:
                signature=(event.get('type'),event.get('observed_us'),event.get('sequence'),event.get('path'),event.get('code'))
                if signature in self.native_seen:continue
                self.native_seen.add(signature);self.native_order.append(signature)
                if len(self.native_order)>256:self.native_seen.remove(self.native_order.pop(0))
                if kind=='tty.batch':
                    # Keep original bytes; UTF-8 is only a human-readable preview.
                    event={**event,'text':bytes.fromhex(event['data']).decode('utf-8',errors='replace')}
                self.event({**event,'run_id':run,'native_sequence':event.get('sequence')})
                durable_json(self.root/'native-events.json',self.native_order)
        elif kind=='performance.batch':
            if result.get('dropped_samples'):self.event({'type':'performance.overflow','run_id':run,'lost':result['dropped_samples']})
            for sample in result['samples']:self.event({'type':'performance.sample','run_id':run,'sample':sample})
        elif kind=='log.batch':
            public=self.log_native.get(result['watch_id'],result['watch_id'])
            watch=self.logs.get(public)
            if watch is None:return
            watch['next_offset']=result['next_offset']
            meta={'watch_id':public,'path':watch.get('path'),'run_id':watch.get('run_id',run)}
            if result['reset']:self.event({'type':'log.reset',**meta,'offset':result['offset']})
            if result['data']:self.event({'type':'log.data',**meta,'offset':result['offset'],'next_offset':result['next_offset'],'encoding':result['encoding'],'data':result['data']})
            if int(result['marker_hits']) and not watch.get('fired'):
                self.event({'type':'log.marker',**meta,'literal':watch.get('marker'),'hits':result['marker_hits'],'ends':result['marker_ends'],'offsets_omitted':result['marker_offsets_omitted']})
                if watch.get('once'):
                    watch['fired']=True
                    with contextlib.suppress(queue.Full):self.control_queue.put_nowait(public)
        else:raise ClientError('Unknown Vita push frame type.')
    def disconnected(self,message):
        lost=getattr(self.client,'connection_lost',None)
        if lost is not None:lost()
        if self.connected:
            self.connected=False;self.connection_error=message;self.lost_at=time.monotonic()
            self.event({'type':'connection.lost','message':message})
    def _transport_live(self):
        connection=getattr(self.client,'_connection',_MISSING)
        return connection is _MISSING or (connection is not None and getattr(connection,'sock',None) is not None)
    def _grace_covers(self,gap):
        try:grace=int(self.features.get('connection_grace_us'))/1e6
        except (TypeError,ValueError):return False
        return gap is None or gap<grace-15
    def subscribe(self):
        """Enable native pushes for the current session (also the old-plugin reconnect)."""
        with self._subscribe_lock:
            previous=self.subscribed_token
            gap=None if self.lost_at is None else time.monotonic()-self.lost_at
            self._subscribing=True
            try:reply=self.client.call('events.subscribe')
            finally:self._subscribing=False
            if reply.get('status')=='error':
                raise ClientError('Installed plugin rejected native push subscription; install the matching build. '+str(reply.get('error')))
            result=checked(reply)
            session=result.get('session') if isinstance(result,dict) else None
            self.features=dict(session) if isinstance(session,dict) else {}
            self.subscribed_token=getattr(self.client,'token',None)
            renewed=previous is not None and previous!=self.subscribed_token
            self.connected=True;self.connection_error=None;self.last_activity=time.monotonic();self.lost_at=None
            if previous is not None:self.reconnects+=1
            self.event({'type':'connection.ready','transport':'persistent_tls_push','tty':result.get('tty') if isinstance(result,dict) else None,
                        'resumed':previous is not None,'session_renewed':renewed})
            if previous is not None and (renewed or not self._grace_covers(gap)):
                self.rearm('session renewed' if renewed else 'reconnected after the native session grace')
    def after_call(self):
        """A command just succeeded: restore pushes if the connection changed."""
        if self._subscribing or self._rearming or self.closing.is_set():return
        self.last_activity=time.monotonic()
        try:
            if getattr(self.client,'token',None)!=self.subscribed_token:
                self.subscribe()
            elif not self.connected and self._transport_live():
                if not self.features.get('ping'):
                    # Older plugins drop push state with the connection.
                    self.subscribe();return
                gap=None if self.lost_at is None else time.monotonic()-self.lost_at
                self.connected=True;self.connection_error=None;self.lost_at=None;self.reconnects+=1
                self.event({'type':'connection.ready','transport':'persistent_tls_push','resumed':True,'session_renewed':False,
                            'gap_s':None if gap is None else round(gap,3)})
                if not self._grace_covers(gap):self.rearm('reconnected after the native session grace')
        except ClientError as exc:
            self.connection_error=str(exc)
    def rearm(self,reason):
        """Restart log watches and server-started performance pushes the Vita released."""
        if self._rearming:return
        same_session=reason!='session renewed'
        self._rearming=True
        try:
            for public,watch in list(self.logs.items()):
                old=watch.get('native_id',public)
                if same_session:
                    # IDs from an earlier session may name a new watch now.
                    with contextlib.suppress(ClientError):self.client.call('log.stop',{'watch_id':old})
                try:reply=self.client.call('log.start',{'path':watch['path'],'marker':watch['marker']})
                except ClientError as exc:reply={'status':'client_error','error':str(exc)}
                if reply.get('status')=='ok':
                    native=reply['result']['watch_id']
                    self.log_native.pop(old,None);self.log_native[native]=public;watch['native_id']=native
                    self.event({'type':'log.resumed','watch_id':public,'path':watch['path'],'run_id':watch.get('run_id'),'reason':reason,
                                'from_offset':reply['result'].get('offset'),'last_offset':watch.get('next_offset')})
                else:
                    self.unregister_watch(public)
                    self.event({'type':'log.interrupted','watch_id':public,'reason':reason+'; re-arming failed: '+json.dumps(reply.get('error'))})
            perf=self.perf
            if perf:
                remaining=perf['duration_s']-(time.monotonic()-perf['started'])
                if remaining>=1:
                    try:reply=self.client.call('performance.watch',{'duration_s':math.ceil(remaining),'interval_ms':perf['interval_ms']})
                    except ClientError as exc:reply={'status':'client_error','error':str(exc)}
                    resumed=reply.get('status') in ('ok','accepted')
                    self.event({'type':'performance.resumed' if resumed else 'performance.interrupted','reason':reason,'remaining_s':math.ceil(remaining)})
                    if not resumed:self.perf=None
                else:self.perf=None
        finally:self._rearming=False
    def ensure_connected(self):
        with self._subscribe_lock:
            token=getattr(self.client,'token',None)
            if self.connected and token==self.subscribed_token and self._transport_live():return
            if token!=self.subscribed_token or not self.features.get('ping'):
                self.subscribe();return
            self.client.call('session.ping')
            if not self.connected:self.subscribe()
    def _pending(self):
        try:return private_json(self.options.state).get('pending') if self.options.state.exists() else None
        except (OSError,ValueError,ClientError):return None

    def _session_status(self):
        expires=getattr(self.client,'session_expires_at',None)
        deadline=getattr(self.client,'session_deadline',None)
        remaining=None if expires is None else max(0,deadline-time.monotonic() if deadline is not None else expires-time.time())
        active=max(self.last_activity,getattr(self.client,'last_exchange',0) or 0)
        idle_remaining=max(0,30*60-(time.monotonic()-active))
        expired=remaining==0 or idle_remaining==0
        return {'expires_at':expires,'expires_in_s':remaining,'idle_expires_in_s':idle_remaining,
                'state':'expired' if expired else ('unknown' if expires is None else 'valid'),
                'extend_supported':bool(self.features.get('extend')) and not getattr(self.client,'_extend_unsupported',False)}

    def _keep_alive(self):
        """One supervisor tick: reconnect, extend before expiry, or heartbeat."""
        client=self.client
        while self.connected:
            try:public=self.control_queue.get_nowait()
            except queue.Empty:break
            native=self.unregister_watch(public)
            checked(client.call('log.stop',{'watch_id':native}))
        if not self.connected or getattr(client,'token',None)!=self.subscribed_token:
            self.ensure_connected();return
        expired=getattr(client,'session_expired',None)
        if expired is not None and expired(EXTEND_MARGIN_S):
            if not getattr(client,'_extend_unsupported',True) and client.extend_session():return
            if expired(120) and self.renewer is not None and not self.runs.busy():
                # Older plugins cannot extend: renew while idle, not mid-command.
                self.renewer.renew_now(client);self.ensure_connected();return
        if self.features.get('ping') and time.monotonic()-(getattr(client,'last_exchange',0) or 0)>=HEARTBEAT_S:
            client.call('session.ping')

    def _supervise(self):
        failures=0;next_attempt=0
        while not self.closing.wait(1):
            if time.monotonic()<next_attempt:continue
            # A running command does its own recovery; never queue behind it.
            if not self.rpc_guard.acquire(timeout=.5):continue
            try:
                with recovery_limit(self.client,10):self._keep_alive()
                failures=0
            except Exception as exc:
                self.connection_error=str(exc);failures+=1
                next_attempt=time.monotonic()+min(15,2**failures)
            finally:self.rpc_guard.release()

    def renew_session(self,pair=False,log=None):
        """session connect/pair while serving: reuse a live session when possible."""
        client=self.client
        before=getattr(client,'token',None)
        if not pair:
            try:
                with recovery_limit(client,5):
                    reply=client.call('session.ping' if self.features.get('ping') else 'capabilities')
                if reply.get('status')=='ok':
                    self.ensure_connected()
                    return {'status':'ok','result':{'session':'reused' if getattr(client,'token',None)==before else 'renewed','session_status':self._session_status()}}
            except ClientError:
                pass
        if self.renewer is None:raise ClientError('Session renewal requires device_dir with its saved pairing identity.')
        self.renewer.renew_now(client,pair=pair,log=log)
        self.ensure_connected()
        return {'status':'ok','result':{'session':'paired' if pair else 'renewed','session_status':self._session_status()}}

    def dispatch(self,request,progress=None,cancel=None):
        method=request.get('method');args=request.get('args',{})
        if not isinstance(args,dict):raise ClientError('Server arguments must be an object.')
        if method=='server.status':
            session=self._session_status()
            result={'connected':self.connected and session['state']!='expired','session':session,'connection_error':self.connection_error,'run':self.runs.status(),'latest_event':self.store.sequence,'socket':str(self.socket_path),'event_journal':str(self.store.path),
                    'features':self.features,'reconnects':self.reconnects}
            unresolved=read_unresolved(self.options.state,5)
            if unresolved:
                result['unresolved']=unresolved;result['unresolved_journal']=str(unresolved_path(self.options.state))
            return {'status':'ok','result':result}
        if method=='events.read':return {'status':'ok','result':self.store.read(**args)}
        if method=='session.renew':
            if self.runs.busy():raise ClientError('A run is active; session changes wait until it finishes (run status, run cancel).')
            def log(*parts):
                if progress is not None:progress({'status':'output','value':{'message':' '.join(str(p) for p in parts)}})
            with self.rpc_guard:return self.renew_session(bool(args.get('pair')),log)
        recovery=method=='execute' and args.get('group')=='session' and args.get('action')=='recover'
        if recovery:
            if self.runs.busy():raise ClientError('Session recovery conflicts with the active run.')
            # Recover the exact pending request before screen.on can issue another.
            with self.rpc_guard:return self.client.recover()
        if method=='run.start':
            with self.rpc_guard:
                if not self.runs.busy():
                    try:self.ensure_connected()
                    except ClientError as exc:raise ClientError('Vita event connection is unavailable: '+str(exc)) from exc
            return {'status':'ok','result':self.runs.start(args)}
        if method=='run.status':return {'status':'ok','result':self.runs.status()}
        if method=='run.cancel':return {'status':'ok','result':self.runs.cancel()}
        if method=='performance.start':
            if self.runs.busy():raise ClientError('Performance is controlled by the active run.')
            VitaClient._command('performance.watch',args)
            with self.rpc_guard:
                reply=self.client.call('performance.watch',args)
                if reply.get('status') in ('ok','accepted'):self.perf={'duration_s':args['duration_s'],'interval_ms':args['interval_ms'],'started':time.monotonic()}
                return reply
        if method=='performance.stop':
            if self.runs.busy():raise ClientError('Performance is controlled by the active run.')
            with self.rpc_guard:
                self.perf=None
                return self.client.call('performance.cancel')
        if method=='watch.log.start':
            if set(args)-{'path','literal','once'} or not {'path','literal'}<=set(args) or type(args.get('once',False))is not bool:raise ClientError('Log watch requires path/literal and optional once.')
            with self.rpc_guard:
                result=checked(self.client.call('log.start',{'path':args['path'],'marker':args['literal']}))
                public=self.register_watch(result['watch_id'],args['path'],args['literal'],once=args.get('once',False))
                return {'status':'ok','result':{**result,'watch_id':public}}
        if method=='watch.log.stop':
            with self.rpc_guard:
                watch_id=args.get('watch_id')
                native=self.logs.get(watch_id,{}).get('native_id',watch_id)
                reply=self.client.call('log.stop',{**args,'watch_id':native});checked(reply);self.unregister_watch(watch_id)
                if isinstance(reply.get('result'),dict) and 'watch_id' in reply['result']:
                    reply={**reply,'result':{**reply['result'],'watch_id':watch_id}}
                return reply
        if method=='execute':
            import argparse
            import vita_agent
            values=args.copy()
            for field in ('source','file','output','transfer_state','candidate','plan','macro_store','state','credentials','device_dir'):
                if values.get(field) is not None:values[field]=Path(values[field])
            options=argparse.Namespace(**values)
            options._cancel=cancel
            if self.runs.busy() and (options.group in ('app','input','touch','macro','config','content','decrypt') or (options.group=='screen' and options.action!='capture') or (options.group=='fs' and options.action not in ('list','stat','download')) or options.group in ('call','session','performance')):raise ClientError('This command conflicts with the active run; status, events, metadata and captures remain available.')
            with self.rpc_guard:
                client=self.client
                if isinstance(getattr(client,'notices',None),list):client.notices=[]
                def command_progress(event):
                    self.event({'type':'command.progress','result':event})
                    if progress is None:return
                    if isinstance(event,dict) and event.get('status')=='progress':progress(event)
                    else:progress({'status':'output','value':event})
                if options.group!='screen' or options.action not in ('on','off'):
                    # Best effort: a display that will not wake must not block the command.
                    with contextlib.suppress(ClientError):client.call('screen.on')
                failed=True;result=None
                try:
                    result=vita_agent.execute(options,client,emit_result=command_progress)
                    failed=False
                finally:
                    self.last_activity=time.monotonic()
                    # Preserve the primary failure and any pending request;
                    # local validation errors still get normal screen cleanup.
                    cleanup=self.screen_off_when_done and not self.runs.busy() and not self.background_screen_busy() and getattr(options,'op',None)!='system.reboot' and not (options.group=='screen' and options.action in ('on','off'))
                    if cleanup and (not failed or self._pending() is None):
                        try:
                            with recovery_limit(client,10):screen_off_if_idle(client)
                        except Exception as exc:
                            # Cleanup never replaces the command's own result.
                            self.event({'type':'command.cleanup_failed','message':str(exc)})
                            if not failed and isinstance(result,dict):result['cleanup_error']=str(exc)
                notices=getattr(client,'notices',None)
                if notices and isinstance(result,dict):result['notices']=list(notices)
                return result
        raise ClientError('Unknown server method.')
    @property
    def socket_path(self):return self.root/'server.sock'
    def serve(self):
        path=self.socket_path
        lock=os.open(self.root/'server.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        import fcntl
        # A CLI may hold a shared probe lock for an instant.
        deadline=time.monotonic()+2
        while True:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    os.close(lock)
                    # One server per identity owns the Vita's single command
                    # connection; a second one just points at it.
                    print(json.dumps(already_serving(self.options)),flush=True);return
                time.sleep(.05)
        with contextlib.suppress(OSError):
            os.ftruncate(lock,0);os.pwrite(lock,(str(os.getpid())+'\n').encode(),0)
        server=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(IPC_IDLE_TIMEOUT)
                guard=threading.Lock();cancel=threading.Event();done=threading.Event()
                def send(result):
                    encoded=json.dumps(result,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
                    if len(encoded)>MAX_IPC:encoded=b'{"status":"client_error","message":"IPC reply exceeds 1 MiB; request a limit."}\n'
                    with guard:
                        try:
                            self.wfile.write(encoded);self.wfile.flush()
                        except OSError:
                            # The CLI went away: let loops waiting on it stop.
                            cancel.set()
                def keepalive():
                    while not done.wait(IPC_KEEPALIVE):send({'status':'keepalive'})
                try:
                    raw=self.rfile.readline(MAX_IPC+1)
                    if len(raw)>MAX_IPC or not raw.endswith(b'\n'):raise ClientError('IPC request exceeds limit or lacks framing.')
                    threading.Thread(target=keepalive,name='vita-ipc-keepalive',daemon=True).start()
                    result=server.dispatch(strict_json(raw),progress=send,cancel=cancel)
                except (NativeFrameError,UploadError,UncertainOutcomeError) as exc:result=exc.as_result()
                except Exception as exc:result={'status':'client_error','message':str(exc)}
                finally:done.set()
                send(result)
        class Listener(socketserver.ThreadingUnixStreamServer):
            daemon_threads=True
        with contextlib.suppress(FileNotFoundError):path.unlink()
        handlers={}
        def stop(signum,frame):
            for sig in handlers:signal.signal(sig,signal.SIG_IGN)
            raise SystemExit(0)
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM,signal.SIGHUP):
                with contextlib.suppress(ValueError,OSError):handlers[sig]=signal.signal(sig,stop)
        try:
            with Listener(str(path),Handler) as listener:
                os.chmod(path,0o600)
                try:
                    with recovery_limit(self.client,15):self.ensure_connected()
                except Exception as exc:self.connection_error=str(exc)
                supervisor=threading.Thread(target=self._supervise,name='vita-server-supervisor',daemon=True);supervisor.start()
                print(json.dumps({'status':'ok','result':{'listening':str(path),'connected':self.connected,'transport':'persistent_tls_push'}}),flush=True)
                listener.serve_forever(poll_interval=.25)
        finally:
            self.closing.set()
            if self.runs.busy():
                self.runs.cancel()
                if self.runs.thread:self.runs.thread.join(timeout=25)
            with contextlib.suppress(Exception):self.client.close()
            if 'supervisor' in locals():supervisor.join(timeout=8)
            with contextlib.suppress(FileNotFoundError):path.unlink()
            for sig,previous in handlers.items():
                with contextlib.suppress(ValueError,OSError,TypeError):signal.signal(sig,previous)
            os.close(lock)


def request(options,method,args=None,*,emit_progress=None,emit_output=None):
    path=options.state.parent/'server/server.sock'
    payload=json.dumps({'method':method,'args':args or {}},default=lambda x:str(x) if isinstance(x,Path) else x,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
    if len(payload)>MAX_IPC:raise ClientError('Server request exceeds 1 MiB.')
    latest=None
    if method=='execute' and args and args.get('group')=='fs' and args.get('action')=='upload':
        latest={'type':'upload','phase':'waiting_for_server','received':None,'bytes':None,
                'operation_id':None,'path':args.get('destination'),'transfer_state':str(args.get('transfer_state'))}
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(IPC_IDLE_TIMEOUT);sock.connect(str(path));sock.sendall(payload)
            with sock.makefile('rb') as stream:
                while True:
                    raw=stream.readline(MAX_IPC+1)
                    if len(raw)>MAX_IPC or not raw.endswith(b'\n'):raise ClientError('Incomplete or oversized PC server reply.')
                    reply=strict_json(raw)
                    # Commands that only stream output (performance samples) end with null.
                    if reply is None:return None
                    if not isinstance(reply,dict):raise ClientError('Invalid PC server reply.')
                    status=reply.get('status')
                    if status=='keepalive':continue
                    if status=='output':
                        if emit_output is not None:emit_output(reply.get('value'))
                        continue
                    if status!='progress':return reply
                    latest=reply.get('result')
                    if not isinstance(latest,dict):raise ClientError('Invalid PC server progress.')
                    if emit_progress is not None:emit_progress(reply)
    except (TimeoutError,OSError,ClientError) as exc:
        detail=str(exc) or type(exc).__name__
        if isinstance(exc,TimeoutError):
            detail=('The PC server sent nothing for %d s, not even its keepalive; it may be stuck. Check server status '
                    'or restart serve (credentials and pending state are kept).'%IPC_IDLE_TIMEOUT)
        if isinstance(exc,(ConnectionRefusedError,FileNotFoundError)):
            detail=('Local PC serve socket is unavailable; this does not show whether the Vita is reachable. '
                    'Check VITA_AGENT_CONFIG_DIR and start serve with the same config/identity directory. '
                    'A stopped server can leave a stale socket; do not start a duplicate server. '+connection_setup_hint())
        if isinstance(latest,dict) and latest.get('type')=='upload':
            raise UploadError('PC server progress stopped: '+detail+
                              '; the server may still be transferring. Wait for it to finish before resuming',latest) from exc
        if isinstance(exc,(ConnectionRefusedError,FileNotFoundError,TimeoutError)):
            raise ClientError(detail) from exc
        raise


def already_serving(options):
    root=options.state.parent/'server'
    pid=None
    with contextlib.suppress(OSError,ValueError):
        pid=int((root/'server.lock').read_text().strip() or 0) or None
    return {'status':'ok','result':{'already_running':True,'pid':pid,'socket':str(root/'server.sock'),
            'message':'A serve process already runs for this config directory; commands use it. '
                      'Only one can own the Vita command connection, so nothing else was started.'}}


def running(options):
    """True only while a serve process holds the lock; a stale socket is ignored."""
    root=options.state.parent/'server'
    if not (root/'server.sock').exists():return False
    try:fd=os.open(root/'server.lock',os.O_RDONLY|os.O_NOFOLLOW)
    except FileNotFoundError:return True
    except OSError:return True
    try:
        import fcntl
        try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:return True
        return False
    finally:os.close(fd)
