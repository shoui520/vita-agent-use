# SPDX-License-Identifier: GPL-3.0-or-later
"""Forward native Vita event records asynchronously through the persistent harness."""
import threading
from vita_client import ClientError

class EventListener:
    def __init__(self, client, emit):
        self.client=client;self.emit=emit
        self.guard=threading.Lock();self.stop_event=threading.Event()
        self.dialog_cursor=0;self.dialog_dropped=0;self.dialog_active=False
        self.logs={};self.thread=None;self.cursor=0;self.state='idle';self.error=None;self.dropped=0

    @staticmethod
    def checked(reply):
        if reply.get('status')!='ok':raise ClientError('Native event watch rejected: '+str(reply.get('error')))
        return reply['result']

    def start(self):
        if self.thread is not None and self.thread.is_alive():raise ClientError('Event listener already running.')
        result=self.checked(self.client.call('events.start'))
        self.cursor=result['next'];self.dropped=result['dropped']
        try:
            dialogs=self.checked(self.client.call('dialog.events.start'))
        except BaseException:
            self.checked(self.client.call('events.stop'))
            raise
        self.dialog_cursor=dialogs['next'];self.dialog_dropped=dialogs['dropped'];self.dialog_active=True
        self.stop_event.clear();self.state='running';self.error=None
        self.thread=threading.Thread(target=self._worker,name='vita-events',daemon=True)
        self.thread.start()
        return self.status()

    def _worker(self):
        try:
            while not self.stop_event.wait(0.5):
                while True:
                    reply=self.client.call('events.read',{'after':self.cursor})
                    if reply.get('status')=='error' and reply.get('error',{}).get('code')==-2:
                        break # Kernel hook publication owns the ring briefly.
                    batch=self.checked(reply)
                    if batch['lost'] or batch['dropped']!=self.dropped:
                        self.emit({'type':'events.overflow','lost':batch['lost'],
                                   'dropped_since_last':batch['dropped']-self.dropped})
                    self.dropped=batch['dropped']
                    for event in batch['events']:self.emit(event)
                    self.cursor=batch['next']
                    if not batch['more'] or self.stop_event.is_set():break
                self._dialogs()
                self._logs()
        except Exception as exc:
            with self.guard:self.state,self.error='failed',str(exc)
            self.emit({'type':'events.error','message':str(exc)})

    def _dialogs(self):
        # Native fixed ring; formatting never waits on this poll or the network.
        for _ in range(4):
            if self.stop_event.is_set():return
            reply=self.client.call('dialog.events.read',{'after':self.dialog_cursor})
            if reply.get('status')=='error' and reply.get('error',{}).get('code')==-2:return
            batch=self.checked(reply)
            if batch['lost'] or batch['dropped']!=self.dialog_dropped:
                self.emit({'type':'events.overflow','source':'dialog.errors','lost':batch['lost'],
                           'dropped_since_last':batch['dropped']-self.dialog_dropped})
            self.dialog_dropped=batch['dropped']
            for event in batch['events']:self.emit(event)
            self.dialog_cursor=batch['next']
            if not batch['more']:return

    def log_start(self,path,marker):
        if self.state!='running':raise ClientError('Start the event listener before adding log watches.')
        with self.guard:
            result=self.checked(self.client.call('log.start',{'path':path,'marker':marker}))
            self.logs[result['watch_id']]=path
        return {'status':'ok','result':result}

    def log_stop(self,watch_id):
        with self.guard:
            result=self.checked(self.client.call('log.stop',{'watch_id':watch_id}))
            self.logs.pop(watch_id,None)
        return {'status':'ok','result':result}

    def _logs(self):
        # Fixed bursts keep an actively written log from starving captures/input.
        # Native literal scanning determines marker hits; no host rescanning.
        with self.guard:ids=list(self.logs)
        for watch_id in ids:
            for _ in range(16):
                if self.stop_event.is_set():return
                with self.guard:
                    if watch_id not in self.logs:break
                    path=self.logs[watch_id]
                    reply=self.client.call('log.read',{'watch_id':watch_id})
                if reply.get('status')!='ok':
                    self.emit({'type':'log.error','watch_id':watch_id,'path':path,'error':reply.get('error')})
                    break
                result=reply['result']
                if result['reset']:
                    self.emit({'type':'log.reset','watch_id':watch_id,'path':path,'offset':result['offset']})
                if result['data']:
                    self.emit({'type':'log.data','watch_id':watch_id,'path':path,
                               'offset':result['offset'],'next_offset':result['next_offset'],
                               'encoding':result['encoding'],'data':result['data']})
                if int(result['marker_hits']):
                    self.emit({'type':'log.marker','watch_id':watch_id,'path':path,
                               'hits':result['marker_hits'],'ends':result['marker_ends'],
                               'offsets_omitted':result['marker_offsets_omitted']})
                if not result['more']:break

    def status(self):
        with self.guard:
            return {'status':'ok','result':{'state':self.state,'after':self.cursor,
                                           'error':self.error,'dialog_errors':{'active':self.dialog_active,'after':self.dialog_cursor},'poll_interval_ms':500,'logs':[{'watch_id':i,'path':p} for i,p in self.logs.items()]}}

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=25)
            if self.thread.is_alive():raise ClientError('Event listener cleanup still in progress.')
            with self.guard:ids=list(self.logs)
            for watch_id in ids:self.log_stop(watch_id)
            try:self.checked(self.client.call('events.stop'))
            finally:
                if self.dialog_active:
                    self.checked(self.client.call('dialog.events.stop'));self.dialog_active=False
        with self.guard:self.state='stopped'
        return self.status()
