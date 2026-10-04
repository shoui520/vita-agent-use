# SPDX-License-Identifier: GPL-3.0-or-later
"""Asynchronous per-title macro runner sharing the harness's persistent client."""
import threading
import time
from macros import MacroStore, compile_macro,compile_segments
from vita_client import ClientError, VitaClient

class MacroRunner:
    def __init__(self, client, store):
        self.client, self.store = client, MacroStore(store)
        self.thread = None
        self.stop_event = threading.Event()
        self.guard = threading.Lock()
        self.job = {'state': 'idle'}

    @staticmethod
    def checked(reply, expected):
        if reply.get('status') != expected:
            raise ClientError('Macro command rejected: ' + str(reply.get('error')))
        return reply

    def run(self, title_id, name, repeats=1):
        if self.thread is not None and self.thread.is_alive():
            raise ClientError('A macro is already running.')
        macro = self.store.load(title_id, name)
        # Validate the entire macro/repeat envelope before acquiring inputs.
        segments=compile_segments(macro)
        args=VitaClient._command('input.submit',{**segments[0],'repeats':repeats})['args']
        if len(segments)==1:return self.start(args,title_id=title_id,name=name)
        if sum(s['duration_us'] for s in segments)*repeats>2**64-1:
            raise ClientError('Repeated macro duration overflows native time.')
        return self._stream(segments,title_id,name,repeats)

    def _stream(self,segments,title_id,name,repeats):
        # Prefetch one continuation before first start. Later segments are
        # queued as soon as native status observes a bank change, never timed
        # individually over the network. A missed deadline fails the run.
        self.checked(self.client.call('macro.acquire',{'title_id':title_id}),'accepted')
        try:
            first={k:v for k,v in segments[0].items() if k!='start_us'};first['start_delay_us']=1000000
            started=self.checked(self.client.call('input.submit',first),'accepted')
            next_reply=self.checked(self.client.call('macro.enqueue',segments[1]),'accepted')
        except BaseException:
            self.client.call('input.release');raise
        with self.guard:
            self.job={'state':'queued','title_id':title_id,'name':name,'execution_id':started['execution_id'],
                      'queued_execution_id':next_reply['execution_id'],'repeats':repeats,
                      'cycle_us':sum(s['duration_us'] for s in segments),'segments_per_cycle':len(segments),
                      'completed_segments':0,'total_segments':len(segments)*repeats,'native':None,'error':None}
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._stream_worker,args=(segments,repeats,started['execution_id'],next_reply['execution_id']),name='vita-macro',daemon=True)
        self.thread.start();return self.status()

    def _stream_worker(self,segments,repeats,current,queued):
        completed=0;total=len(segments)*repeats;sent=2;heartbeat=time.monotonic()
        interval=max(.05,min(1,min(s['duration_us'] for s in segments)/4000000))
        try:
            while not self.stop_event.wait(interval):
                if time.monotonic()-heartbeat>=1:
                    self.checked(self.client.call('input.heartbeat'),'accepted');heartbeat=time.monotonic()
                native=self.checked(self.client.call('input.status'),'ok')['result']
                observed=native['execution_id']
                if queued is not None and observed==queued:
                    completed+=1;current=queued;queued=None
                    if sent<total:
                        queued=self.checked(self.client.call('macro.enqueue',segments[sent%len(segments)]),'accepted')['execution_id'];sent+=1
                elif observed!=current:raise ClientError('Macro execution was replaced.')
                with self.guard:
                    self.job.update(execution_id=current,queued_execution_id=queued,native=native,completed_segments=completed,
                                    iteration=completed//len(segments),state='queued' if native['state']==1 else 'running')
                if native['state'] not in (1,2):
                    if native['state']!=3 or queued is not None or completed+1!=total:
                        raise ClientError('Macro ended before all continuation segments completed; native result '+str(native.get('error_code'))+'.')
                    with self.guard:self.job.update(state='finished',completed_segments=total,iteration=repeats)
                    break
            if self.stop_event.is_set():
                self.checked(self.client.call('input.cancel'),'accepted')
                with self.guard:self.job['state']='cancelled'
        except Exception as exc:
            with self.guard:self.job.update(state='failed',error=str(exc))
        finally:
            try:self.checked(self.client.call('input.release'),'accepted')
            except Exception as exc:
                with self.guard:self.job['release_error']=str(exc)

    def start(self, args, *, title_id=None, name='input'):
        if self.thread is not None and self.thread.is_alive():
            raise ClientError('An input job is already running.')
        args = VitaClient._command('input.submit', args)['args']
        if title_id is None:
            self.checked(self.client.call('input.acquire'), 'accepted')
        else:
            self.checked(self.client.call('macro.acquire', {'title_id': title_id}), 'accepted')
        try:
            args = {key:value for key,value in args.items() if key!='start_us'}
            args['start_delay_us']=150000
            submitted = self.checked(self.client.call('input.submit', args), 'accepted')
        except BaseException:
            self.client.call('input.release')
            raise
        with self.guard:
            self.job = {'state': 'queued', 'title_id': title_id, 'name': name,
                        'execution_id': submitted['execution_id'], 'repeats': args['repeats'],
                        'cycle_us': args['duration_us'], 'native': None, 'error': None}
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._worker, name='vita-macro', daemon=True)
        self.thread.start()
        return self.status()

    def _worker(self):
        try:
            while not self.stop_event.wait(1):
                self.checked(self.client.call('input.heartbeat'), 'accepted')
                status = self.checked(self.client.call('input.status'), 'ok')['result']
                with self.guard:
                    if status['execution_id'] != self.job['execution_id']:
                        raise ClientError('Macro execution was replaced.')
                    self.job['native'] = status
                    self.job['state'] = {1: 'queued', 2: 'running', 3: 'finished',
                                         4: 'cancelled', 5: 'lease_expired', 6: 'failed'}.get(status['state'], 'idle')
                if status['state'] not in (1, 2):
                    break
            if self.stop_event.is_set():
                self.checked(self.client.call('input.cancel'), 'accepted')
                with self.guard:self.job['state'] = 'cancelled'
        except Exception as exc:
            with self.guard:
                self.job['state'], self.job['error'] = 'failed', str(exc)
        finally:
            try:
                self.checked(self.client.call('input.release'), 'accepted')
            except Exception as exc:
                with self.guard:self.job['release_error'] = str(exc)

    def status(self):
        with self.guard:
            return {'status': 'ok', 'result': dict(self.job)}

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=25)
            if self.thread.is_alive():
                raise ClientError('Macro cleanup is still in progress; no new macro was started.')
        return self.status()
