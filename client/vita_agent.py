#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unified vita-agent-use command line. JSON output is the default."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

from vita_client import ClientError, NativeFrameError, UploadError, VitaClient, private_json, strict_json, validate_host, validate_agent_name, connection_refused_message

CONFIG_ENV = "VITA_AGENT_CONFIG_DIR"


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.epilog = 'Set VITA_AGENT_CONFIG_DIR to the directory chosen in bootstrap (containing config.json and pc/).'
    p.add_argument('--macro-store', type=Path)
    p.set_defaults(screen_off_when_done=True, vita_ip=None, agent_name=None, device_dir=None, credentials=None, state=None)
    groups = p.add_subparsers(dest='group', required=True)
    groups.add_parser('bootstrap', help='Human TUI for configuration, plugin compatibility checks and PC identity setup.')
    def group(name, help):
        return groups.add_parser(name, help=help).add_subparsers(dest='action', required=True)
    def cmd(g, name, op=None, **kw):
        c = g.add_parser(name, **kw)
        c.set_defaults(op=op)
        return c
    def listing(c):
        c.add_argument('--limit', type=int)
        c.add_argument('--page', type=int, help='Requires --limit; defaults to 1.')
    def write(c):
        c.add_argument('--yes', action='store_true')
        c.add_argument('--operation-id')
    g = group('system', 'Console metadata and reboot.')
    cmd(g, 'snapshot'); cmd(g, 'reboot', 'system.reboot'); cmd(g, 'capabilities', 'capabilities')
    g = group('session', 'Pairing, saved-PC reconnect and exact request recovery.')
    c = cmd(g, 'provision'); c.add_argument('--host'); c.add_argument('--name')
    cmd(g, 'pair'); cmd(g, 'connect'); cmd(g, 'recover')
    g = group('app', 'Installed/running apps, observed launch and close.')
    c = cmd(g, 'list', 'app.list'); c.add_argument('--query', default=''); listing(c)
    cmd(g, 'running', 'app.running')
    for a in ('launch', 'close'):
        cmd(g, a, 'app.'+a).add_argument('title_id')
    c = cmd(g, 'install', 'app.install'); c.add_argument('path', help='Vita-side .vpk path.'); write(c)
    c.add_argument('--no-wait', action='store_true', help='Return the operation ID while installation continues.')
    c.add_argument('--timeout', type=float, default=1800, help='Seconds to wait; does not cancel native promotion.')
    cmd(g, 'install-status', 'app.install.status').add_argument('operation_id')
    c = groups.add_parser('decrypt', help='Decrypt a Vita SELF to a host ELF using native authentication/PFS.')
    c.set_defaults(action='decrypt', op=None)
    c.add_argument('path', help='Vita filesystem path to eboot.bin, .self, .suprx or .skprx.')
    c.add_argument('--output', type=Path, help='New host ELF file; defaults to the source basename with .elf extension.')
    c.add_argument('--operation-id', help='Reuse this ID to inspect/resume the same native job.')
    c.add_argument('--timeout', type=float, default=1800)
    c.add_argument('--no-wait', action='store_true', help='Return the job ID; query using call decrypt.status.')
    g = group('screen', 'Display control and JPEG capture.')
    cmd(g, 'on', 'screen.on'); cmd(g, 'off', 'screen.off')
    cmd(g, 'capture').add_argument('--output', type=Path, required=True)
    g = group('fs', 'Complete listings, transfers and native write operations.')
    c = cmd(g, 'list', 'fs.list'); c.add_argument('path'); listing(c)
    c.add_argument('--sort-by', choices=('name','modified','date','size'), default='name')
    c.add_argument('--order', choices=('asc','desc','dsc'), default='asc')
    c.add_argument('--human', action='store_true', help='Print filename, modification date and size as a table.')
    cmd(g, 'stat', 'fs.stat').add_argument('path')
    c = cmd(g, 'download'); c.add_argument('path'); c.add_argument('output', type=Path)
    c = cmd(g, 'upload'); c.add_argument('source', type=Path); c.add_argument('destination')
    c.add_argument('--transfer-state', type=Path, required=True); c.add_argument('--overwrite', action='store_true')
    c.add_argument('--expected-sha256', default=''); c.add_argument('--yes', action='store_true')
    for a in ('mkdir','move','trash','purge'):
        c = cmd(g, a, 'fs.'+a); c.add_argument('path'); write(c)
        if a == 'move': c.add_argument('destination')
        if a == 'purge': c.add_argument('--trash-id', required=True)
    g = group('plugins', 'Enabled plugins grouped by taiHEN section.')
    listing(cmd(g, 'list', 'plugins.list'))
    g = group('input', 'Device-scheduled simultaneous button/touch sequences.')
    for a in ('acquire','heartbeat','status','cancel','release'): cmd(g,a,'input.'+a)
    cmd(g,'submit').add_argument('file',type=Path,help='JSON input.submit argument object; use - for stdin.')
    g = group('touch', 'Touch panel geometry and timed swipes.')
    cmd(g,'panels','touch.panels')
    c = cmd(g,'swipe'); c.add_argument('--panel',choices=('front','back'),required=True)
    c.add_argument('--from',dest='start',nargs=2,type=int,required=True)
    c.add_argument('--to',dest='end',nargs=2,type=int,required=True)
    c.add_argument('--duration-ms',type=int,required=True)
    c.add_argument('--coordinate-space',choices=('screenshot','native'),default='screenshot')
    c.add_argument('--width',type=int); c.add_argument('--height',type=int)
    g = group('macro', 'Private per-title macros; run waits until completion.')
    cmd(g,'save').add_argument('file',type=Path)
    for a in ('load','run','compile'):
        c=cmd(g,a);c.add_argument('title_id');c.add_argument('name')
        if a in ('run','compile'):c.add_argument('--repeats',type=int,default=1)
        if a=='compile':c.add_argument('--start-us',required=True)
    g = group('performance', 'CPU/FPS/memory measurements and timed watches.')
    cmd(g,'measure').add_argument('--window-ms',type=int,required=True)
    cmd(g,'watch').add_argument('--seconds',type=int,required=True)
    cmd(g,'cancel','performance.cancel')
    g = group('livearea', 'Read-only Shell layout, schema and blobs.')
    c=cmd(g,'layout','livearea.layout');c.add_argument('--section',choices=('pages','icons','all'),default='all');listing(c)
    listing(cmd(g,'schema','livearea.schema'))
    cmd(g,'blob').add_argument('file',type=Path,help='JSON blob-download arguments including output.')
    g = group('watch', 'Foreground polling watchers; not a PC push server.')
    cmd(g,'dumps');cmd(g,'dialogs')
    c=cmd(g,'log');c.add_argument('path');c.add_argument('--marker',required=True)
    for name, prefix in (('events','events'),('dialogs','dialog.events')):
        g=group(name,'Native event queue controls.')
        cmd(g,'start',prefix+'.start');cmd(g,'stop',prefix+'.stop')
        cmd(g,'read',prefix+'.read').add_argument('--after',type=int,default=0)
    g=group('acl','Native physical approval for scoped write access.')
    c=cmd(g,'request');c.add_argument('path');c.add_argument('--request-id');c.add_argument('--timeout',type=float,default=90)
    cmd(g,'status','acl.status').add_argument('request_id')
    cmd(g,'sync').add_argument('--output',type=Path,required=True)
    g=group('config','Guarded tai/config.txt review and verified apply.')
    c=cmd(g,'plan');c.add_argument('path');c.add_argument('candidate',type=Path);c.add_argument('--plan',type=Path,required=True)
    c=cmd(g,'apply');c.add_argument('--plan',type=Path,required=True);c.add_argument('--transfer-state',type=Path,required=True);c.add_argument('--yes',action='store_true')
    g=group('content','Native content inventory, export and guarded deletion.')
    c=cmd(g,'list','content.list');c.add_argument('category');listing(c)
    c=cmd(g,'export');c.add_argument('category',choices=('photo','music','video'));c.add_argument('id');c.add_argument('--output',type=Path,required=True)
    c=cmd(g,'preview');c.add_argument('identifier');c.add_argument('--kind',choices=('application','vita_savedata','photo','music','video'),default='application');c.add_argument('--user',type=int);c.add_argument('--operation-id')
    c=cmd(g,'delete');c.add_argument('plan',type=Path);c.add_argument('--yes',action='store_true');c.add_argument('--timeout',type=float,default=180)
    cmd(g,'status','content.delete.status').add_argument('operation_id')
    g=group('savedata','Vita savedata inventory.')
    c=cmd(g,'list','savedata.list');c.add_argument('--user-id',default='00');listing(c)
    g=group('audit','Mirror on-device filesystem/content audit logs to PC.')
    for a in ('fs','content'):
        c=cmd(g,a);c.add_argument('--output',type=Path,required=True);c.add_argument('--max-pages',type=int)
    g=group('diagnostics','Read-only UDP service/input/log diagnostics.')
    for a in ('status','input','log'):cmd(g,a).add_argument('--host')
    c=groups.add_parser('serve',help='Persistent PC command server and native Vita event receiver.')
    c.set_defaults(action='serve',op=None)
    g=group('server','Persistent PC server status and received event history.')
    cmd(g,'status')
    c=cmd(g,'events');c.add_argument('--after',type=int,default=0);c.add_argument('--wait',type=float,default=0);c.add_argument('--limit',type=int,default=256)
    c=cmd(g,'watch-log');c.add_argument('path');c.add_argument('--literal',required=True);c.add_argument('--once',action='store_true')
    cmd(g,'unwatch-log').add_argument('watch_id',type=int)
    c=cmd(g,'performance-start');c.add_argument('--seconds',type=int,required=True);c.add_argument('--interval-ms',type=int,default=1000)
    cmd(g,'performance-stop')
    g=group('run','Asynchronous prepare, launch, observe and close workflows.')
    c=cmd(g,'start');c.add_argument('file',type=Path);c.add_argument('--yes',action='store_true')
    cmd(g,'status');cmd(g,'cancel')
    c=groups.add_parser('call',help='Low-level JSON operation escape hatch.')
    c.set_defaults(action='call',op=None);c.add_argument('operation');c.add_argument('--args',default='{}')
    return p


def emit(value):
    print(json.dumps(value,ensure_ascii=False,separators=(',',':')),flush=True)


def read_json(path):
    data=sys.stdin.buffer.read(16777217) if str(path)=='-' else path.read_bytes()
    if len(data)>16777216:raise ClientError('JSON file exceeds 16 MiB.')
    return strict_json(data)


def native_args(a):
    keys={'app.list':('query','limit','page'),'app.launch':('title_id',),'app.close':('title_id',),'app.install.status':('operation_id',),
          'fs.list':('path','sort_by','order','limit','page'),'fs.stat':('path',),'plugins.list':('limit','page'),
          'livearea.layout':('section','limit','page'),'livearea.schema':('limit','page'),
          'content.list':('category','limit','page'),'acl.status':('request_id',),
          'savedata.list':('user_id','limit','page'),'content.delete.status':('operation_id',),'events.read':('after',),'dialog.events.read':('after',)}
    result={k:getattr(a,k) for k in keys.get(a.op,()) if getattr(a,k,None) is not None}
    if a.op=='app.install':
        result={'path':a.path,'yes':a.yes,'operation_id':a.operation_id or uuid.uuid4().hex}
    if a.op in ('fs.mkdir','fs.move','fs.trash','fs.purge'):
        result={'path':a.path,'yes':a.yes,'operation_id':a.operation_id or uuid.uuid4().hex}
        if a.op=='fs.move':result['destination']=a.destination
        if a.op=='fs.purge':result['trash_id']=a.trash_id
    if a.op=='livearea.layout' and result.get('section')=='all':
        if set(result)-{'section'}:raise ClientError('Use --section pages or icons with --limit/--page.')
        return {}
    return result


def wait_runner(runner):
    last=None
    while True:
        r=runner.status()
        state=r.get('result',r).get('state')
        if state!=last:emit(r);last=state
        if state not in ('running','queued'):return r
        time.sleep(.1)


def execute(a,c,emit_result=emit):
    if a.group=='decrypt':
        from decrypt import decrypt
        return decrypt(c,a.path,a.output,a.operation_id,a.timeout,a.no_wait,emit_result)
    if a.op=='app.install':
        import math
        if not math.isfinite(a.timeout) or a.timeout<=0:raise ClientError('Install timeout must be positive and finite.')
        args=native_args(a)
        VitaClient._command(a.op,args)
        result=c.call(a.op,args)
        if a.no_wait:return result
        deadline=time.monotonic()+a.timeout
        while result.get('status')=='ok' and result.get('result',{}).get('running'):
            if time.monotonic()>=deadline:
                return {**result,'status':'unconfirmed','message':'Installation still running; query app install-status with this operation_id.'}
            time.sleep(1)
            result=c.call('app.install.status',{'operation_id':args['operation_id']})
        return result
    if a.op:return c.call(a.op,native_args(a))
    g,action=a.group,a.action
    if g=='call':return c.call(a.operation,strict_json(a.args.encode()))
    if g=='session':return c.recover()
    if g=='system':
        from system_metadata import collect
        return {'status':'ok','result':collect(c)}
    if g=='screen':
        fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as f:
                data,meta=c.frame();f.write(data)
        except BaseException:
            a.output.unlink();raise
        return {'status':'ok','file':str(a.output),'bytes':len(data),**meta}
    if g=='fs':
        if action=='download':return c.download(a.path,a.output)
        from upload import upload
        return upload(c,a.source,a.destination,a.transfer_state,a.overwrite,a.expected_sha256,a.yes,progress=emit_result)
    if g in ('macro','touch','input'):
        from macro_runner import MacroRunner
        runner=MacroRunner(c,a.macro_store or a.state.parent/'macros')
        try:
            if g=='touch':
                from swipes import swipe_plan
                args={'panel':a.panel,'from':a.start,'to':a.end,'duration_ms':a.duration_ms,'coordinate_space':a.coordinate_space}
                for k in ('width','height'):
                    if getattr(a,k) is not None:args[k]=getattr(a,k)
                runner.start(swipe_plan(c,args),name='swipe')
            elif g=='input':runner.start(read_json(a.file),name='input')
            elif action=='run':runner.run(a.title_id,a.name,a.repeats)
            else:raise ClientError('Local macro operation was not dispatched.')
            return wait_runner(runner)
        finally:runner.stop()
    if g=='performance':
        from performance import collect
        for sample in collect(c,window_ms=a.window_ms if action=='measure' else None,duration_s=a.seconds if action=='watch' else None):emit_result(sample)
        return None
    if g=='livearea':
        from livearea import download_blob
        return download_blob(c,read_json(a.file))
    if g=='watch':
        from event_listener import EventListener
        guard=threading.Lock()
        def event(value):
            with guard:emit_result({'event':value})
        w=EventListener(c,event)
        try:
            emit_result(w.start())
            if action=='log':emit_result(w.log_start(a.path,a.marker))
            while True:
                time.sleep(.5)
                r=w.status()
                if r['result']['state']!='running':return r
        finally:w.stop()
    if g=='acl':
        from request_acl import sync_audit
        if action=='sync':sync_audit(c,a.output);return {'status':'ok','file':str(a.output)}
        rid=a.request_id or uuid.uuid4().hex
        r=c.call('acl.status',{'request_id':rid}) if a.request_id else c.call('acl.request',{'request_id':rid,'path':a.path})
        emit_result(r);deadline=time.monotonic()+a.timeout
        while r.get('status')=='ok' and r['result']['state']=='pending' and time.monotonic()<deadline:
            time.sleep(1);r=c.call('acl.status',{'request_id':rid})
        return r
    if g=='config':
        from tai_config import prepare,apply
        return prepare(c,a.path,a.candidate,a.plan) if action=='plan' else apply(c,a.plan,a.transfer_state,a.yes)
    if g=='content':
        if action=='export':
            from content import export_media
            return export_media(c,{'category':a.category,'id':a.id,'output':str(a.output)})
        from content_delete import preview,request_delete
        if action=='delete':return request_delete(c,read_json(a.plan),a.yes,True,a.timeout)
        args={'operation_id':a.operation_id or uuid.uuid4().hex}
        if a.kind in ('photo','music','video'):args.update(kind=a.kind,media_id=a.identifier)
        else:
            args['title_id']=a.identifier
            if a.kind=='vita_savedata':args.update(kind=a.kind,user=a.user)
        return preview(c,args)
    if g=='audit':
        if action=='fs':
            from audit_sync import AuditMirror
            mirror=AuditMirror(a.output,c.pin)
        else:
            from content_delete import ContentAuditMirror
            mirror=ContentAuditMirror(a.output,c.pin)
        try:return mirror.sync(c,a.max_pages if a.max_pages is not None else (1000 if action=='fs' else None))
        finally:mirror.close()
    raise ClientError('Unsupported command.')



def selected_config():
    value = os.environ.get(CONFIG_ENV)
    if not value or not value.strip() or '\0' in value:
        raise ClientError('Set VITA_AGENT_CONFIG_DIR to the directory chosen in bootstrap (containing config.json and pc/).')
    folder = Path(value).expanduser()
    if not folder.is_absolute():
        raise ClientError('VITA_AGENT_CONFIG_DIR must be an absolute directory path.')
    if not folder.is_dir():
        raise ClientError('VITA_AGENT_CONFIG_DIR is not an existing directory: ' + str(folder))
    return folder.resolve() / 'config.json'


def load_config(options):
    """Read config.json from the directory selected only by the environment."""
    config_path = selected_config()
    if not config_path.exists():
        raise ClientError('Missing client config: ' + str(config_path) + '. Run bootstrap and export VITA_AGENT_CONFIG_DIR to its chosen directory.')
    config = private_json(config_path)
    keys = {'device_dir', 'credentials', 'state', 'macro_store', 'screen_off_when_done', 'vita_ip', 'agent_name'}
    if not isinstance(config, dict) or not config or set(config) - keys:
        raise ClientError('Client config must contain device_dir or credentials/state paths.')
    for key, value in config.items():
        if key in ('vita_ip', 'agent_name'):
            (validate_host if key == 'vita_ip' else validate_agent_name)(value)
            setattr(options,key,value)
            continue
        if key == 'screen_off_when_done':
            if type(value) is not bool:raise ClientError('screen_off_when_done must be true or false.')
            options.screen_off_when_done=value
            continue
        if not isinstance(value, str) or not value or '\0' in value:
            raise ClientError('Client config paths must be nonempty strings.')
        if getattr(options, key) is None:
            path = Path(value).expanduser()
            setattr(options, key, path if path.is_absolute() else (config_path.parent / path).resolve())
    if not options.device_dir and not (options.credentials and options.state):
        raise ClientError('Client config requires device_dir or both credentials and state.')


def connection_options(options):
    result={}
    if options.vita_ip is not None:result['host']=options.vita_ip
    if options.agent_name is not None:result['agent_name']=options.agent_name
    return result


def main(argv=None):
    p=parser();a=p.parse_args(argv)
    if getattr(a,'page',None) is not None and getattr(a,'limit',None) is None:p.error('--page requires --limit')
    for key in ('limit','page','repeats'):
        if getattr(a,key,None) is not None and getattr(a,key)<1:p.error('--'+key+' must be positive')
    client=None
    try:
        if a.group=='bootstrap':
            from bootstrap import run
            run();return 0
        if not (a.group=='diagnostics' and a.host):load_config(a)
        if a.device_dir:
            a.credentials=a.credentials or a.device_dir/'pc/credentials.json'
            a.state=a.state or a.device_dir/'pc/state.json'
        if a.group=='diagnostics':
            from diagnose_vita import query
            host=a.host or a.vita_ip or (private_json(a.credentials)['host'] if a.credentials else None)
            if not host:p.error('diagnostics requires --host or credentials')
            emit(query(host,input_sample=a.action=='input',logging=a.action=='log'));return 0
        if a.group=='session' and a.action in ('provision','pair','connect'):
            if not a.device_dir:p.error('session setup requires device_dir in config.json')
            import pair_vita
            pair_vita.BASE=a.device_dir.resolve()
            reused=False
            with contextlib.redirect_stdout(sys.stderr):
                if a.action=='provision':
                    host=a.host or a.vita_ip
                    if not host:raise ClientError('Set vita_ip in the selected config or pass --host.')
                    pair_vita.provision(host,a.name or a.agent_name or 'Agent')
                else:
                    if a.action=='pair' and not (pair_vita.BASE/'pc/pairing.json').exists():
                        host=a.vita_ip
                        if not host:raise ClientError('Set vita_ip in the selected config.')
                        pair_vita.provision(host,a.agent_name or 'Agent')
                    try:
                        creds=pair_vita.pair(resume=a.action=='connect',**connection_options(a))
                    except ConnectionRefusedError:
                        if a.action!='connect' or not a.credentials.exists():
                            raise
                        # A stopped serve can leave its token and command listener
                        # alive while the fresh-session port is closed. Reuse the
                        # exact credentials/state; never mint IDs past a pending effect.
                        client=VitaClient(private_json(a.credentials),a.state,timeout=20,
                                          screen_off_when_done=a.screen_off_when_done,**connection_options(a))
                        reply=client.call('capabilities')
                        if reply.get('status')!='ok':
                            raise ClientError('Saved command session was rejected; start serve or wait for the session to expire.')
                        reused=True
                    if not reused:
                        client=pair_vita.wait_for_commands(creds,screen_off_when_done=a.screen_off_when_done)
            emit({'status':'ok','result':{'session':'reused'}} if reused else {'status':'ok'});return 0
        if not a.state:raise ClientError('Set device_dir or state in the selected config.')
        if a.group=='macro' and a.action in ('save','load','compile'):
            from macros import MacroStore,compile_macro
            store=MacroStore(a.macro_store or a.state.parent/'macros')
            if a.action=='save':r={'status':'ok','file':str(store.save(read_json(a.file)))}
            else:
                macro=store.load(a.title_id,a.name)
                r={'status':'ok','result':macro if a.action=='load' else compile_macro(macro,start_us=a.start_us,repeats=a.repeats)}
            emit(r);return 0
        if not a.credentials:raise ClientError('Set device_dir or credentials in the selected config.')
        import server
        if a.group=='serve':
            server.AgentServer(a).serve();return 0
        if a.group in ('server','run'):
            if a.group=='run':
                method='run.'+a.action
                args=read_json(a.file) if a.action=='start' else {}
                if a.action=='start':
                    if not isinstance(args,dict):raise ClientError('Run file must contain an object.')
                    if 'yes' in args:raise ClientError('Express installation/overwrite intent with run start --yes.')
                    args['yes']=a.yes
                    for value in args.get('prepare',{}).values():
                        if isinstance(value,dict) and 'source' in value:value['source']=str(Path(value['source']).expanduser().resolve())
            elif a.action=='performance-start':method,args='performance.start',{'duration_s':a.seconds,'interval_ms':a.interval_ms}
            elif a.action=='performance-stop':method,args='performance.stop',{}
            elif a.action=='events':method,args='events.read',{'after':a.after,'timeout':a.wait,'limit':a.limit}
            elif a.action=='watch-log':method,args='watch.log.start',{'path':a.path,'literal':a.literal,'once':a.once}
            elif a.action=='unwatch-log':method,args='watch.log.stop',{'watch_id':a.watch_id}
            else:method,args='server.status',{}
            r=server.request(a,method,args);emit(r);return 0 if r.get('status')=='ok' else 1
        if server.running(a):
            values=vars(a).copy()
            for key,value in list(values.items()):
                if isinstance(value,Path) and str(value)!='-':values[key]=str(value.resolve())
            if any(str(getattr(a,key,None))=='-' for key in ('file',)):
                raise ClientError('Use a JSON file when submitting commands to the PC server.')
            r=server.request(a,'execute',values,emit_progress=emit)
            if r is not None:emit(r)
            return 1 if r is not None and (r.get('status') in ('error','client_error','unconfirmed') or r.get('code',0) or r.get('state')=='failed' or r.get('result',{}).get('state')=='failed') else 0
        client=VitaClient(private_json(a.credentials),a.state,timeout=20,screen_off_when_done=a.screen_off_when_done,**connection_options(a))
        r=execute(a,client)
        client.close();client=None
        if r is not None:
            if a.group=='fs' and a.action=='list' and a.human and r.get('status')=='ok':
                info=r['result'];print(info['path']);print('Filename\tDate modified\tSize')
                for e in info['entries']:print(f"{e['name']}\t{e.get('modified') or 'unknown'}\t{'folder' if e['kind']=='directory' else e['bytes']+' B'}")
                print(str(info['entry_count'])+' entries')
            else:emit(r)
            return 1 if r.get('status') in ('error','client_error','unconfirmed') or r.get('code',0) or r.get('state')=='failed' or r.get('result',{}).get('state')=='failed' else 0
        return 0
    except KeyboardInterrupt:return 130
    except UploadError as e:
        emit(e.as_result());return 1
    except NativeFrameError as e:
        emit(e.as_result());return 1
    except ConnectionRefusedError:
        emit({'status':'client_error','message':connection_refused_message()});return 1
    except (ClientError,OSError,ValueError,TypeError) as e:
        emit({'status':'client_error','message':str(e)});return 1
    finally:
        if client is not None:
            try:client.close()
            except (ClientError,OSError) as e:print('Screen cleanup failed: '+str(e),file=sys.stderr)


if __name__=='__main__':
    raise SystemExit(main())
