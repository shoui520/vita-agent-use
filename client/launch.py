# SPDX-License-Identifier: GPL-3.0-or-later
"""Native launch acknowledgement followed by observed title confirmation."""
import time
from vita_client import ClientError, VitaClient

def launch(client, args, *, timeout=20, interval=0.25, sleep=time.sleep, clock=time.monotonic, close_settle=1.0):
    VitaClient._command('app.launch', args) # validate before closing anything
    title=args['title_id'];deadline=clock()+timeout
    closed=[]
    running=client._call_raw('app.running',{})
    if running.get('status')!='ok':raise ClientError('Cannot inventory running apps before launch.')
    entries=running['result']['entries']
    # Close native application records, including a suspended game. Shell itself
    # is never in this title-ID-only list. No process kill or filesystem writes.
    for entry in entries:
        reply=client._call_raw('app.close',{'title_id':entry['title_id']})
        if reply.get('status')!='accepted':
            return {'status':'error','error':{'message':'Conflicting app close was rejected.'},'result':{'expected_title_id':title,'closed':closed,'close_reply':reply}}
        closed.append(entry['title_id'])
    if entries:
        while True:
            reply=client._call_raw('app.running',{})
            if reply.get('status')!='ok':raise ClientError('Cannot confirm conflicting app termination.')
            if not reply['result']['entries']:break
            if clock()>=deadline:
                return {'status':'unconfirmed','result':{'phase':'closing','expected_title_id':title,'closed':closed,'remaining':reply['result']['entries']}}
            sleep(interval)
        # Native records disappear before Shell's close transition finishes.
        # Observed immediate relaunch can acknowledge but leave LiveArea active.
        sleep(close_settle)
    acknowledged=client._call_raw('app.launch',args)
    if acknowledged.get('status')!='accepted':return {**acknowledged,'result':{'expected_title_id':title,'closed':closed}}
    # Acknowledgement is retained separately even if observation times out.
    deadline=clock()+timeout
    while True:
        snapshot=client._call_raw('system.snapshot',{})
        if snapshot.get('status')!='ok':raise ClientError('Launch accepted but foreground observation failed.')
        foreground=snapshot['result']['foreground']
        confirmed=foreground.get('title_id')==title and foreground.get('error_code')==0
        if confirmed or clock()>=deadline:
            return {'status':'ok' if confirmed else 'unconfirmed',
                    'result':{'confirmed':confirmed,'expected_title_id':title,
                              'observed_title_id':foreground.get('title_id'),
                              'foreground':foreground,'closed':closed,'acknowledgement':acknowledged}}
        sleep(interval)
