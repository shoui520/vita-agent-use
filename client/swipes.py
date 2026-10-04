# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile screenshot/native-coordinate swipes to the on-device touch timeline."""
from vita_client import ClientError

def map_point(point, width, height, geometry):
    if not isinstance(point, list) or len(point)!=2 or any(type(v) is not int for v in point):
        raise ClientError('Touch point must be [x,y] integers.')
    x,y=point
    if type(width) is not int or type(height) is not int or width<2 or height<2 or not 0<=x<width or not 0<=y<height:
        raise ClientError('Touch point is outside the supplied screenshot dimensions.')
    return [geometry['min_x']+(x*(geometry['max_x']-geometry['min_x'])+(width-1)//2)//(width-1),
            geometry['min_y']+(y*(geometry['max_y']-geometry['min_y'])+(height-1)//2)//(height-1)]

def compile_swipe(args, panel, start_us):
    allowed={'panel','from','to','duration_ms','coordinate_space','width','height','id','force','interval_ms'}
    if not isinstance(args,dict) or set(args)-allowed or not {'panel','from','to','duration_ms'}<=set(args):
        raise ClientError('Swipe requires panel, from, to, duration_ms.')
    if args['panel'] not in ('front','back') or panel['error_code'] or panel['name']!=args['panel']:
        raise ClientError('Touch panel geometry is unavailable.')
    duration=args['duration_ms'];interval=args.get('interval_ms',16)
    if type(duration) is not int or not 16<=duration<=60000 or type(interval) is not int or not 8<=interval<=1000:
        raise ClientError('Swipe duration must be 16..60000 ms, interval 8..1000 ms.')
    space=args.get('coordinate_space','screenshot')
    if space=='screenshot':
        if not {'width','height'}<=set(args):raise ClientError('Screenshot coordinates require actual width and height.')
        a=map_point(args['from'],args['width'],args['height'],panel['geometry']['display'])
        b=map_point(args['to'],args['width'],args['height'],panel['geometry']['display'])
    elif space=='native':
        a,b=args['from'],args['to'];g=panel['geometry']['active']
        for point in (a,b):
            if not isinstance(point,list) or len(point)!=2 or any(type(v) is not int for v in point) or not g['min_x']<=point[0]<=g['max_x'] or not g['min_y']<=point[1]<=g['max_y']:
                raise ClientError('Native touch point is outside panel geometry.')
    else:raise ClientError('coordinate_space must be screenshot or native.')
    interval=min(interval,duration//2)
    moving=duration-interval
    steps=(moving+interval-1)//interval
    if steps+2>1024:raise ClientError('Swipe exceeds 1024 states; increase interval_ms.')
    finger,force=args.get('id',0),args.get('force',128)
    if type(finger) is not int or not 0<=finger<=127 or type(force) is not int or not panel['geometry']['force']['min']<=force<=panel['geometry']['force']['max']:
        raise ClientError('Invalid finger ID or force.')
    events=[]
    for i in range(steps+1):
        at=min(i*interval,moving)
        point=[a[j]+((b[j]-a[j])*at)//moving for j in range(2)]
        events.append({'at_us':at*1000,args['panel']:[{'id':finger,'x':point[0],'y':point[1],'force':force}]})
    # Endpoint contact lasts one device sampling interval before release.
    released=duration*1000
    events.append({'at_us':released,args['panel']:[]})
    return {'start_us':str(start_us),'duration_us':released+interval*1000,'repeats':1,
            'max_lateness_us':100000,'events':events}

def swipe_plan(client,args):
    panels=client.call('touch.panels')
    if panels.get('status')!='ok':raise ClientError('Cannot read native panel geometry.')
    panel=next((p for p in panels['result']['panels'] if p['name']==args.get('panel')),None)
    if panel is None:raise ClientError('panel must be front or back.')
    # Pure validation before taking over any input lease.
    return compile_swipe(args,panel,0)
