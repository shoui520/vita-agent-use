# SPDX-License-Identifier: GPL-3.0-or-later
"""Vita-specific save inventory; Content Manager does not manage these saves."""
import re
from vita_client import ClientError

def inventory(client,args):
    if not isinstance(args,dict) or set(args)-{'user_id','limit','page'}:
        raise ClientError('savedata.list takes optional user_id, limit and page.')
    user=args.get('user_id','00');limit=args.get('limit');page=args.get('page',1)
    if not isinstance(user,str) or not re.fullmatch('[0-9]{2}',user):
        raise ClientError('user_id must be the two-digit native user directory name.')
    if 'limit' in args and (type(limit) is not int or limit<1):raise ClientError('limit must be positive.')
    if type(page) is not int or page<1 or ('page' in args and limit is None):raise ClientError('page requires a positive limit and starts at 1.')
    root='ux0:user/'+user+'/savedata'
    saves=client.call('fs.list',{'path':root,'sort_by':'name'})
    if saves.get('status')!='ok':raise ClientError('Vita savedata directory could not be read.')
    apps=client.call('app.list')
    if apps.get('status')!='ok':raise ClientError('Native installed-title registry could not be read.')
    titles={row['title_id']:row for row in apps['result']['entries']}
    entries=[]
    for row in saves['result']['entries']:
        if row['kind']!='directory':continue
        name=row['name'];title=titles.get(name)
        entries.append({'save_id':name,'path':root+'/'+name,'name':title['name'] if title else name,
                        'installed':title is not None,'title_id':title['title_id'] if title else None,
                        'modified':row.get('modified'),'bytes':None,'size_measured':False})
    total=len(entries);start=(page-1)*limit if limit is not None else 0
    entries=entries[start:start+limit] if limit is not None else entries
    result={'source':'native_filesystem_and_shell_registry','category':'vita_savedata','path':root,'user_id':user,
            'snapshot':False,'entries':entries,'entry_count':len(entries),'total_entries':total,'complete':limit is None or page==1 and len(entries)==total,
            'payload_representation':'on_disk','decrypted_export_supported':False}
    if limit is not None:result['pagination']={'limit':limit,'page':page,'has_more':start+limit<total}
    return {'status':'ok','result':result}
