# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete native Shell page/icon inventory plus the native iconlayout file."""
from vita_client import ClientError
from pathlib import Path
import hashlib
import os
import re
INI_PATH='ux0:iconlayout.ini' # Verified literal in 3.65 SceShell's livespace_db module.
def download_blob(client,args):
    """Stream a selected native blob to a host file without embedding pixels in JSON."""
    from vita_client import VitaClient
    if not isinstance(args,dict) or set(args)!={'section','page_id','position','column','output'} or not isinstance(args['output'],str) or not args['output']:
        raise ClientError('livearea.blob.download requires section, page_id, position, column and host output.')
    query={key:value for key,value in args.items() if key!='output'}
    query['offset']=0
    VitaClient._command('livearea.blob',query)
    path=Path(args['output'])
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    total=None;digest=hashlib.sha256()
    try:
        with os.fdopen(fd,'wb') as stream:
            while True:
                reply=client.call('livearea.blob',query)
                if reply.get('status')!='ok':raise ClientError('Native LiveArea blob read rejected.')
                result=reply.get('result',{});size=result.get('bytes');chunk=result.get('chunk',{})
                if not isinstance(size,str) or not re.fullmatch('0|[1-9][0-9]*',size):raise ClientError('Invalid native blob size.')
                size=int(size)
                if size>2**31-1 or (total is not None and size!=total):raise ClientError('LiveArea blob size changed or exceeds the native offset range.')
                total=size
                text=chunk.get('data') if isinstance(chunk,dict) else None
                if not isinstance(chunk,dict) or chunk.get('encoding')!='hex' or chunk.get('storage_type')!='blob' or not isinstance(text,str) or not re.fullmatch('[0-9a-f]*',text) or len(text)%2:
                    raise ClientError('Invalid native blob bytes.')
                data=bytes.fromhex(text);at=query['offset'];end=at+len(data)
                if len(data)!=min(512,total-at) or type(result.get('offset')) is not int or result['offset']!=at or type(result.get('next_offset')) is not int or result['next_offset']!=end or type(result.get('more')) is not bool or result['more']!=(end<total):
                    raise ClientError('Native blob read did not advance consistently.')
                stream.write(data);digest.update(data)
                if end==total:break
                query['offset']=end
            stream.flush();os.fsync(stream.fileno())
    except BaseException:
        path.unlink()
        raise
    return {'status':'ok','result':{'source':'native_livearea_database','file':str(path),'bytes':str(total),'sha256':digest.hexdigest(),'snapshot':False,
            'section':args['section'],'page_id':args['page_id'],'position':args['position'],'column':args['column']}}
def parse_ini(data):
    encoding='utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
    try:text=data.decode(encoding)
    except UnicodeError:return {'encoding':'hex','data':data.hex(),'parsed':False}
    sections=[];entries=[];unparsed=[]
    sections.append({'name':'','entries':entries})
    for number,line in enumerate(text.splitlines(),1):
        value=line.strip()
        if not value or value.startswith((';','#')):continue
        if value.startswith('[') and value.endswith(']'):
            entries=[];sections.append({'name':value[1:-1],'entries':entries})
        elif '=' in value:
            key,item=value.split('=',1);entries.append({'key':key.strip(),'value':item.strip()})
        else:unparsed.append({'line':number,'text':line})
    return {'encoding':encoding,'parsed':not unparsed,'sections':sections,'unparsed_lines':unparsed}

def layout(client,args):
    if set(args)-{'include_iconlayout_ini'} or type(args.get('include_iconlayout_ini',True)) is not bool:
        raise ClientError('Layout takes optional include_iconlayout_ini boolean, or a pages/icons section listing.')
    pages=client.list_entries('livearea.layout',{'section':'pages'})['result']['entries']
    icons=client.list_entries('livearea.layout',{'section':'icons'})['result']['entries']
    grouped=[{**page,'icons':[]} for page in pages];by_id={p['page_id']:p for p in grouped};orphan=[]
    if len(by_id)!=len(grouped):raise ClientError('LiveArea page IDs changed/repeated during listing.')
    for icon in icons:
        page=by_id.get(icon['page_id'])
        (page['icons'] if page is not None else orphan).append(icon)
    for section,rows in [('pages',grouped),('icons',icons)]:
        for row in rows:
            for field in ('reserved01','reserved02','reserved03','reserved04','reserved05'):
                blob=row.get(field)
                if isinstance(blob,dict) and blob.get('storage_type')=='blob' and blob.get('data_included') is False:
                    blob['read']={'op':'livearea.blob','args':{'section':section,'page_id':row['page_id'],
                                 'position':row.get('position',0),'column':field,'offset':0}}
    result={'source' :'native_livearea_database','path':'ur0:shell/db/app.db','snapshot':False,
            'pages':grouped,'page_count':len(pages),'icon_count':len(icons),'orphan_icons':orphan}
    if args.get('include_iconlayout_ini',True):
        info=client.call('fs.stat',{'path':INI_PATH})
        ini={'path':INI_PATH,'present':info.get('status')=='ok','source_role':'configuration_file'}
        if not ini['present']:ini['error']=info.get('error',info.get('result'))
        else:
            data=bytearray();revision=None
            while True:
                chunk,meta=client.file_chunk(INI_PATH,len(data),16384)
                if meta['file_bytes']>1024*1024:raise ClientError('iconlayout.ini exceeds the 1 MiB host parsing budget; use file download.')
                current=(meta['file_bytes'],meta['modified'])
                if revision is not None and current!=revision:raise ClientError('iconlayout.ini changed while reading; retry layout.')
                revision=current;data.extend(chunk)
                if len(data)==meta['file_bytes']:break
                if not chunk:raise ClientError('iconlayout.ini read did not advance.')
            ini.update(bytes=str(len(data)),modified=revision[1],**parse_ini(bytes(data)))
        result['iconlayout_ini']=ini
    return {'status':'ok','result':result}
