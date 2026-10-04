# SPDX-License-Identifier: GPL-3.0-or-later
"""Preview, request, or observe native application or Vita savedata deletion."""
import argparse
import json
from pathlib import Path
import secrets
from content_delete import preview, request_delete
from vita_client import VitaClient, private_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials',type=Path,required=True)
    parser.add_argument('--state',type=Path,required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    plan=commands.add_parser('preview');plan.add_argument('title_id');plan.add_argument('--operation-id')
    plan.add_argument('--kind',choices=('application','vita_savedata'),default='application')
    plan.add_argument('--user',type=int)
    execute=commands.add_parser('request');execute.add_argument('plan',type=Path);execute.add_argument('--yes',action='store_true');execute.add_argument('--timeout',type=float,default=180)
    status=commands.add_parser('status');status.add_argument('operation_id')
    args=parser.parse_args()
    client=VitaClient(private_json(args.credentials),args.state)
    try:
        if args.command=='preview':
            request={'operation_id':args.operation_id or secrets.token_hex(16),'title_id':args.title_id}
            if args.kind=='vita_savedata':
                if args.user is None or not 0<=args.user<64:parser.error('vita_savedata requires --user 0..63')
                request.update(kind=args.kind,user=args.user)
            elif args.user is not None:parser.error('--user applies only to vita_savedata')
            reply=preview(client,request)
        elif args.command=='request':reply=request_delete(client,json.loads(args.plan.read_text()),args.yes,True,args.timeout)
        else:reply=client.call('content.delete.status',{'operation_id':args.operation_id})
        print(json.dumps(reply,ensure_ascii=False,indent=2))
    finally:client.close()


if __name__=='__main__':main()
