"""Explicit core-only compact storage CLI; no service/Worker authority."""
import argparse
import io
import json
import os
import sqlite3
import time

from . import shared_export as core
from .pipeline import json_chunks


def _fd_bytes(number,maximum):
    if type(number) is not int or number<0:raise ValueError('explicit_inherited_fd_required')
    result=bytearray()
    with os.fdopen(number,'rb',closefd=True) as stream:
        while len(result)<=maximum:
            chunk=stream.read(min(4096,maximum+1-len(result)))
            if not chunk:break
            result.extend(chunk)
    if len(result)>maximum:raise ValueError('inherited_fd_byte_limit')
    return bytes(result)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    parser.add_argument('--action',required=True,choices=('export','verify','metadata','page','graph','selection','evidence','snapshot','revisions'))
    parser.add_argument('--network',action='append');parser.add_argument('--process');parser.add_argument('--profile')
    parser.add_argument('--mode',choices=('offline','replay'),default='offline');parser.add_argument('--run-id');parser.add_argument('--attempt-id',type=int,default=1)
    parser.add_argument('--seconds',type=int,default=1800)
    parser.add_argument('--logical-root');parser.add_argument('--path',default='[]');parser.add_argument('--offset',type=int,default=0);parser.add_argument('--limit',type=int,default=100)
    parser.add_argument('--snapshot',type=int);parser.add_argument('--after',type=int,default=0)
    parser.add_argument('--operation');parser.add_argument('--change');parser.add_argument('--trigger',action='store_true')
    parser.add_argument('--ref-offset',type=int,default=0);parser.add_argument('--ref-limit',type=int,default=100)
    parser.add_argument('--issue-approval',action='store_true');parser.add_argument('--authority-key-fd',type=int);parser.add_argument('--approval-fd',type=int)
    args=parser.parse_args()
    try:
        if not 1<=args.seconds<=1800:raise ValueError('core_deadline_outside_budget')
        deadline=time.monotonic()+args.seconds
        key=None;approval=None
        if args.authority_key_fd is not None:
            key=_fd_bytes(args.authority_key_fd,32)
            if len(key)!=32:raise ValueError('core_approval_key_invalid')
        if args.approval_fd is not None:
            approval=json.loads(_fd_bytes(args.approval_fd,65536))
        if args.action=='export':
            if not args.network or args.process is None or args.profile is None:raise ValueError('export_inputs_required')
            if args.issue_approval or approval is not None or key is not None:raise ValueError('export_cannot_issue_approval')
            value={'manifest':core.export_task(args.network,args.process,args.profile,args.root,run_id=args.run_id,attempt_id=args.attempt_id,mode=args.mode,deadline=deadline)}
        elif args.action=='verify':
            if approval is not None:raise ValueError('source_verifier_cannot_consume_read_approval')
            if args.issue_approval:
                if key is None:raise ValueError('approval_authority_key_fd_required')
                issued=core.issue_approval(args.root,key,deadline=deadline)
                manifest=core.read_json(os.path.join(args.root,'run_manifest.json'),65536)
                value={'verification':'source_replayed_storage_and_business_fields_verified','manifest':manifest,'approval':issued}
            else:
                if key is not None:raise ValueError('authority_key_requires_issue_approval')
                value={'verification':'source_replayed_storage_and_business_fields_verified','manifest':core.verify_task(args.root,deadline=deadline)}
        else:
            if args.issue_approval:raise ValueError('only_full_source_verify_can_issue_approval')
            if (approval is None)!=(key is None):raise ValueError('read_approval_and_authority_key_required_together')
            keywords=dict(deadline=deadline,approval=approval,authority_key=key)
            if args.action=='metadata':value=core.metadata_task(args.root,**keywords)
            elif args.action in ('selection','evidence'):
                value=core.query_task(args.root,operation_id=args.operation,change_id=args.change,snapshot=args.snapshot,trigger=args.trigger,ref_offset=args.ref_offset,ref_limit=args.ref_limit,**keywords)
            else:
                if approval is None:core.verify_task(args.root,deadline=deadline)
                with core.open_reader(args.root,**keywords) as reader:
                    if args.action=='page':
                        if args.logical_root not in {row['name'] for row in reader.run_manifest['logical_artifacts']}:raise KeyError('unknown_logical_root')
                        path=json.loads(args.path)
                        value=reader.page(args.logical_root,path=path,offset=args.offset,limit=args.limit)
                    elif args.action=='graph':value={'storage_format':core.FORMAT,'graph':reader.get('graph.json')}
                    elif args.action=='snapshot':
                        if reader.run_manifest['mode']!='replay' or args.snapshot is None or args.snapshot<0:raise ValueError('explicit_replay_snapshot_required')
                        value=reader.get('history/snapshots',path=[args.snapshot])
                    elif args.action=='revisions':
                        if reader.run_manifest['mode']!='replay' or args.after<0:raise ValueError('replay_revisions_required')
                        value=reader.page('history/revisions',offset=args.after,limit=args.limit)
                    else:raise ValueError('unsupported_core_action')
        output=io.BytesIO()
        for chunk in json_chunks(value):
            if output.tell()+len(chunk)+1>core.QUERY_BYTES:raise ValueError('shared_cli_output_limit')
            output.write(chunk)
        print(output.getvalue().decode())
    except (ValueError,KeyError,TypeError,OSError,sqlite3.Error) as error:
        parser.exit(2,json.dumps({'status':'failed','error_type':type(error).__name__,'reason':str(error)},sort_keys=True)+'\n')


if __name__=='__main__':main()
