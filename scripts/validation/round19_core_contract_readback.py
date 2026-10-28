#!/usr/bin/env python3
"""New-runtime full verification of an immutable old core result copy.

Not a new export/capacity run. Runs sequentially with the matrix, never alongside.
Private read capability stays in process memory and inherited stdin.
"""
import argparse
import json
from pathlib import Path
import secrets
import shutil
import time

import round19_core_matrix as matrix


def run(source,output,image):
    source=Path(source).resolve();root=Path(output).resolve()
    if not root.is_relative_to(Path('/private/tmp')):raise ValueError('new_private_tmp_required')
    root.mkdir(mode=0o700,parents=True,exist_ok=False)
    started=time.monotonic();deadline=started+matrix.LIMITS['wall_seconds']
    original=matrix.file_inventory(source/'result/artifact')
    record={'version':'core-contract-old-result-readback-1','scope':'new contract runtime verifies old immutable result; not new export or six-cell capacity acceptance',
        'run_id':'contract-readback-'+secrets.token_hex(4),'status':'running','phases':[],'limits':matrix.LIMITS,
        'runtime_source_sha256':matrix.runtime_sources(),'image':image,'original_artifact_inventory':original}
    key=secrets.token_bytes(32)
    try:
        shutil.copytree(source/'input',root/'input');shutil.copytree(source/'result',root/'result')
        (root/'harness').mkdir()
        for name in ('round19_core_cell.py','round19_core_oracle.py','round19_core_guards.py'):
            shutil.copyfile(matrix.ROOT/'scripts/validation'/name,root/'harness'/name)
        old=json.loads((root/'result/artifact/run_manifest.json').read_text());record['old_run_id']=old['run_id']
        approval=matrix.run_container(root,'verify',old['mode'],image,root/'input',key,None,deadline,record)
        matrix.run_container(root,'query',old['mode'],image,root/'input',key,approval,deadline,record)
        if matrix.file_inventory(root/'result/artifact')!=original or matrix.file_inventory(source/'result/artifact')!=original:
            raise ValueError('old_artifact_changed')
        record.update(status='passed',original_and_copy_bytes_unchanged=True)
    except BaseException as error:
        record.update(status='failed',error_type=type(error).__name__,reason=str(error));raise
    finally:
        record['whole_seconds']=time.monotonic()-started
        if record['whole_seconds']>matrix.LIMITS['wall_seconds'] and record['status']=='passed':
            record.update(status='failed',reason='readback_chain_deadline')
        matrix.write(root/'report.json',record)
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','image'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();result=run(args.source,args.output,args.image)
    print(json.dumps({'status':result['status'],'whole_seconds':result['whole_seconds']}))
    raise SystemExit(0 if result['status']=='passed' else 1)
