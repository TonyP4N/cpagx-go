#!/usr/bin/env python3
"""Package an existing terminal S100 snapshot without rerunning analysis.

Source files and evidence are read-only; a new PG is populated from retained SQL
and the production terminal backup audits make a reusable source bundle.
"""
import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import round19_formal_service_acceptance as formal
r = formal.r

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();source=args.source.resolve();work=args.output.resolve()
    work.mkdir(mode=0o700,parents=True,exist_ok=False)
    state=json.loads((source/'state.json').read_text())
    pg='cpag-r20-s100-import-'+secrets.token_hex(4)
    r.run('docker','run','--name',pg,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only',r.PG_IMAGE,stdout=subprocess.DEVNULL)
    try:
        for _ in range(150):
            if subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('postgres_readiness_timeout')
        with (source/'database.sql').open('rb') as stream, (work/'import.log').open('wb') as log:
            r.bundle.pg(pg,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=stream,stdout=log,stderr=subprocess.STDOUT)
        root=Path(state['source_root']);control=Path(state['control_root'])
        if r.bundle.inventory(root)!=r.bundle.inventory(source/'source') or r.bundle.inventory(control)!=r.bundle.inventory(source/'control'):
            raise RuntimeError('original_retained_snapshot_changed_since_archive')
        snapshot=r.bundle.backup(pg,'m4_validation',root,work/'bundle',control_root=control,maintenance=True)
        if snapshot['format_version']!=7:raise RuntimeError('terminal_format7_required')
        for original,target in [('state.json','state.json'),('app-initial-config.json','app-restored-config.json'),('cpagx-v3','cpagx-v3')]:
            shutil.copy2(source/original,work/target)
        formal.write(work/'reused-s100-report.json',{'status':'passed','recomputed_runs':0,'source_report_sha256':formal.sha(source/'report.json'),
            'source_sql_sha256':formal.sha(source/'database.sql'),'source_run':state['run_id'],'bundle_sha256':formal.sha(work/'bundle/bundle.json')})
        print(json.dumps({'status':'passed','source_run':state['run_id'],'bundle':str(work/'bundle')}))
    finally:
        subprocess.run(['docker','stop',pg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
