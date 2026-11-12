#!/usr/bin/env python3
"""Small real preparation/CSV locator/format6 PostgreSQL restore acceptance.

Uses the existing synthetic business oracle and explicit service preparation.
Never seeds a ready row. This is correctness evidence, not capacity acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import secrets
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/backup')]
import round19_evaluation_acceptance as r19
from cpag_core.pipeline import canonical


def sql_literal(value):return "'"+value.replace("'","''")+"'"


def run(work):
    r18=r19.r18;original_backup=r18.bundle.backup
    prepared={};checks=[];negative=[];roles=[];viewer_credentials={}
    def checked(client,job,root,attempt,config,case):
        path=f'/api/v3/runs/{job}/evaluation-preparation';restored='restored' in str(root)
        if job not in prepared:
            assert not restored,'restored service must not recreate a missing preparation'
            accepted=client.expect('POST',path,{'projection':'dual'},code=202)['preparation']
            deadline=time.monotonic()+90
            while True:
                state=client.expect('GET',path+'?projection=dual')['preparation']
                if state['state']=='ready':break
                assert state['state'] in ('queued','preparing'),state
                assert time.monotonic()<deadline,state
                time.sleep(.1)
            assert state['id']==accepted['id'] and state['strategy_version']=='evaluation-preparation-1'
            assert state['attempt']==attempt and state['projection']=='dual'
            assert state['document_size']>0 and len(state['document_sha256'])==64
            prepared[job]=state
        else:
            state=client.expect('GET',path+'?projection=dual')['preparation'];old=prepared[job]
            for key in ('id','state','attempt','projection','preparation_attempt','publication_sha256','document_sha256','document_size'):
                assert state[key]==old[key],(key,state,old)
        assert not ({'owner','error_detail','document_bytes'} & set(state)),'private preparation field exposed'
        checks.append({'run_id':job,'stage':'restored' if restored else 'original','mode':'offline' if case=='offline' else 'replay',
            'preparation':state,'ready_without_recreation_after_restore':restored})
        if not viewer_credentials:
            meta=client.expect('GET',f'/api/v3/runs/{job}')['run']
            username='r19-preparation-viewer';password=secrets.token_urlsafe(24)
            uid=client.expect('POST','/api/v3/users',{'username':username,'password':password,'role':'viewer'},code=201)['user']['id']
            viewer=r18.r.Client(client.origin);viewer.expect('POST','/api/v3/session',{'username':username,'password':password})
            viewer.expect('GET',path+'?projection=dual',code=404)
            client.expect('POST',f"/api/v3/datasets/{meta['dataset_id']}/acl",{'user_id':uid,'access':'viewer'})
            visible=viewer.expect('GET',path+'?projection=dual')['preparation'];assert visible['id']==state['id']
            viewer.expect('POST',path,{'projection':'dual'},code=403)
            viewer_credentials.update(username=username,password=password,job=job)
            roles.append({'stage':'original','ungranted_preparation_read':404,'granted_preparation_read':200,'viewer_prepare_write':403})
        elif restored and job==viewer_credentials['job']:
            viewer=r18.r.Client(client.origin)
            viewer.expect('POST','/api/v3/session',{'username':viewer_credentials['username'],'password':viewer_credentials['password']})
            visible=viewer.expect('GET',path+'?projection=dual')['preparation'];assert visible['id']==state['id']
            viewer.expect('POST',path,{'projection':'dual'},code=403)
            roles.append({'stage':'restored','granted_preparation_read':200,'viewer_prepare_write':403})
    def backup(container,db,root,destination):
        catalog=r18.bundle.catalog_now(container,db)
        rows=catalog['v3_evaluation_preparations']
        assert rows and all(row['state']=='ready' for row in rows)
        target=rows[0];quoted=sql_literal(target['id'])
        def execute(query):return r18.bundle.pg(container,db,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',query,capture_output=True,text=True)
        raw=bytes.fromhex(execute(f"SELECT encode(document_bytes,'hex') FROM v3_evaluation_preparations WHERE id={quoted};").stdout.strip())
        assert len(raw)==target['document_size'] and hashlib.sha256(raw).hexdigest()==target['document_sha256']
        restore=f"UPDATE v3_evaluation_preparations SET state='ready',document_bytes=decode({sql_literal(raw.hex())},'hex'),document_sha256={sql_literal(target['document_sha256'])},document_size={len(raw)} WHERE id={quoted};"
        # Real database storage constraints must also prevent a ready row from
        # losing its body. Error details are kept private, never public results.
        try:execute(f"UPDATE v3_evaluation_preparations SET document_bytes=NULL WHERE id={quoted};")
        except subprocess.CalledProcessError as error:
            assert 'check constraint' in error.stderr.lower()
            negative.append({'mutation':'ready_missing_bytea','result':'database_check_constraint_rejected'})
        else:raise AssertionError('database allowed ready without bytes')
        for pending in ('queued','preparing'):
            execute(f"UPDATE v3_evaluation_preparations SET state='{pending}',document_bytes=NULL,document_sha256=NULL,document_size=0 WHERE id={quoted};")
            try:
                try:original_backup(container,db,root,work/('rejected-backup-'+pending))
                except ValueError as error:
                    assert 'pending evaluation preparation blocks terminal snapshot' in str(error),error
                    negative.append({'mutation':pending,'result':'backup_refused_nonterminal_preparation'})
                else:raise AssertionError('backup accepted nonterminal preparation')
            finally:execute(restore)
        changed=bytes([raw[0]^1])+raw[1:]
        execute(f"UPDATE v3_evaluation_preparations SET document_bytes=decode({sql_literal(changed.hex())},'hex') WHERE id={quoted};")
        try:
            try:original_backup(container,db,root,work/'rejected-backup-same-size-bytea')
            except ValueError as error:
                assert 'preparation bytea checksum mismatch' in str(error),error
                negative.append({'mutation':'same_size_prepared_bytea','result':'backup_refused_checksum_mismatch','size_unchanged':True})
            else:raise AssertionError('backup accepted changed prepared bytea')
        finally:execute(restore)
        result=original_backup(container,db,root,destination)
        assert result['format_version']==6
        assert len(result['preparation_audit']['documents'])==len(rows)
        assert all(row['source_projection_equal'] and row['semantic_verification_executed'] for row in result['preparation_audit']['documents'])
        assert all(not row['semantic_verification_executed'] for row in result['copied_preparation_audit']['documents'])
        return result
    r18.bundle.backup=backup
    try:r19.run(work,bundle_version=r19.eb.V3_VERSION,before_evaluation=checked)
    finally:
        r18.bundle.backup=original_backup
        if (work/'public').exists():
            result={'checks':checks,'negative':negative,'roles':roles,'scope':'small synthetic real service preparation + v3 logical CSV locator + format6 dump/empty database restore; no capacity or industrial acceptance'}
            (work/'public/preparation-results.json').write_text(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args();run(Path(args.output).resolve())
