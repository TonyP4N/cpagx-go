#!/usr/bin/env python3
"""Ordered R16 regression with real Go/PG/Worker and terminal bundle restore.
Only generated fixtures; no industrial material is validated.
"""
import argparse,base64,copy,hashlib,json,os,secrets,signal,subprocess,sys,time
from pathlib import Path
import round16_acceptance as r
import bundle


def sql(container,statement,db='m4_validation'):
    return bundle.pg(container,db,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-c',statement,
                     capture_output=True,text=True).stdout.strip()


def literal(value):
    return "convert_from(decode('"+base64.b64encode(value.encode()).decode()+"','base64'),'UTF8')"


def counts(container):
    return sql(container,"SELECT (SELECT count(*) FROM m4_jobs)||':'||(SELECT count(*) FROM v3_run_bindings)")


def intake(dataset):
    return {'dataset_id':dataset,'synthetic':True,
        'authorization':{'allowed_use':'synthetic testing','evidence_ref':'generated fixture','reviewer':'acceptance'},
        'time_basis':{'timezone':'UTC','precision':'microsecond','synchronization':'generated clocks','evidence_ref':'fixture'},
        'mapping':{'field_units_ref':'fixture','device_map_ref':'fixture','effective_period_ref':'fixture'}}


def main(work,serve):
    work.mkdir(mode=0o700,parents=True,exist_ok=False);(work/'public').mkdir()
    container='cpag-r16-supplement-'+secrets.token_hex(4)
    root=work/'source';root.mkdir();control=work/'control';control.mkdir()
    restored=work/'restored';rc=work/'restored-control';rc.mkdir()
    pg,port,internal,rport,rinternal=[r.port() for _ in range(5)]
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),
             GOCACHE=os.environ.get('GOCACHE','/tmp/cpag-go-build'),GOMODCACHE=os.environ.get('GOMODCACHE','/tmp/cpag-go-mod'))
    report={'scope':'synthetic software only','checks':{},'status':'running'}
    app=worker=restored_app=None;created=False
    def check(name):report['checks'][name]=True
    try:
        r.build(work,env,skip_image_build=True)
        r.run('docker','run','--name',container,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only',
            '-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL);created=True
        for _ in range(150):
            if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('database readiness timeout')
        for migration in sorted((r.REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        with (r.REPO/'internal/jobs/migrations/007_v3_preflight_snapshots.sql').open('rb') as source:
            bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        user='supplement-admin';password=secrets.token_urlsafe(24);wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        cfg=r.make_config(pg,'m4_validation',root,control,port,internal,wt,ct,user,password,r.REPO/'webui/out')
        app=r.start_app(work,'app-initial',work/'cpagx-v3',cfg)
        client=r.Client('http://127.0.0.1:'+str(port));client.expect('POST','/api/v3/session',{'username':user,'password':password})
        r.cli_request(work/'cpagctl',work,client.origin,user,password,'/api/v3/datasets')
        network,process,profile_path=r.make_case(work/'fixture','success');profile=json.loads(profile_path.read_text())
        def dataset(name,**metadata):
            return client.expect('POST','/api/v3/datasets',{'name':name,'source_kind':'synthetic','source':'generated fixture',
              'batch':'supplement','authorization_ref':'generated-only test',**metadata},code=201)['dataset']['id']
        def config(ds,kind,doc):return client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':kind,'document':doc},code=201)['config']['id']
        def preflight(ds,cid,code=200):return client.expect('POST',f'/api/v3/datasets/{ds}/preflight',{'config_version_id':cid},code=code)
        def history(ds,pid):return client.expect('GET',f'/api/v3/datasets/{ds}/preflights/{pid}')['preflight']
        def reject(name,ds,cid,pid,code,error):
            body={'dataset_id':ds,'config_version_id':cid,'preflight_id':pid,'mode':'dual_source'}
            before=counts(container)
            value=client.expect('POST','/api/v3/runs',body,code=code)
            assert value['error']['code']==error,(name,value)
            args=[str(work/'cpagctl'),'--url',client.origin,'--session',str(work/'cli-session.json'),'request','POST','/api/v3/runs']
            cli=subprocess.run(args,input=json.dumps(body),text=True,capture_output=True)
            assert cli.returncode!=0 and json.loads(cli.stdout)['error']['code']==error,(name,cli.stdout)
            assert counts(container)==before,'rejected request inserted job/binding'
            # Each rejected API/CLI call has a specific audit reason, not only a generic HTTP count.
            audited=int(sql(container,"SELECT count(*) FROM v3_audit_events WHERE dataset_id='"+ds+"' AND action='run_gate_rejected' AND outcome='"+error+"'"))
            assert audited>=2,(name,'missing rejection audit')
            report['checks'][name]={'http':code,'error':error,'api_cli_equal':True,'no_jobs_or_bindings':True,'audit_count':audited}
        ds=dataset('Supplement single source then pair')
        r.upload(client,ds,'network',network,'network-1')
        ic=config(ds,'intake',intake(ds));p1=preflight(ds,ic);p1id=p1['preflight_id']
        assert p1['report']['status']=='single_source_review'
        first=history(ds,p1id)
        r.stop(app);app=None
        before_bundle=bundle.backup(container,'m4_validation',root,work/'single-source-bundle')
        assert before_bundle['catalog_audit']['valid'];check('single_source_complete_backup')
        app=r.start_app(work,'app-after-first-backup',work/'cpagx-v3',cfg)
        r.upload(client,ds,'process',process,'process-1')
        p2=preflight(ds,ic);p2id=p2['preflight_id'];second=history(ds,p2id)
        assert p2['report']['status']=='ready_for_manual_review'
        assert history(ds,p1id)==first,'append reinterpreted historical report'
        assert len(first['snapshot']['files'])==1 and len(second['snapshot']['files'])==2
        dc=config(ds,'dual',profile)
        worker_cfg=work/'worker.json';r.write_private(worker_cfg,{'api_url':f'http://127.0.0.1:{internal}',
          'shared_root':str(root),'control_root':str(control),'worker_token':wt,'coordinator_token':ct,
          'worker_id':'supplement-worker','image':r.WORKER_IMAGE,'poll_seconds':.2,'recovery_seconds':2})
        worker=r.start_worker(work,'worker',worker_cfg,env)
        runid=client.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':dc,'preflight_id':p2id,'mode':'dual_source'},code=201)['run']['id']
        status=r.status_until(client,runid);assert status['state']=='succeeded'
        evidence=r.check_evidence(client,runid,root,status['attempt']);assert evidence['original_refs']==4
        check('complete_materials_real_worker_four_refs')
        r.stop(worker);worker=None
        for field in ('source','batch','authorization_ref'):
            bad=dataset('Missing '+field,**{field:''})
            r.upload(client,bad,'network',network,'network-1');r.upload(client,bad,'process',process,'process-1')
            bi=config(bad,'intake',intake(bad));bp=preflight(bad,bi);bd=config(bad,'dual',profile)
            reject('missing_'+field,bad,bd,bp['preflight_id'],422,'preflight_incomplete')
        conflicting=config(ds,'intake',{**intake(ds),'dataset_id':'wrong-batch'})
        conflict=preflight(ds,conflicting,409)
        reject('batch_conflict',ds,dc,conflict['preflight_id'],409,'batch_conflict')
        for name in ('mapping','time'):
            changed=copy.deepcopy(profile)
            if name=='mapping':changed['mappings']=[]
            else:changed['clocks']['process']['basis']=''
            badconf=config(ds,'dual',changed)
            reject('missing_'+name+'_basis',ds,badconf,p2id,422,'insufficient_basis')
        retained=root/first['snapshot']['files'][0]['path'];retained_bytes=retained.read_bytes();retained_mode=retained.stat().st_mode&0o777
        try:
            retained.chmod(0o600);retained.write_bytes(retained_bytes+b'changed after preflight')
            reject('checked_original_bytes_changed',ds,dc,p2id,409,'preflight_stale')
        finally:retained.write_bytes(retained_bytes);retained.chmod(retained_mode)
        old_report=sql(container,"SELECT report::text FROM v3_preflights WHERE id='"+p2id+"'")
        try:
            sql(container,"UPDATE v3_preflights SET report=jsonb_set(report,'{verified_file_count}','999') WHERE id='"+p2id+"'")
            reject('retained_report_tamper',ds,dc,p2id,409,'preflight_stale')
        finally:sql(container,"UPDATE v3_preflights SET report="+literal(old_report)+"::jsonb WHERE id='"+p2id+"'")
        invalid=client.expect('POST','/api/v3/datasets',{'name':'bad kind','source_kind':'INVALID'},code=400)
        assert invalid['error']['code']=='invalid_source_kind';check('invalid_source_kind_400')
        new_profile=copy.deepcopy(profile);new_profile['config_version']='supplement-next'
        config(ds,'dual',new_profile)
        extra=work/'fixture'/'extra.csv';extra.write_bytes(process.read_bytes())
        r.upload(client,ds,'process',extra,'extra-process')
        reject('checked_input_set_changed',ds,dc,p2id,409,'preflight_stale')
        assert history(ds,p1id)==first and history(ds,p2id)==second
        assert client.expect('GET','/api/v3/runs/'+runid+'/result')['data']['analysis']==evidence['result']['data']['analysis']
        check('append_files_configs_preserves_history_and_run')
        original=root/first['snapshot']['files'][0]['path'];raw=original.read_bytes();mode=original.stat().st_mode&0o777
        r.stop(app);app=None
        original.chmod(0o600);original.write_bytes(raw+b'tamper')
        try:
            try:bundle.backup(container,'m4_validation',root,work/'bad-original-bundle')
            except ValueError:check('tampered_original_backup_refused')
            else:raise AssertionError('tampered original backed up')
        finally:original.write_bytes(raw);original.chmod(mode)
        saved=sql(container,"SELECT snapshot_json FROM v3_preflights WHERE id='"+p1id+"'")
        sql(container,"UPDATE v3_preflights SET snapshot_json=snapshot_json||' ' WHERE id='"+p1id+"'")
        try:
            try:bundle.backup(container,'m4_validation',root,work/'bad-history-bundle')
            except ValueError:check('tampered_historical_snapshot_backup_refused')
            else:raise AssertionError('tampered history backed up')
        finally:sql(container,"UPDATE v3_preflights SET snapshot_json="+literal(saved)+" WHERE id='"+p1id+"'")
        final_bundle=bundle.backup(container,'m4_validation',root,work/'complete-bundle')
        assert final_bundle['catalog_audit']['valid'];check('append_then_complete_backup')
        restored_audit=bundle.restore(container,work/'complete-bundle',restored)
        assert restored_audit['valid'] and restored_audit['catalog_equal'];check('empty_database_new_directory_restore')
        restore_cfg=r.make_config(pg,'m4_restore_validation',restored,rc,rport,rinternal,wt,ct,user,password,r.REPO/'webui/out')
        restored_app=r.start_app(work,'restored-app',work/'cpagx-v3',restore_cfg)
        restored_client=r.Client('http://127.0.0.1:'+str(rport));restored_client.expect('POST','/api/v3/session',{'username':user,'password':password})
        for pid,previous in [(p1id,first),(p2id,second)]:
            actual=restored_client.expect('GET',f'/api/v3/datasets/{ds}/preflights/{pid}')['preflight']
            assert actual==previous,'restored historical report/snapshot differs'
        assert r.check_evidence(restored_client,runid,restored,status['attempt'])['original_refs']==4
        check('restored_two_history_reports_and_four_refs')
        # Simulate pre-007 records only in the disposable source database, then exercise the explicit migration.
        sql(container,"UPDATE v3_preflights SET snapshot_json=NULL,snapshot_sha256=NULL,snapshot_status='pending_legacy',snapshot_reason=NULL")
        sql(container,"UPDATE v3_run_bindings SET preflight_id=NULL,preflight_link_origin='legacy_unbound',preflight_link_reason='legacy run predates preflight gate'")
        migration=subprocess.run([str(work/'cpagx-v3'),'--config',str(work/'app-after-first-backup-config.json'),'--backfill-legacy'],capture_output=True,text=True)
        assert migration.returncode==0,'explicit historical migration failed: '+migration.stderr
        assert sql(container,"SELECT count(*) FROM v3_preflights WHERE snapshot_status<>'reconstructed'")=='0'
        upgraded=bundle.backup(container,'m4_validation',root,work/'upgraded-bundle')
        assert upgraded['catalog_audit']['valid'];check('explicit_legacy_backfill_preserves_reports_and_backs_up')
        previous=json.loads(sql(container,"SELECT to_jsonb(p)::text FROM v3_preflights p WHERE id='"+p1id+"'"))
        try:
            sql(container,"UPDATE v3_preflights SET snapshot_json=NULL,snapshot_sha256=NULL,snapshot_status='pending_legacy',snapshot_reason=NULL,report=jsonb_set(report,'{verified_file_count}','999') WHERE id='"+p1id+"'")
            failed_migration=subprocess.run([str(work/'cpagx-v3'),'--config',str(work/'app-after-first-backup-config.json'),'--backfill-legacy'],capture_output=True,text=True)
            assert failed_migration.returncode!=0,'unreconstructable history incorrectly reported success'
            failed=json.loads(sql(container,"SELECT to_jsonb(p)::text FROM v3_preflights p WHERE id='"+p1id+"'"))
            assert failed['snapshot_status']=='unreconstructable' and failed['snapshot_reason'] and failed['report']['verified_file_count']==999
            try:bundle.backup(container,'m4_validation',root,work/'unreconstructable-bundle')
            except ValueError:check('unreconstructable_report_retained_and_backup_refused')
            else:raise AssertionError('unreconstructable history silently skipped')
        finally:
            # Undo only the test-injected corruption; never delete a historical row.
            sql(container,"UPDATE v3_preflights SET snapshot_json="+literal(previous['snapshot_json'])+",snapshot_sha256='"+previous['snapshot_sha256']+"',snapshot_status='reconstructed',snapshot_reason=NULL,report="+literal(json.dumps(previous['report']))+"::jsonb WHERE id='"+p1id+"'")
        app=r.start_app(work,'app-final',work/'cpagx-v3',cfg)
        for pid,previous in [(p1id,first),(p2id,second)]:assert history(ds,pid)['report']==previous['report']
        worker=r.start_worker(work,'worker-final',worker_cfg,env)
        report.update(status='passed',historical_dataset_id=ds,preflight_ids=[p1id,p2id],run_id=runid,
          snapshot_sha256=[first['snapshot_sha256'],second['snapshot_sha256']],original_evidence_refs=4)
        state={'url':client.origin,'restored_url':restored_client.origin,'username':user,'password':password,
          'fixture_dir':str(work/'fixture'),'source_root':str(root),'restored_root':str(restored),'pg_container':container,
          'run_id':runid,'restored_run_id':runid,'historical_dataset_id':ds,'historical_preflight_ids':[p1id,p2id]}
        r.write_private(work/'state.json',state)
        (work/'public/results.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'status':'passed','checks':len(report['checks'])}),flush=True)
        if serve:
            stopped=False
            def stop(*_):
                nonlocal stopped
                stopped=True
            signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
            while not stopped:time.sleep(.5)
    except Exception as exc:
        report.update(status='failed',error=str(exc));(work/'public/results.json').write_text(json.dumps(report,indent=2)+'\n');raise
    finally:
        r.stop(worker);r.stop(app);r.stop(restored_app)
        if created:subprocess.run(['docker','rm','-f','-v',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--serve',action='store_true')
    a=p.parse_args();main(a.output.resolve(),a.serve)
