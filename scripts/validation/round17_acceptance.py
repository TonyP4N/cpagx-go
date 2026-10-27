#!/usr/bin/env python3
"""R17 ordered synthetic acceptance using normal Go/PG/isolated Worker.
Generated real-source branch is an interface test, never industrial evidence.
"""
import argparse,copy,hashlib,json,os,secrets,signal,struct,subprocess,sys,time
from pathlib import Path
import round16_acceptance as r
from round16_supplement import intake,counts
from round17_profile import profile
import bundle
from cpag_core.pipeline import canonical


def fixture(path):
    network,process,_=r.make_case(path,'success')
    data=network.read_bytes();offset=24;records=[]
    while offset<len(data):
        size=struct.unpack_from('<I',data,offset+8)[0]
        records.append(data[offset:offset+16+size]);offset+=16+size
    assert len(records)==2
    paths=[]
    for index,record in enumerate(records):
        target=path/f'capture-{index+1}.pcap';target.write_bytes(data[:24]+record);paths.append(target)
    config=profile(rules=True);(path/'profile.json').write_bytes(canonical(config)+b'\n')
    return paths,process,config


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def main(work,serve=False):
    work.mkdir(parents=True,mode=0o700,exist_ok=False);(work/'public').mkdir()
    root=work/'source';root.mkdir();control=work/'control';control.mkdir();restored=work/'restored'
    rc=work/'restore-control';rc.mkdir();container='cpag-r17-'+secrets.token_hex(4)
    pg,port,internal,rport,rinternal=[r.port() for _ in range(5)]
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),
      GOCACHE=os.environ.get('GOCACHE','/tmp/cpag-go-build'),GOMODCACHE=os.environ.get('GOMODCACHE','/tmp/cpag-go-mod'))
    report={'scope':'generated software fixtures; real-source branch is interface test only','checks':{},'status':'running'}
    app=worker=restored_app=None;created=False
    try:
        r.build(work,env,skip_image_build=True)
        r.run('docker','run','--name',container,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only','-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL);created=True
        for _ in range(150):
            if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('database readiness timeout')
        for migration in sorted((r.REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        user='r17-admin';password=secrets.token_urlsafe(24);wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        cfg=r.make_config(pg,'m4_validation',root,control,port,internal,wt,ct,user,password,r.REPO/'webui/out')
        app=r.start_app(work,'app',work/'cpagx-v3',cfg);client=r.Client(f'http://127.0.0.1:{port}')
        client.expect('POST','/api/v3/session',{'username':user,'password':password})
        r.cli_request(work/'cpagctl',work,client.origin,user,password,'/api/v3/datasets')
        networks,process,conf=fixture(work/'fixture')
        def dataset(synthetic):
            provenance=conf['source_provenance']
            return client.expect('POST','/api/v3/datasets',{'name':'R17 cross-file' if synthetic else 'R17 generated real-source interface test',
                'source_kind':'synthetic' if synthetic else 'real','source':provenance['source'],'batch':provenance['release'],'authorization_ref':provenance['authorization_ref']},code=201)['dataset']['id']
        def config(ds,kind,doc):return client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':kind,'document':doc},code=201)['config']['id']
        def preflight(ds,cid):return client.expect('POST',f'/api/v3/datasets/{ds}/preflight',{'config_version_id':cid})['preflight_id']
        def history(ds,pid):return client.expect('GET',f'/api/v3/datasets/{ds}/preflights/{pid}')['preflight']
        def submit(ds,cid,pid):return client.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':cid,'preflight_id':pid,'mode':'dual_source'},code=201)['run']['id']
        ds=dataset(True);r.upload(client,ds,'network',networks[0],'network-first')
        ic=config(ds,'intake',intake(ds));p1=preflight(ds,ic);old=history(ds,p1)
        r.upload(client,ds,'network',networks[1],'network-second');r.upload(client,ds,'process',process,'process-input')
        p2=preflight(ds,ic);current=history(ds,p2);dc=config(ds,'dual',conf)
        before=counts(container)
        stale=client.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':dc,'preflight_id':p1,'mode':'dual_source'},code=409)
        assert stale['error']['code']=='preflight_stale' and counts(container)==before
        report['checks']['old_preflight_refused_no_job']=True
        worker_cfg=work/'worker.json';r.write_private(worker_cfg,{'api_url':f'http://127.0.0.1:{internal}','shared_root':str(root),'control_root':str(control),
            'worker_token':wt,'coordinator_token':ct,'worker_id':'r17-worker','image':r.WORKER_IMAGE,'poll_seconds':.2,'recovery_seconds':2})
        worker=r.start_worker(work,'worker',worker_cfg,env)
        hashes=[];runids=[];outputs=[]
        for index in range(3):
            job=submit(ds,dc,p2);status=r.status_until(client,job);assert status['state']=='succeeded',status
            result=client.expect('GET',f'/api/v3/runs/{job}/result')['data'];analysis=result['analysis']
            assert len(analysis['network'])==2 and len(analysis['changes'])==1 and len(analysis['candidates'])==1
            assert analysis['operations'][0]['response']['state']=='success'
            assert len(analysis['rule_findings'])>0
            ev=r.check_evidence(client,job,root,status['attempt']);assert ev['original_refs']==4
            records=client.expect('GET',f"/api/v3/runs/{job}/evidence?operation="+analysis['operations'][0]['operation_id'])['verified_original_evidence']
            network_hashes={entry['source_ref']['file_sha256'] for entry in records if entry['source_ref']['frame_number'] is not None}
            assert network_hashes=={bundle.sha(path) for path in networks}
            output=root/'jobs'/job/f"attempt-{status['attempt']}";outputs.append(output)
            hashes.append({name:digest(json.loads((output/name).read_text())) for name in ('events.json','graph.json','analysis.json')});runids.append(job)
        assert hashes[0]==hashes[1]==hashes[2];report['checks']['three_independent_worker_runs']=hashes
        # Use the bound payload order, not upload timing or parser output, for CLI parity.
        payload=json.loads(bundle.pg(container,'m4_validation','psql','-X','-qAt','-c',f"SELECT payload::text FROM m4_jobs WHERE id='{runids[0]}'",capture_output=True,text=True).stdout)
        cli_dir=work/'cli-export';args=[sys.executable,'-m','cpag_core.dual_source_export']
        for ref in payload.get('networks',[payload['network']]):args+=['--network',str(root/ref['path'])]
        args+=['--process',str(process),'--profile',str(work/'fixture/profile.json'),'--output',str(cli_dir)]
        r.run(*args,env=env,capture_output=True)
        cli_hashes={name:digest(json.loads((cli_dir/name).read_text())) for name in hashes[0]}
        assert cli_hashes==hashes[0],(cli_hashes,hashes[0]);report['checks']['cli_worker_semantic_hashes']=cli_hashes
        assert r.cli_call(work/'cpagctl',work,client.origin,'GET',f'/api/v3/runs/{runids[0]}/result')==client.expect('GET',f'/api/v3/runs/{runids[0]}/result')
        report['checks']['cli_api_result_equal']=True
        newconf=copy.deepcopy(conf);newconf['config_version']='r17-next';config(ds,'dual',newconf)
        assert history(ds,p1)==old and history(ds,p2)==current
        assert digest(json.loads((outputs[0]/'analysis.json').read_text()))==hashes[0]['analysis.json'];report['checks']['historical_versions_unchanged']=True
        real=dataset(False)
        for i,path in enumerate(networks):r.upload(client,real,'network',path,f'network-{i}')
        r.upload(client,real,'process',process,'process-input');ri=intake(real);ri['synthetic']=False
        ric=config(real,'intake',ri);rp=preflight(real,ric);realconf=profile(synthetic=False,rules=True);rd=config(real,'dual',realconf)
        realid=submit(real,rd,rp);realstatus=r.status_until(client,realid);assert realstatus['state']=='succeeded',realstatus
        realresult=client.expect('GET',f'/api/v3/runs/{realid}/result');assert realresult['synthetic'] is False and realresult['data']['analysis']['synthetic'] is False
        assert r.check_evidence(client,realid,root,realstatus['attempt'])['original_refs']==4
        report['checks']['generated_real_branch_unvalidated']=True
        # Every finite rule exposes its own original records through the existing evidence route.
        finding=json.loads((outputs[0]/'analysis.json').read_text())['rule_findings'][0]
        assert client.expect('GET',f"/api/v3/runs/{runids[0]}/evidence?change="+finding['finding_id'])['verified_original_evidence']
        report['checks']['finite_rule_original_evidence']=True
        # Damage only an owned disposable publication; failed reads must not serve trusted data.
        retained=outputs[0]/'dual/sources/network-001.pcap';saved=retained.read_bytes();mode=retained.stat().st_mode&0o777
        try:
            retained.chmod(0o600);retained.write_bytes(saved+b'tamper')
            client.expect('GET',f'/api/v3/runs/{runids[0]}/result',code=409)
        finally:retained.write_bytes(saved);retained.chmod(mode)
        report['checks']['secondary_capture_tamper_refused']=True
        # More uploads are allowed, but the fifth capture cannot become an analysis job.
        for i in range(3,6):
            extra=work/'fixture'/f'capture-{i}.pcap';raw=bytearray(networks[0].read_bytes());struct.pack_into('<I',raw,24,1767225600+i);extra.write_bytes(raw)
            r.upload(client,ds,'network',extra,f'extra-network-{i}')
        p5=preflight(ds,ic);before=counts(container)
        code,error=client.request('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':dc,'preflight_id':p5,'mode':'dual_source'})
        assert code in (413,422) and counts(container)==before,(code,error)
        report['checks']['fifth_capture_refused_no_job']={'status':code,'error':error['error']['code']}
        assert history(ds,p1)==old and history(ds,p2)==current
        r.stop(worker);worker=None;r.stop(app);app=None
        snap=bundle.backup(container,'m4_validation',root,work/'bundle');assert snap['catalog_audit']['valid']
        restored_audit=bundle.restore(container,work/'bundle',restored);assert restored_audit['valid'] and restored_audit['catalog_equal']
        restorecfg=r.make_config(pg,'m4_restore_validation',restored,rc,rport,rinternal,wt,ct,user,password,r.REPO/'webui/out')
        restored_app=r.start_app(work,'restored-app',work/'cpagx-v3',restorecfg)
        restored_client=r.Client(f'http://127.0.0.1:{rport}');restored_client.expect('POST','/api/v3/session',{'username':user,'password':password})
        for job in [*runids,realid]:
            assert r.check_evidence(restored_client,job,restored,1)['original_refs']==4
        assert restored_client.expect('GET',f'/api/v3/datasets/{ds}/preflights/{p1}')['preflight']==old
        report['checks']['empty_database_new_directory_all_captures_restore']=True
        # Fresh service process, owned test environment only.
        app=r.start_app(work,'app-restarted',work/'cpagx-v3',cfg);worker=r.start_worker(work,'worker-restarted',worker_cfg,env)
        report.update(status='passed',run_ids=runids,real_interface_run_id=realid,original_evidence_refs=4)
        (work/'public/results.json').write_text(json.dumps(report,indent=2)+'\n')
        r.write_private(work/'state.json',{'url':client.origin+'/workspace/','restored_url':restored_client.origin+'/workspace/',
          'username':user,'password':password,'fixture_dir':str(work/'fixture'),'run_id':runids[0],'restored_run_id':runids[0],'real_run_id':realid})
        if serve:
            signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
            while True:time.sleep(1)
    except KeyboardInterrupt:pass
    finally:
        r.stop(worker);r.stop(app);r.stop(restored_app)
        if created:subprocess.run(['docker','rm','-f',container],capture_output=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);p.add_argument('--serve',action='store_true');a=p.parse_args();main(a.output,a.serve)
