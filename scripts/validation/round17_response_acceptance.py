#!/usr/bin/env python3
"""R17 response-clock supplement: formal PG/isolated Worker, CLI and restore.
Generated synthetic bytes exercise a software boundary; no industrial validation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
from urllib.parse import urlencode

import round16_acceptance as r
from round16_supplement import intake
from round17_acceptance import fixture, digest
import bundle
from cpag_core.pipeline import canonical

VERSION = 'bounded-dual-source-2'
REASON = 'response_clock_validity_outside'


def check_boundary(analysis, graph):
    """Hand-counted expected answer, independent of the analyzer implementation."""
    assert analysis['analysis_version'] == VERSION
    assert analysis['synthetic'] is True
    assert {name:len(analysis[name]) for name in ('network','process','changes','candidates','operations')} == {
        'network':2,'process':5,'changes':1,'candidates':0,'operations':1}
    operation = analysis['operations'][0]
    assert operation['response']['state'] == 'success'
    assert operation['response']['general_status'] == 0
    assert operation['time']['interval'] is not None
    assert operation['response']['time']['interval'] is None
    assert 'clock_validity_outside' in operation['response']['time']['unknown_reasons']
    assert operation['assessment'] == 'unknown'
    assert REASON in operation['unknown_reasons']
    assert analysis['quality']['operation_time_issues'] == [{'operation_id':operation['operation_id'],'reasons':[REASON]}]
    assert analysis['quality']['unknown_reasons'] == []
    assert operation['candidates'] == [] and operation['support'] == []
    assert graph['edges'] == [] and graph['claims'] == []
    assert {row['event']['event_id'] for row in analysis['network']} <= {node['event_id'] for node in graph['nodes']}
    assert analysis['changes'][0]['event_id'] in {node['event_id'] for node in graph['nodes']}
    return operation


def check_evidence(client, job, root, attempt, expected_networks, expected_process_hash):
    output = root/'jobs'/job/f'attempt-{attempt}'
    analysis = json.loads((output/'analysis.json').read_text())
    graph = json.loads((output/'graph.json').read_text())
    operation = check_boundary(analysis, graph)
    served = client.expect('GET', f'/api/v3/runs/{job}/result')
    assert served['data']['analysis'] == analysis
    assert served['data']['quality'] == analysis['quality']
    assert json.loads((output/'quality.json').read_text()) == analysis['quality']
    served_graph = client.expect('GET', f'/api/v3/runs/{job}/graph')
    # The graph route retains its normal response envelope; find the graph itself.
    graph_payload = served_graph.get('data', served_graph)
    if isinstance(graph_payload, dict) and 'graph' in graph_payload:
        graph_payload = graph_payload['graph']
    assert graph_payload == graph
    op = client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'operation':operation['operation_id']}))
    change_id = analysis['changes'][0]['event_id']
    change = client.expect('GET',f'/api/v3/runs/{job}/evidence?'+urlencode({'change':change_id}))
    network_refs = op['verified_original_evidence']
    process_refs = change['verified_original_evidence']
    assert len(network_refs) == 2 and len(process_refs) == 2
    assert len(op['verified_network_fields']) == 2 and change['verified_network_fields'] == []
    assert {entry['source_ref']['file_sha256'] for entry in network_refs} == set(expected_networks)
    assert all(entry['source_ref']['frame_number'] == 1 for entry in network_refs)
    assert all(entry['source_ref']['record_number'] is None for entry in network_refs)
    assert {entry['source_ref']['raw_time'] for entry in network_refs} == {'1767225610000000','1767225611000000'}
    assert all(entry['original']['integrity'] == 'file_and_frame_sha256_verified' for entry in network_refs)
    expected_process = analysis['changes'][0]['evidence_refs']
    assert sorted(canonical(entry['source_ref']) for entry in process_refs) == sorted(canonical(ref) for ref in expected_process)
    assert all(entry['source_ref']['frame_number'] is None and entry['source_ref']['record_number'] is not None for entry in process_refs)
    assert {entry['source_ref']['file_sha256'] for entry in process_refs} == {expected_process_hash}
    expected_rows = {2:('2026-01-01T00:00:10.500000Z','0'),3:('2026-01-01T00:00:12Z','1')}
    assert {entry['source_ref']['record_number'] for entry in process_refs} == set(expected_rows)
    for entry in process_refs:
        reference, original = entry['source_ref'], entry['original']
        timestamp, value = expected_rows[reference['record_number']]
        assert reference['column'] == 'pump' and reference['raw_time'] == timestamp
        assert original['time'] == timestamp and original['pump'] == value
    assert op['selection']['operation']['assessment'] == 'unknown'
    assert REASON in op['selection']['operation']['unknown_reasons']
    artifacts = client.expect('GET',f'/api/v3/runs/{job}/artifacts')['artifacts']
    entry = next(item for item in artifacts if item['path'] == 'analysis.json')
    downloaded = client.expect('GET',f'/api/v3/runs/{job}/artifacts/analysis.json/download')
    assert isinstance(downloaded,bytes) and hashlib.sha256(downloaded).hexdigest() == entry['sha256']
    return {'operation_id':operation['operation_id'],'change_id':change_id,
            'operation_original_refs':len(network_refs),'change_original_refs':len(process_refs),
            'combined_original_refs':len(network_refs)+len(process_refs),
            'semantic_hashes':{name:digest(json.loads((output/name).read_text())) for name in ('events.json','graph.json','analysis.json')},
            'analysis_download_sha256':entry['sha256']}


def main(work, serve=False):
    work.mkdir(parents=True,mode=0o700,exist_ok=False)
    (work/'public').mkdir()
    root=work/'source';root.mkdir()
    control=work/'control';control.mkdir()
    restored=work/'restored';restore_control=work/'restore-control';restore_control.mkdir()
    static_root=Path(os.environ.get('CPAG_STATIC_ROOT',str(r.REPO/'webui/out'))).resolve()
    container='cpag-r17-response-'+secrets.token_hex(4)
    pg,port,internal,rport,rinternal=[r.port() for _ in range(5)]
    env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),
             GOCACHE=os.environ.get('GOCACHE','/tmp/cpag-go-build'),GOMODCACHE=os.environ.get('GOMODCACHE','/tmp/cpag-go-mod'))
    report={'scope':'generated synthetic response-clock boundary; no industrial validation','expected_version':VERSION,'status':'running','checks':{}}
    app=worker=restored_app=None;created=False
    try:
        r.build(work,env,skip_image_build=True)
        r.run('docker','run','--name',container,'-d','-e','POSTGRES_DB=m4_validation','-e','POSTGRES_PASSWORD=m4-disposable-only',
              '-p',f'127.0.0.1:{pg}:5432',r.PG_IMAGE,stdout=subprocess.DEVNULL)
        created=True
        for _ in range(150):
            if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','postgres','-d','m4_validation'],capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('database readiness timeout')
        for migration in sorted((r.REPO/'internal/jobs/migrations').glob('*.sql')):
            with migration.open('rb') as source:
                bundle.pg(container,'m4_validation','psql','-v','ON_ERROR_STOP=1',stdin=source,stdout=subprocess.DEVNULL)
        username='r17-response-admin';password=secrets.token_urlsafe(24)
        wt=secrets.token_urlsafe(32);ct=secrets.token_urlsafe(32)
        cfg=r.make_config(pg,'m4_validation',root,control,port,internal,wt,ct,username,password,static_root)
        cfg['static_root']=str(static_root)
        app=r.start_app(work,'app',work/'cpagx-v3',cfg)
        client=r.Client(f'http://127.0.0.1:{port}')
        client.expect('POST','/api/v3/session',{'username':username,'password':password})
        r.cli_request(work/'cpagctl',work,client.origin,username,password,'/api/v3/datasets')
        networks,process,conf=fixture(work/'fixture')
        conf['config_version']='r17-response-clock-boundary-v1'
        conf['clocks']['network']['valid_to']='2026-01-01T00:00:10.500000Z'
        (work/'fixture/profile.json').write_bytes(canonical(conf)+b'\n')
        dataset_name='R17 response outside clock validity'
        ds=client.expect('POST','/api/v3/datasets',{'name':dataset_name,'source_kind':'synthetic',
            'source':'generated response-clock boundary fixture','batch':'r17-response-supplement','authorization_ref':'repository generated software fixture'},code=201)['dataset']['id']
        for index,path in enumerate(networks):
            r.upload(client,ds,'network',path,f'response-boundary-network-{index}')
        r.upload(client,ds,'process',process,'response-boundary-process')
        ic=client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':'intake','document':intake(ds)},code=201)['config']['id']
        preflight=client.expect('POST',f'/api/v3/datasets/{ds}/preflight',{'config_version_id':ic})['preflight_id']
        dc=client.expect('POST',f'/api/v3/datasets/{ds}/configs',{'kind':'dual','document':conf},code=201)['config']['id']
        worker_cfg=work/'worker.json'
        r.write_private(worker_cfg,{'api_url':f'http://127.0.0.1:{internal}','shared_root':str(root),'control_root':str(control),
            'worker_token':wt,'coordinator_token':ct,'worker_id':'r17-response-worker','image':r.WORKER_IMAGE,'poll_seconds':.2,'recovery_seconds':2})
        worker=r.start_worker(work,'worker',worker_cfg,env)
        runids=[];evidence=[];network_hashes=[bundle.sha(path) for path in networks]
        process_hash=bundle.sha(process)
        for _ in range(3):
            job=client.expect('POST','/api/v3/runs',{'dataset_id':ds,'config_version_id':dc,'preflight_id':preflight,'mode':'dual_source'},code=201)['run']['id']
            status=r.status_until(client,job)
            assert status['state']=='succeeded',status
            checked=check_evidence(client,job,root,status['attempt'],network_hashes,process_hash)
            runids.append(job);evidence.append(checked)
        assert evidence[0]['semantic_hashes']==evidence[1]['semantic_hashes']==evidence[2]['semantic_hashes']
        report['checks']['three_isolated_worker_runs']=evidence
        # Use the actual bound task order to compare the same inputs through CLI.
        payload=json.loads(bundle.pg(container,'m4_validation','psql','-X','-qAt','-c',
            f"SELECT payload::text FROM m4_jobs WHERE id='{runids[0]}'",capture_output=True,text=True).stdout)
        cli=work/'cli-export';args=[sys.executable,'-m','cpag_core.dual_source_export']
        for ref in payload.get('networks',[payload['network']]):
            args+=['--network',str(root/ref['path'])]
        args+=['--process',str(process),'--profile',str(work/'fixture/profile.json'),'--output',str(cli)]
        r.run(*args,env=env,capture_output=True)
        cli_analysis=json.loads((cli/'analysis.json').read_text());cli_graph=json.loads((cli/'graph.json').read_text())
        check_boundary(cli_analysis,cli_graph)
        cli_hashes={name:digest(json.loads((cli/name).read_text())) for name in evidence[0]['semantic_hashes']}
        assert cli_hashes==evidence[0]['semantic_hashes']
        report['checks']['cli_worker_semantic_hashes']=cli_hashes
        assert r.cli_call(work/'cpagctl',work,client.origin,'GET',f'/api/v3/runs/{runids[0]}/result') == client.expect('GET',f'/api/v3/runs/{runids[0]}/result')
        report['checks']['cli_api_result_equal']=True
        r.stop(worker);worker=None
        r.stop(app);app=None
        snapshot=bundle.backup(container,'m4_validation',root,work/'bundle')
        assert snapshot['catalog_audit']['valid']
        restored_audit=bundle.restore(container,work/'bundle',restored)
        assert restored_audit['valid'] and restored_audit['catalog_equal'] and restored_audit['attempt_history_equal']
        restore_cfg=r.make_config(pg,'m4_restore_validation',restored,restore_control,rport,rinternal,wt,ct,username,password,static_root)
        restore_cfg['static_root']=str(static_root)
        restored_app=r.start_app(work,'restored-app',work/'cpagx-v3',restore_cfg)
        restored_client=r.Client(f'http://127.0.0.1:{rport}')
        restored_client.expect('POST','/api/v3/session',{'username':username,'password':password})
        restored_checks=[]
        for job,original in zip(runids,evidence):
            status=restored_client.expect('GET',f'/api/v3/runs/{job}')['run']
            assert status['state']=='succeeded'
            checked=check_evidence(restored_client,job,restored,status['attempt'],network_hashes,process_hash)
            assert checked==original
            restored_checks.append(checked)
        report['checks']['terminal_backup_empty_database_new_directory_restore']={'catalog_equal':True,'attempt_history_equal':True,'runs':restored_checks}
        app=r.start_app(work,'app-restarted',work/'cpagx-v3',cfg)
        report.update(status='passed',static_root=str(static_root),run_ids=runids,expected={'network':2,'process':5,'changes':1,'candidates':0,'graph_edges':0,
                      'assessment':'unknown','response_state':'success','unknown_reason':REASON,'operation_refs':2,'change_refs':2,'combined_refs':4})
        (work/'public/results.json').write_text(json.dumps(report,indent=2)+'\n')
        r.write_private(work/'state.json',{'url':client.origin+'/workspace/','restored_url':restored_client.origin+'/workspace/',
            'username':username,'password':password,'dataset_id':ds,'dataset_name':dataset_name,'run_id':runids[0],'restored_run_id':runids[0],
            'operation_id':evidence[0]['operation_id'],'change_id':evidence[0]['change_id'],'network_hashes':network_hashes,
            'analysis_download_sha256':evidence[0]['analysis_download_sha256'],'process_hash':process_hash})
        if serve:
            stopping=False
            def stop_serving(*_):
                nonlocal stopping
                stopping=True
            signal.signal(signal.SIGTERM,stop_serving);signal.signal(signal.SIGINT,stop_serving)
            while not stopping:
                if app.poll() is not None or restored_app.poll() is not None:
                    raise RuntimeError('served application exited')
                time.sleep(.5)
    finally:
        r.stop(worker);r.stop(app);r.stop(restored_app)
        if created:
            subprocess.run(['docker','rm','-f',container],capture_output=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--serve',action='store_true')
    arguments=parser.parse_args()
    main(arguments.output.resolve(),arguments.serve)
