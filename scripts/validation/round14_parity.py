"""Compare real Celery and persistent Docker execution of identical synthetic bytes."""
import argparse
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlencode
from round9_celery import http, require, json_response


def main():
    parser=argparse.ArgumentParser();parser.add_argument('celery',type=Path);parser.add_argument('persistent',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();celery=json.loads((args.celery/'results.json').read_text());persistent=json.loads((args.persistent/'ready.json').read_text())
    base=persistent['bridge_url']+'/cpag/persistent';report={'synthetic_only':True,'cases':{},'allowed_runtime_differences':{'run_id':'Celery core UUID versus persistent job identity','attempt_id':'Persistent attempt identity; independent Celery first run is 1','tool_versions.python':'Host versus container Python patch version'}}
    for name,celery_id in celery['tasks'].items():
        folder=args.celery/'inputs'/name
        paths=[next(folder.glob('*.pcap')),folder/'process.csv',folder/'profile.json']
        # upload helper route is /cpag/dual-source; bridge prefix accounts for it.
        from round13_celery import uuid
        boundary='r14-'+uuid.uuid4().hex;parts=[]
        for field,path in zip(('network_file','process_file','profile_file'),paths):
            parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{path.name}"\r\n\r\n').encode()+path.read_bytes()+b'\r\n')
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="synthetic_confirmed"\r\n\r\ntrue\r\n--{boundary}--\r\n'.encode())
        code,raw=http(base,'/dual-source',b''.join(parts),'multipart/form-data; boundary='+boundary)
        require(code==202,f'{name} submission {code}: {raw!r}');job=json.loads(raw)['task_id']
        for _ in range(240):
            status=json_response(base,'/status/'+job)
            if status['status'] in ('completed','failed','cancelled'):break
            time.sleep(.5)
        if name=='invalid':
            require(status['status']=='failed' and status.get('error'),'invalid task did not fail with reason');report['cases'][name]={'persistent_id':job,'status':'failed'};continue
        require(status['status']=='completed',f'{name}: {status}')
        a=json_response(celery['api_base'],f'/cpag/result/{celery_id}/json')['data'];b=json_response(base,'/result/'+job+'/json')['data']
        for key in ('analysis','events','graph','quality','dataset'):
            require(a[key]==b[key],f'{name} {key} differs')
        left_manifest=json_response(celery['api_base'],f'/cpag/download/{celery_id}/run_manifest.json')
        right_manifest=json_response(base,f'/download/{job}/run_manifest.json')
        runtime={key:{'celery':left_manifest[key],'persistent':right_manifest[key]} for key in ('run_id','attempt_id','tool_versions')}
        require(right_manifest['run_id']==job and right_manifest['attempt_id']==status['attempt'],'persistent manifest identity differs')
        for manifest in (left_manifest,right_manifest):
            manifest.pop('run_id');manifest.pop('attempt_id');manifest['tool_versions'].pop('python')
        require(left_manifest==right_manifest,f'{name} normalized manifest or nested file digests differ')
        views=0
        for op in a['analysis']['operations']:
            query='?'+urlencode({'operation':op['operation_id']})
            left=json_response(celery['api_base'],f'/cpag/dual-source/{celery_id}/evidence'+query)
            right=json_response(base,f'/dual-source/{job}/evidence'+query)
            require(left==right,f'{name} raw evidence differs');views+=1
        report['cases'][name]={'persistent_id':job,'celery_id':celery_id,'equal':['analysis','events','graph','quality','dataset','original_evidence'],'operation_queries':views,'attempt':status['attempt'],'runtime_metadata':runtime,'all_nested_artifact_hashes_equal':True}
    report['status']='passed';args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
