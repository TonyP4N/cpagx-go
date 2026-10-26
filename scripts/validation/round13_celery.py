"""Real Celery dual-source acceptance; --serve keeps an isolated UI sandbox until stopped."""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from round9_celery import ROOT, COMPOSE, command, http, poll, wait_http, wait_worker_log, stop_process, require, json_response
from dual_source_fixtures import make_case


def upload(base, paths):
    boundary='round13-'+uuid.uuid4().hex; parts=[]
    for field,path in zip(('network_file','process_file','profile_file'),paths):
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{path.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+path.read_bytes()+b'\r\n')
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="synthetic_confirmed"\r\n\r\ntrue\r\n--{boundary}--\r\n'.encode())
    return http(base,'/cpag/dual-source',b''.join(parts),'multipart/form-data; boundary='+boundary)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def start_ui(base, port):
    class Proxy(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/api/v2/'):
                return self.forward()
            return super().do_GET()
        def do_POST(self):return self.forward()
        def forward(self):
            if not self.path.startswith('/api/v2/'):
                self.send_error(404);return
            body=self.rfile.read(int(self.headers.get('Content-Length',0))) if self.command=='POST' else None
            code,raw=http(base,self.path.removeprefix('/api/v2'),body,self.headers.get('Content-Type'))
            self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',port),functools.partial(Proxy,directory=str(ROOT/'webui/out')))
    threading.Thread(target=server.serve_forever,daemon=True).start();return server


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--serve',action='store_true')
    parser.add_argument('--ui-port',type=int,default=18300)
    args=parser.parse_args();workspace=args.output.resolve();workspace.mkdir(parents=True,exist_ok=False)
    output=workspace/'outputs';output.mkdir();uploads=workspace/'uploads';uploads.mkdir()
    project='cpag-r13-'+uuid.uuid4().hex[:8];compose=['docker','compose','-p',project,'-f',str(COMPOSE)]
    evidence={'synthetic':True,'runtime':'real RabbitMQ + Redis + Celery prefork + HTTP','project':project,'checks':{},'tasks':{},'limitations':['No production or real industrial validation','Portable artifact restore only; no new PostgreSQL/Celery metadata backup support']}
    api=worker=server=None; api_log=(workspace/'api.log').open('w');worker_log=(workspace/'worker.log').open('w')
    try:
        command(compose+['up','-d','--wait','rabbitmq','redis'])
        rabbit=command(compose+['port','rabbitmq','5672']).rsplit(':',1)[1];redis=command(compose+['port','redis','6379']).rsplit(':',1)[1]
        env=os.environ.copy();env.update(PYTHONPATH=os.pathsep.join((str(ROOT/'services/python-cpag-generator'),str(ROOT/'services/analysis/src'))),RABBITMQ_URL=f'amqp://cpag_round9:disposable-round9-only@127.0.0.1:{rabbit}//',REDIS_URL=f'redis://127.0.0.1:{redis}/0',REDIS_HOST='127.0.0.1',REDIS_PORT=redis,OUTPUT_DIR=str(output),UPLOAD_DIR=str(uploads),NEO4J_URI='bolt://127.0.0.1:1',INFLUXDB_URL='http://127.0.0.1:1',PYTHONUNBUFFERED='1',PYTHONPROFILEIMPORTTIME='1')
        port=free_port();base=f'http://127.0.0.1:{port}';evidence['api_base']=base
        api=subprocess.Popen([sys.executable,'-m','uvicorn','api.v2.app:app','--host','127.0.0.1','--port',str(port)],cwd=ROOT,env=env,stdout=api_log,stderr=subprocess.STDOUT,start_new_session=True);wait_http(base,api)
        entry=[sys.executable,'-m','celery']
        if sys.platform=='darwin':entry=[sys.executable,'-c',"import billiard; billiard.set_start_method('fork', force=True); from celery.__main__ import main; main()"]
        worker=subprocess.Popen(entry+['-A','infrastructure.celery_app','worker','--pool=prefork','--concurrency=1','-Q','cpag_generation','--loglevel=info','--hostname','round13@%h'],cwd=ROOT,env=env,stdout=worker_log,stderr=subprocess.STDOUT,start_new_session=True)
        wait_worker_log(Path(worker_log.name),'ready.',worker)
        gold=json.loads((ROOT/'fixtures/dual-source/expectations.json').read_text())['cases']
        for name in ('success','error','missing_response','mapping_missing','mapping_conflict','ambiguous','invalid'):
            paths=make_case(workspace/'inputs'/name,name if name!='invalid' else 'success')
            if name=='invalid':paths[1].write_text('time,pump\n')
            code,raw=upload(base,paths);require(code==202,f'{name} submission {code}: {raw!r}')
            task=json.loads(raw)['task_id'];state=poll(base,task,'failed' if name=='invalid' else 'completed');evidence['tasks'][name]=task
            if name=='invalid':
                require(state.get('error'),'invalid input missing reason');require(http(base,f'/cpag/result/{task}/json')[0]==409,'invalid result exposed');evidence['checks'][name]={'status':'failed','error':state['error']};continue
            result=json_response(base,f'/cpag/result/{task}/json');analysis=result['data']['analysis'];expected=gold[name]
            require(len(analysis['candidates'])==expected['candidates'],'candidate count differs')
            for op in analysis['operations']:
                require(op['response']['state']==expected['response'],'response differs')
                view=json_response(base,f'/cpag/dual-source/{task}/evidence?operation='+op['operation_id'])
                if name=='success':require(len(view['verified_original_evidence'])==4,'normal evidence not four refs')
            for candidate in analysis['candidates']:require(candidate['state']==expected['candidate_state'],'candidate state differs')
            inventory=json_response(base,f'/cpag/artifacts/{task}')
            for artifact in inventory['files']:
                filename=artifact['filename'];code,raw=http(base,f'/cpag/download/{task}/{filename}')
                require(code==200 and raw==(output/task/filename).read_bytes(),'download differs')
            evidence['checks'][name]={'status':state['status'],'response':analysis['operations'][0]['response']['state'],'candidate_states':[c['state'] for c in analysis['candidates']],'unknown_reasons':analysis['operations'][0]['unknown_reasons'],'download_files':[f['filename'] for f in inventory['files']]}
        task=evidence['tasks']['success'];target=output/task/'analysis.json';original=target.read_bytes()
        for kind in ('missing','tampered'):
            if kind=='missing':target.unlink()
            else:target.write_bytes(original+b' ')
            paths=[f'/cpag/result/{task}/json',f'/cpag/artifacts/{task}',f'/cpag/download/{task}/graph.json',f'/cpag/dual-source/{task}/evidence?operation=first']
            failures={path:http(base,path)[0] for path in paths};require(set(failures.values())=={409},f'integrity bypass {failures}')
            evidence['checks'][kind]=failures;target.write_bytes(original)
        json_response(base,f'/cpag/dual-source/{task}/evidence?operation=first')
        evidence['status']='passed'
        if args.serve:
            require((ROOT/'webui/out/index.html').is_file(),'build webui first')
            server=start_ui(base,args.ui_port);evidence['ui_url']=f'http://127.0.0.1:{args.ui_port}/'
        (workspace/'results.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence),flush=True)
        if args.serve:
            signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
            while True:time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        evidence['status']='failed';evidence['error']=f'{type(exc).__name__}: {exc}'
        if isinstance(exc,(subprocess.CalledProcessError,subprocess.TimeoutExpired)):
            evidence['subprocess_stderr']=str(exc.stderr);evidence['subprocess_stdout']=str(exc.stdout)
        raise
    finally:
        if server:server.shutdown()
        stop_process(worker);stop_process(api);api_log.close();worker_log.close()
        try:command(compose+['down','--volumes','--remove-orphans']);evidence['cleanup']='passed'
        except Exception as exc:evidence['cleanup']=str(exc)
        (workspace/'results.json').write_text(json.dumps(evidence,indent=2)+'\n')

if __name__=='__main__':main()
