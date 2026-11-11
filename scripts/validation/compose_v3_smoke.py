#!/usr/bin/env python3
"""Cold-build a disposable source Compose stack and exercise its real v3 API.

Only the generated cpag-compose-smoke/ci project is stopped/removed. Public
report excludes credentials, raw API authority, database contents and logs.
"""
import argparse
import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener

REPO = Path(__file__).resolve().parents[2]



class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class WorkbenchHTML(HTMLParser):
    def __init__(self):
        super().__init__(); self.assets=[]; self.data=[]; self.in_data=False
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=='script':
            self.in_data=attrs.get('id')=='__NEXT_DATA__'
            value=attrs.get('src','')
            if value.startswith('/_next/static/'):self.assets.append(value)
        elif tag=='link' and attrs.get('rel')=='stylesheet':
            value=attrs.get('href','')
            if value.startswith('/_next/static/'):self.assets.append(value)
    def handle_endtag(self, tag):
        if tag=='script':self.in_data=False
    def handle_data(self, data):
        if self.in_data:self.data.append(data)


class Smoke:
    def __init__(self, args):
        self.args = args; self.out = args.output.resolve()
        self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.public = self.out/'public'; self.public.mkdir()
        self.context = self.out/'source'; self.context.mkdir()
        self.phase = 'source'; self.started = time.monotonic()
        self.project = args.project or 'cpag-compose-smoke-'+secrets.token_hex(6)
        if re.fullmatch(r'cpag-compose-(?:smoke|ci)-[a-z0-9-]{3,40}', self.project) is None:
            raise ValueError('disposable Compose project prefix required')
        self.report = {'scope': 'disposable source Compose synthetic smoke; not capacity or industrial acceptance',
                       'project': self.project, 'status': 'running', 'runs': []}
        self.env = dict(os.environ, CPAG_IMAGE='cpag-v3:'+self.project,
                        CPAG_RELAY_IMAGE='cpag-v3-relay:'+self.project, CPAG_EXTERNAL_ORIGIN='')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        self.env['CPAG_HTTP_PORT'] = str(port); self.origin = 'http://127.0.0.1:'+str(port)
        self.cookies = http.cookiejar.CookieJar()
        self.http = build_opener(ProxyHandler({}), HTTPCookieProcessor(self.cookies))
        self.dc = ['docker','compose','-p',self.project,'-f',str(self.context/'deployments/docker-compose.yml')]
        self.launched = False
        self.save()

    def save(self):
        self.report['phase'] = self.phase
        self.report['wall_seconds'] = round(time.monotonic()-self.started, 3)
        (self.public/'report.json').write_text(json.dumps(self.report, indent=2)+'\n')

    def command(self, args, data=None):
        result = subprocess.run(args, input=data, text=True, env=self.env, capture_output=True)
        if result.returncode:
            (self.out/'last-command.stdout').write_text(result.stdout)
            (self.out/'last-command.stderr').write_text(result.stderr)
            if args[:len(self.dc)]==self.dc and len(args)>len(self.dc) and args[len(self.dc)]=='up':
                # Detached Compose progress contains no service stdout or config.
                (self.public/'compose-startup.log').write_text(result.stderr)
            raise RuntimeError('disposable Compose command failed')
        return result.stdout.strip()

    def compose(self, *args, data=None): return self.command(self.dc+list(args), data=data)
    def execute(self, service, code, *args):
        return self.compose('exec','-T',service,'python3','-c',code,*args)

    def prepare(self):
        commit = self.command(['git','-C',str(REPO),'rev-parse','HEAD'])
        archive = self.out/'source.tar'
        with archive.open('wb') as stream:
            subprocess.run(['git','-C',str(REPO),'archive','--format=tar',commit], stdout=stream, check=True)
        with tarfile.open(archive) as bundle: bundle.extractall(self.context, filter='data')
        self.report['source_commit'] = commit
        self.report['docker_architecture'] = self.command(['docker','info','--format','{{.Architecture}}'])
        model = json.loads(self.compose('config','--format','json'))
        expected = {'bootstrap','postgres','migrate','api','private-relay','source-verifier','relay','resident-worker'}
        assert set(model['services']) == expected, 'canonical standalone service set changed'
        for volume in model.get('volumes', {}).values():
            assert not volume.get('external') and volume['name'].startswith(self.project+'_'), 'test may only own project-scoped volumes'
        for service in model['services'].values():
            assert not service.get('privileged')
            for volume in service.get('volumes', []):
                assert volume.get('type') != 'bind', 'standalone stack must not depend on host data/socket binds'
                assert 'docker.sock' not in json.dumps(volume)
        local = json.loads(self.command(['docker','compose','-p',self.project,'-f',str(self.context/'deployments/docker-compose.local.yml'),'config','--format','json']))
        assert local['services'] == model['services'], 'documented local alias diverged'
        self.report['canonical_alias_matches'] = True
        self.report['no_host_binds_or_docker_socket'] = True
        self.phase = 'cold_build'; self.save()
        # This log is public-source compilation only, before bootstrap creates
        # credentials. Runtime/container logs remain private to this directory.
        with (self.public/'source-build.log').open('w') as log:
            result=subprocess.run(self.dc+['build','--no-cache'],env=self.env,stdout=log,stderr=subprocess.STDOUT)
        if result.returncode: raise RuntimeError('cold source build failed; see public/source-build.log')
        self.phase = 'startup'; self.save(); self.launched = True
        self.compose('up','-d','--no-build','--wait','--wait-timeout','300')
        self.wait(lambda: self.raw('/health/ready') is not None, 120)
        self.landing()
        self.app = json.loads(self.execute('api', "import json;print(json.dumps(json.load(open('/etc/cpag/app.json'))))"))
        foreign = Request(self.origin+'/api/v3/session', method='POST',
            data=json.dumps({'username':self.app['bootstrap_admin_username'],'password':self.app['bootstrap_admin_password']}).encode(),
            headers={'Content-Type':'application/json','Origin':'http://foreign.invalid','Sec-Fetch-Site':'cross-site'})
        try:
            self.http.open(foreign,timeout=30)
            raise AssertionError('foreign browser origin accepted')
        except HTTPError as error:
            assert error.code==403
        self.report['foreign_origin_rejected']=True
        self.post('/session', {'username': self.app['bootstrap_admin_username'], 'password': self.app['bootstrap_admin_password']})
        identity = self.worker_identity()
        assert identity['generation']['backend']=='compose-pid1-v1'
        assert identity['generation']['container_id'].startswith('pid1://')
        self.report['initial_worker'] = identity
        self.report['built_image_id'] = self.command(['docker','image','inspect',self.env['CPAG_IMAGE'],'--format','{{.Id}}'])
        self.phase = 'api_baseline'; self.save()

    def landing(self):
        # Follow no unvalidated redirect: all requests stay on this test relay.
        client=build_opener(ProxyHandler({}),NoRedirect())
        try:
            client.open(self.origin+'/',timeout=30)
            raise AssertionError('public root did not redirect to workbench')
        except HTTPError as error:
            assert error.code==302 and error.headers.get('Location')=='/workbench/'
        with client.open(self.origin+'/workbench/',timeout=30) as response:
            assert response.status==200 and 'text/html' in response.headers.get('Content-Type','')
            html=response.read().decode()
        parsed=WorkbenchHTML();parsed.feed(html)
        data=json.loads(''.join(parsed.data));assert data['page']=='/workbench'
        assert parsed.assets and any('.js' in path for path in parsed.assets)
        paths=[]
        for suffix in ('.js','.css'):
            path=next((p for p in parsed.assets if suffix in p),None)
            if path:paths.append(path)
        assets=[]
        for path in paths:
            with client.open(self.origin+path,timeout=30) as response:
                body=response.read();content=response.headers.get('Content-Type','')
                assert response.status==200 and body and not body.lstrip().startswith(b'<!DOCTYPE')
                assert ('javascript' in content) if '.js' in path else ('text/css' in content)
            assets.append({'path':path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'content_type':content})
        self.report['public_landing']={'root_status':302,'location':'/workbench/','workbench_status':200,'next_page':data['page'],'assets':assets}
        self.save()

    def raw(self, path):
        with self.http.open(self.origin+path, timeout=30) as response: return response.read()

    def request(self, method, path, body=None, headers=None):
        merged={'Content-Type':'application/json'}
        if method=='POST': merged.update({'Origin':self.origin,'Sec-Fetch-Site':'same-origin'})
        merged.update(headers or {})
        request = Request(self.origin+'/api/v3'+path, method=method,
            data=None if body is None else body if isinstance(body, bytes) else json.dumps(body).encode(),
            headers=merged)
        with self.http.open(request, timeout=60) as response: return json.load(response)

    def post(self, path, body): return self.request('POST',path,body)
    def get(self, path): return self.request('GET',path)

    def wait(self, check, seconds=180):
        deadline = time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                value = check()
                if value: return value
            except (OSError, ValueError): pass
            time.sleep(.25)
        raise TimeoutError('disposable Compose condition timed out')

    def worker_identity(self):
        container = self.compose('ps','-q','resident-worker')
        assert container
        value = json.loads(self.command(['docker','inspect','--format','{{json .State}}',container]))
        assert value['Running']
        return {'container_id':container,'pid':value['Pid'],
                'generation':json.loads(self.execute('resident-worker', "import json;print(json.dumps(json.load(open('/state/control/resident-instance.json'))))"))}

    def fixtures(self):
        sys.path.insert(0,str(self.context/'scripts/validation'))
        from round19_core_small import inputs
        _,_,offline,_=inputs(self.out/'fixtures/offline','success','offline')
        _,_,replay,_=inputs(self.out/'fixtures/replay','normal','replay')
        ds=self.post('/datasets',{'name':'Compose synthetic smoke','source_kind':'synthetic','source':'generated fixture',
            'batch':'compose-v3','authorization_ref':'repository-generated synthetic material'})['dataset']['id']
        route='/datasets/'+ds
        for name in ('network.pcap','response.pcap','process.csv'):
            data=(self.out/'fixtures/replay'/name).read_bytes()
            self.request('POST',route+'/files?'+urlencode({'name':name,'role':'process' if name.endswith('.csv') else 'network'}),data,
                {'Content-Type':'application/octet-stream','X-Content-SHA256':hashlib.sha256(data).hexdigest(),'Idempotency-Key':secrets.token_hex(16)})
        intake=self.post(route+'/configs',{'kind':'intake','document':{'dataset_id':ds,'synthetic':True,
            'authorization':{'allowed_use':'synthetic testing','evidence_ref':'generated fixture','reviewer':'compose smoke'},
            'time_basis':{'timezone':'UTC','precision':'microsecond','synchronization':'generated clocks','evidence_ref':'fixture'},
            'mapping':{'field_units_ref':'fixture','device_map_ref':'fixture','effective_period_ref':'fixture'}}})['config']['id']
        preflight=self.post(route+'/preflight',{'config_version_id':intake})['preflight_id']
        configs={mode:self.post(route+'/configs',{'kind':'dual','document':json.loads(profile.read_text())})['config']['id']
                 for mode,profile in [('dual_source',offline),('dual_source_replay',replay)]}
        self.dataset,self.preflight,self.configs=ds,preflight,configs

    def submit(self, mode='dual_source'):
        return self.post('/runs',{'dataset_id':self.dataset,'config_version_id':self.configs[mode],
                                  'preflight_id':self.preflight,'mode':mode})['run']['id']

    def state(self, job): return self.get('/runs/'+job)['run']
    def terminal(self, job, wanted='succeeded', seconds=240):
        result=self.wait(lambda:(lambda r:r if r['state'] in ('succeeded','failed','cancelled') else None)(self.state(job)),seconds)
        assert result['state']==wanted, 'unexpected terminal state'
        return result

    def receipt(self, job, attempt):
        value=json.loads(self.execute('resident-worker', "import json,sys;p='/state/control/jobs/'+sys.argv[1]+'/attempt-'+sys.argv[2]+'.worker/exit.json';v=json.load(open(p));v.pop('token',None);print(json.dumps(v))",job,str(attempt)))
        assert 'token' not in value
        return value

    def baseline(self):
        self.fixtures()
        before=self.worker_identity()
        containers_before=sorted(self.compose('ps','-q').splitlines())
        for mode in ('dual_source','dual_source_replay'):
            job=self.submit(mode);run=self.terminal(job);route='/runs/'+job
            result=self.wait(lambda:self.get(route+'/result'))
            counts=result['manifest']['counts'];assert all(counts[k]==1 for k in ('operations','changes','candidates'))
            query='/shared-query?'+urlencode({'action':'page','logical_root':'analysis.json','path':json.dumps(['operations']),'limit':10,'offset':0})
            page=self.get(route+query);assert page['total']==1
            evidence=self.get(route+'/shared-query?'+urlencode({'action':'evidence','operation':page['items'][0]['operation_id'],'ref_limit':100}))
            assert len(evidence['verified_original_evidence'])==4
            inventory=self.get(route+'/artifacts')['artifacts'];entry=next(r for r in inventory if r['path']=='run_manifest.json')
            downloaded=self.raw('/api/v3'+route+'/artifacts/run_manifest.json/download')
            assert hashlib.sha256(downloaded).hexdigest()==entry['sha256']
            manifest=json.loads(downloaded);assert manifest['run_id']==job
            receipt=self.receipt(job,run['attempt']);assert receipt['resident']['group_exited'] and receipt['resident']['returncode']==0
            record={'id':job,'mode':mode,'attempt':run['attempt'],'counts':counts,'verified_original_count':4,
                    'download_sha256':entry['sha256'],'receipt':receipt}
            if mode=='dual_source_replay':
                snapshot=self.get(route+'/shared-query?'+urlencode({'action':'get','logical_root':'history/snapshots','path':json.dumps([15,'revision_number'])}))
                assert snapshot==11
                record['snapshot_15_revision']=snapshot
            self.report['runs'].append(record);self.save()
        after=self.worker_identity();assert before==after,'baseline recreated worker'
        assert containers_before==sorted(self.compose('ps','-q').splitlines()),'baseline created per-attempt containers'
        self.report['baseline_same_worker']=True
        self.phase='cancel';self.save()

    def frozen(self):
        code="""import json,os,pathlib,signal,time
root=pathlib.Path('/state/control/jobs');old=set(root.glob('*/attempt-1.worker/child.pid'))
print('ready',flush=True)
end=time.monotonic()+45
while time.monotonic()<end:
 for path in set(root.glob('*/attempt-1.worker/child.pid'))-old:
  try:
   pid=int(path.read_text());os.killpg(pid,signal.SIGSTOP)
   print(json.dumps({'id':path.parents[1].name,'child_pid':pid}),flush=True);raise SystemExit(0)
  except (ProcessLookupError,ValueError):pass
 time.sleep(.001)
raise SystemExit(2)
"""
        watcher=subprocess.Popen(self.dc+['exec','-T','resident-worker','python3','-u','-c',code],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert watcher.stdout.readline().strip()=='ready'
            job=self.submit()
            out,err=watcher.communicate(timeout=50)
            assert watcher.returncode==0,'failed to freeze generated fixture'
            frozen=json.loads(out);assert frozen['id']==job
            return job,frozen
        finally:
            if watcher.poll() is None:watcher.terminate();watcher.wait(timeout=5)

    def lifecycle(self):
        job,frozen=self.frozen();self.post('/runs/'+job+'/cancel',{})
        run=self.terminal(job,'cancelled',90);receipt=self.receipt(job,run['attempt'])
        assert receipt['resident']['group_exited']
        live=json.loads(self.execute('resident-worker',"""import json,pathlib,sys
pg=int(sys.argv[1]);live=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  f=(p/'stat').read_text().rsplit(')',1)[1].split()
  if int(f[2])==pg and f[0]!='Z':live.append(int(p.name))
 except FileNotFoundError:pass
print(json.dumps(live))
""",str(frozen['child_pid'])))
        assert not live
        self.report['cancel']={'id':job,'state':run['state'],'group_exited':True,'live_group_members':live};self.save()
        self.phase='pid1_recovery';self.save();job,frozen=self.frozen();before=self.worker_identity()
        self.compose('kill','-s','SIGKILL','resident-worker')
        self.compose('up','-d','--no-build','resident-worker')
        run=self.terminal(job,seconds=240);after=self.worker_identity()
        assert run['attempt']==2 and before['generation']['generation']!=after['generation']['generation']
        assert before['generation']['deployment_id']==after['generation']['deployment_id']
        history=run['attempt_history'];assert len(history)==2
        assert sum(r['publication_state']=='published' for r in history)==1
        old=history[0]['exit_evidence']['resident']
        assert old['version']=='resident-compose-terminated-1' and old['generation']==before['generation']['generation']
        assert history[1]['exit_evidence']['resident']['version']=='resident-guardian-1'
        self.report['pid1_recovery']={'id':job,'state':run['state'],'attempt':run['attempt'],
            'before_generation':before['generation'],'after_generation':after['generation'],
            'single_published_attempt':True,'history':history}
        self.phase='restart';self.save()
        # A normal user restart reuses generated secrets, DB, storage and migration ledger.
        previous=[r['id'] for r in self.report['runs']]
        self.compose('down','--remove-orphans','--timeout','20')
        self.compose('up','-d','--no-build','--wait','--wait-timeout','300')
        self.wait(lambda:self.raw('/health/ready') is not None,120)
        self.post('/session',{'username':self.app['bootstrap_admin_username'],'password':self.app['bootstrap_admin_password']})
        restarted_app=json.loads(self.execute('api',"import json;print(json.dumps(json.load(open('/etc/cpag/app.json'))))"))
        assert all(restarted_app[key]==self.app[key] for key in ('bootstrap_admin_username','bootstrap_admin_password','database_url'))
        assert all(self.state(job)['state']=='succeeded' for job in previous)
        assert self.get('/runs/'+previous[0]+'/result')['manifest']['counts']['operations']==1
        self.report['restart_preserves_runs']=True

    def run(self):
        try:
            self.prepare();self.baseline();self.lifecycle();self.phase='done';self.report['status']='passed'
        except Exception as error:
            self.report['status']='failed';self.report['failure']={'phase':self.phase,'error_type':type(error).__name__}
            if isinstance(error,HTTPError):
                self.report['failure'].update(http_status=error.code,http_path=urlsplit(error.url).path)
            raise
        finally:
            self.save()
            if self.launched and self.report['status']=='failed':
                try:
                    (self.out/'compose-private.log').write_text(self.compose('logs','--no-color','--tail','150'))
                    (self.out/'compose-private-status.json').write_text(self.compose('ps','--all','--format','json'))
                    # Relay has no secret mounts/env and access logging is off.
                    (self.public/'relay.log').write_text(self.compose('logs','--no-color','--tail','150','relay'))
                    raw=self.compose('ps','--all','--format','json')
                    values=json.loads(raw) if raw.lstrip().startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
                    (self.public/'service-states.json').write_text(json.dumps([{key:row.get(key) for key in ('Service','State','Health','ExitCode')} for row in values],indent=2)+'\n')
                except Exception: pass
            if self.launched and not self.args.keep:
                self.compose('down','--volumes','--remove-orphans','--timeout','20')


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path);parser.add_argument('--project')
    parser.add_argument('--keep',action='store_true',help='retain only the disposable test stack for diagnosis')
    args=parser.parse_args();Smoke(args).run()


if __name__=='__main__':main()
