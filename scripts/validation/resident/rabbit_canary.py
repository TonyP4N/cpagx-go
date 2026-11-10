"""Opt-in isolated RabbitMQ fixture and adversarial canary checks; no production resources."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
from urllib.parse import quote
import uuid

BROKER_IMAGE='mirror.gcr.io/library/rabbitmq@sha256:e582c0bc7766f3342496d8485efb5a1df782b5ce3886ad017e2eaae442311f69'
QUEUE='cpag.v3.tasks'

class Canary:
    def __init__(self, lab, credentials):
        self.lab=lab; self.credentials=credentials
        self.user='fixture-admin'; self.password=secrets.token_hex(24)
        self.consumer_password=secrets.token_hex(24); self.publisher_password=secrets.token_hex(24)
        self.dispatcher=secrets.token_hex(32)
        self.broker_url='amqp://canary-consumer:'+self.consumer_password+'@cpag-rabbitmq:5672/cpag-canary'
        self.publisher_url='amqp://canary-publisher:'+self.publisher_password+'@cpag-rabbitmq:5672/cpag-canary'
        self.report={'scope':'isolated RabbitMQ canary; synthetic only; no capacity acceptance','broker_image':BROKER_IMAGE,'vhost':'cpag-canary','queue':QUEUE}

    def setup(self):
        L=self.lab
        secret=L.obj('Secret','cpag-rabbit-fixture',stringData={'RABBITMQ_DEFAULT_USER':self.user,'RABBITMQ_DEFAULT_PASS':self.password,'RABBITMQ_DEFAULT_VHOST':'cpag-canary'})
        deploy=L.obj('StatefulSet','cpag-rabbitmq',spec={'serviceName':'cpag-rabbitmq','replicas':1,'selector':{'matchLabels':{'app':'cpag-rabbitmq'}},'template':{'metadata':{'labels':{'app':'cpag-rabbitmq'}},'spec':{'automountServiceAccountToken':False,'containers':[{'name':'rabbitmq','image':BROKER_IMAGE,'envFrom':[{'secretRef':{'name':'cpag-rabbit-fixture'}}],'env':[{'name':'RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS','value':'-rabbit consumer_timeout 7200000'},{'name':'RABBITMQ_NODENAME','value':'rabbit@cpag-rabbitmq-0'}],'ports':[{'containerPort':5672},{'containerPort':15672}],'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'1','memory':'768Mi'}},'readinessProbe':{'exec':{'command':['rabbitmq-diagnostics','-q','check_running']},'initialDelaySeconds':10,'periodSeconds':5},'volumeMounts':[{'name':'data','mountPath':'/var/lib/rabbitmq'}]}],'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'cpag-rabbit-data'}}]}}});deploy['apiVersion']='apps/v1'
        service=L.obj('Service','cpag-rabbitmq',spec={'selector':{'app':'cpag-rabbitmq'},'ports':[{'name':'amqp','port':5672,'targetPort':5672},{'name':'management','port':15672,'targetPort':15672}]})
        policy=L.obj('NetworkPolicy','cpag-rabbit-fixture-private',spec={'podSelector':{'matchLabels':{'app':'cpag-rabbitmq'}},'policyTypes':['Ingress'],'ingress':[{'from':[{'podSelector':{'matchLabels':{'app':'cpag-worker'}}},{'podSelector':{'matchLabels':{'app':'cpag-celery-publisher'}}}],'ports':[{'protocol':'TCP','port':5672}]},{'from':[{'podSelector':{'matchLabels':{'app':'cpag-api'}}},{'podSelector':{'matchLabels':{'app':'cpag-rabbit-bootstrap'}}}],'ports':[{'protocol':'TCP','port':15672}]}]});policy['apiVersion']='networking.k8s.io/v1'
        L.apply([secret,L.obj('PersistentVolumeClaim','cpag-rabbit-data',spec={'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'1Gi'}}}),deploy,service,policy]);L.run(L.K+['-n','cpag','rollout','status','statefulset/cpag-rabbitmq','--timeout=240s'])
        for user,password in [('canary-consumer',self.consumer_password),('canary-publisher',self.publisher_password)]:
            L.run(L.K+['-n','cpag','exec','cpag-rabbitmq-0','--','rabbitmqctl','add_user',user,password],stdout=subprocess.DEVNULL)
        for user,permissions in [('canary-consumer',['^$','^$','^cpag\\.v3\\.tasks$']),('canary-publisher',['^cpag\\.v3\\.tasks$','^cpag\\.v3\\.tasks$','^$'])]:
            L.run(L.K+['-n','cpag','exec','cpag-rabbitmq-0','--','rabbitmqctl','set_permissions','-p','cpag-canary',user,*permissions],stdout=subprocess.DEVNULL)
        self.report['client_permissions']={'consumer':'read-only dedicated queue, no management tag','publisher':'configure/write dedicated queue/exchange, no management tag'}

    @staticmethod
    def private_config_init(image, source, target):
        return {'name':'prepare-celery-config','image':image,'imagePullPolicy':'Never','command':['sh','-ec','mkdir -p '+target+'; chmod 0700 '+target+'; cp '+source+'/config.json '+target+'/config.json; chown 65531:65531 '+target+' '+target+'/config.json; chmod 0400 '+target+'/config.json'],'volumeMounts':[{'name':'celery-secret','mountPath':source,'readOnly':True},{'name':'celery-config','mountPath':target}]}

    def configure(self,app,resources,images):
        L=self.lab;app['dispatcher_token']=self.dispatcher
        bootstrap_code='''import base64,json,os,time,urllib.request
url='http://cpag-rabbitmq:15672/api/';auth=base64.b64encode((os.environ['RABBITMQ_DEFAULT_USER']+':'+os.environ['RABBITMQ_DEFAULT_PASS']).encode()).decode()
def request(path,body,method):
 r=urllib.request.Request(url+path,data=json.dumps(body).encode(),method=method,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
 with urllib.request.urlopen(r,timeout=10) as response:return response.read()
for n in range(60):
 try:
  request('exchanges/cpag-canary/cpag.v3.tasks',{'type':'direct','durable':True},'PUT');break
 except OSError:time.sleep(1)
else:raise RuntimeError('fixture management unavailable')
request('queues/cpag-canary/cpag.v3.tasks',{'durable':True,'arguments':{'x-queue-type':'quorum'}},'PUT')
request('bindings/cpag-canary/e/cpag.v3.tasks/q/cpag.v3.tasks',{'routing_key':'cpag.v3.tasks'},'POST')
'''
        bootstrap=L.obj('Pod','cpag-rabbit-bootstrap',spec={'restartPolicy':'Never','automountServiceAccountToken':False,'containers':[{'name':'setup','image':images['api'],'imagePullPolicy':'Never','envFrom':[{'secretRef':{'name':'cpag-rabbit-fixture'}}],'command':['python3','-c',bootstrap_code]}]})
        bootstrap['metadata']['labels']={'app':'cpag-rabbit-bootstrap'}
        L.apply([bootstrap]);L.run(L.K+['-n','cpag','wait','--for=jsonpath={.status.phase}=Succeeded','pod/cpag-rabbit-bootstrap','--timeout=120s']);L.run(L.K+['-n','cpag','delete','pod/cpag-rabbit-bootstrap'])
        consumer={'broker_url':self.broker_url,'queue':QUEUE,'supervisor_socket':'/dispatch/supervisor.sock','worker_name':'resident-celery'}
        publisher={'broker_url':self.publisher_url,'queue':QUEUE,'api_url':'http://cpag-resident-internal:8096','dispatcher_token':self.dispatcher,'publisher_id':'resident-publisher','poll_seconds':.5}
        L.apply([L.obj('Secret','cpag-celery-consumer',stringData={'config.json':json.dumps(consumer)}),L.obj('Secret','cpag-celery-publisher',stringData={'config.json':json.dumps(publisher)}),L.obj('Secret','cpag-dispatcher',stringData={'token':self.dispatcher})])
        worker=next(r for r in resources if r['kind']=='Deployment' and r['metadata']['name']=='cpag-worker')['spec']['template']['spec']
        worker['containers'][0]['command'][-1]=worker['containers'][0]['command'][-1].replace('umask 077;', 'umask 077; chmod 0700 /dispatch;')+' --dispatch-mode hybrid --dispatch-socket /dispatch/supervisor.sock'
        worker['containers'][0]['volumeMounts'].append({'name':'dispatch','mountPath':'/dispatch'})
        worker['volumes'] += [{'name':'dispatch','emptyDir':{}},{'name':'celery-secret','secret':{'secretName':'cpag-celery-consumer','defaultMode':256}},{'name':'celery-config','emptyDir':{'medium':'Memory','sizeLimit':'1Mi'}}]
        worker['initContainers']=[self.private_config_init(images['worker'],'/celery-secret','/celery')]
        consumer_container={'name':'celery-consumer','image':images['worker'],'imagePullPolicy':'Never','command':['python3','-m','cpag_worker.celery_v3','--config','/celery/config.json'],'securityContext':{'runAsUser':65531,'runAsGroup':65531,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},'resources':{'requests':{'cpu':'20m','memory':'64Mi'},'limits':{'cpu':'500m','memory':'256Mi'}},'volumeMounts':[{'name':'dispatch','mountPath':'/dispatch'},{'name':'celery-config','mountPath':'/celery','readOnly':True}]}
        worker['containers'].append(consumer_container)
        api=next(r for r in resources if r['kind']=='Deployment' and r['metadata']['name']=='cpag-api')['spec']['template']['spec']
        api['volumes'].append({'name':'dispatcher-token','secret':{'secretName':'cpag-dispatcher','defaultMode':256}})
        next(c for c in api['containers'] if c['name']=='private-relay')['volumeMounts'].append({'name':'dispatcher-token','mountPath':'/etc/cpag-dispatch','readOnly':True})
        publisher_container={**consumer_container,'name':'publisher','command':['python3','-m','cpag_worker.celery_publisher','--config','/celery/config.json'],'volumeMounts':[{'name':'celery-config','mountPath':'/celery','readOnly':True}]}
        publisher_pod={'automountServiceAccountToken':False,'initContainers':[self.private_config_init(images['worker'],'/celery-secret','/celery')],'containers':[publisher_container],'volumes':[{'name':'celery-secret','secret':{'secretName':'cpag-celery-publisher','defaultMode':256}},{'name':'celery-config','emptyDir':{'medium':'Memory','sizeLimit':'1Mi'}}]}
        deployment=L.obj('Deployment','cpag-celery-publisher',spec={'replicas':1,'selector':{'matchLabels':{'app':'cpag-celery-publisher'}},'template':{'metadata':{'labels':{'app':'cpag-celery-publisher'}},'spec':publisher_pod}});deployment['apiVersion']='apps/v1';resources.append(deployment)
        policy=next(r for r in resources if r['kind']=='NetworkPolicy' and r['metadata']['name']=='cpag-api-resident-private')
        policy['spec']['ingress'][1]['from'].append({'podSelector':{'matchLabels':{'app':'cpag-celery-publisher'}}})

    def api_request(self,path,body):
        code='''import json,sys,http.cookiejar,urllib.request
v=json.load(sys.stdin);jar=http.cookiejar.CookieJar();op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));base='http://127.0.0.1:8095'
def post(p,b):
 r=urllib.request.Request(base+'/api/v3'+p,data=json.dumps(b).encode(),headers={'Content-Type':'application/json'});return json.load(op.open(r,timeout=30))
post('/session',{'username':'lab-admin','password':v['password']}); print(json.dumps(post(v['path'],v['body'])))
'''
        return json.loads(subprocess.check_output(self.lab.K+['-n','cpag','exec','-i','deployment/cpag-api','-c','api','--','python3','-c',code],input=json.dumps({'password':self.credentials['admin'],'path':path,'body':body}),text=True))

    def activate(self,app):
        datasets=[self.api_request('/datasets',{'name':name,'source_kind':'synthetic','source':'canary fixture','batch':'rabbitmq-isolated','authorization_ref':'generated test material'})['dataset']['id'] for name in ('Rabbit baseline','Rabbit outage')]
        app.update(dispatch_mode='rabbit-canary',rabbit_canary_dataset_ids=datasets)
        self.lab.apply([self.lab.obj('Secret','cpag-app-config',stringData={'app.json':json.dumps(app)})])
        self.lab.run(self.lab.K+['-n','cpag','rollout','restart','deployment/cpag-api'])
        self.lab.run(self.lab.K+['-n','cpag','rollout','status','deployment/cpag-api','--timeout=180s'])
        return datasets

    def management(self,path,body=None):
        code='''import json,sys,urllib.request,base64
v=json.load(sys.stdin);auth=base64.b64encode((v['user']+':'+v['password']).encode()).decode();data=None if v['body'] is None else json.dumps(v['body']).encode();r=urllib.request.Request('http://cpag-rabbitmq:15672/api/'+v['path'],data=data,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'});print(urllib.request.urlopen(r,timeout=15).read().decode())
'''
        payload={'user':self.user,'password':self.password,'path':path,'body':body}
        return json.loads(subprocess.check_output(self.lab.K+['-n','cpag','exec','-i','deployment/cpag-api','-c','api','--','python3','-c',code],input=json.dumps(payload),text=True))

    def duplicate(self,job,dispatch):
        # Native Celery protocol2 JSON body, same task args and an independent delivery id.
        body=base64.b64encode(json.dumps([[job,dispatch],{}, {'callbacks':None,'errbacks':None,'chain':None,'chord':None}]).encode()).decode()
        payload={'properties':{'delivery_mode':2,'content_type':'application/json','content_encoding':'utf-8','headers':{'lang':'py','task':'cpag.v3.execute','id':str(uuid.uuid4())}},'routing_key':QUEUE,'payload':body,'payload_encoding':'base64'}
        assert self.management('exchanges/cpag-canary/'+quote(QUEUE,safe='')+'/publish',payload)['routed']

    def broker(self,enabled):
        self.lab.run(self.lab.K+['-n','cpag','scale','statefulset/cpag-rabbitmq','--replicas='+str(int(enabled))])
        if enabled:self.lab.run(self.lab.K+['-n','cpag','rollout','status','statefulset/cpag-rabbitmq','--timeout=240s'])
        else:self.lab.run(self.lab.K+['-n','cpag','wait','--for=delete','pod','-l','app=cpag-rabbitmq','--timeout=120s'])

    def save(self):
        (self.lab.OUT/'rabbit-canary.json').write_text(json.dumps(self.report,indent=2)+'\n')

    def exercise(self,baseline,outage_dataset,env,replay,offline_profile,replay_profile,sql):
        L=self.lab
        def rows(job):
            return json.loads(sql("SELECT row_to_json(t) FROM (SELECT j.id,j.state,j.attempt,j.dispatch_id,j.dispatch_partition,(SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=j.id) attempts,(SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=j.id AND a.publication_state='published') published FROM m4_jobs j WHERE j.id='"+job+"') t"))
        def wait_value(check,seconds=180):
            end=time.monotonic()+seconds
            while time.monotonic()<end:
                result=check()
                if result:return result
                time.sleep(.5)
            raise TimeoutError('Rabbit canary condition timed out')
        baseline_rows=[rows(r['id']) for r in baseline['runs']]
        assert all(r['dispatch_partition']=='rabbit-v3' and r['attempt']==1 and r['published']==1 for r in baseline_rows)
        self.report['baseline_partitions']=baseline_rows;self.save()
        source=baseline['runs'][0]['id'];before=rows(source)
        assert before['dispatch_partition']=='rabbit-v3' and before['attempt']==1 and before['published']==1
        for _ in range(4):self.duplicate(source,before['dispatch_id'])
        wait_value(lambda:self.management('queues/cpag-canary/'+quote(QUEUE,safe='')).get('messages',1)==0)
        time.sleep(2);after=rows(source);assert after==before
        self.report['duplicate']={'deliveries':4,'before':before,'after':after,'same_attempt_and_single_publication':True};self.save()
        # Leave one persistent delivery ready across an actual broker process/pod restart.
        L.run(L.K+['-n','cpag','scale','deployment/cpag-worker','--replicas=0'])
        L.run(L.K+['-n','cpag','wait','--for=delete','pod','-l','app=cpag-worker','--timeout=120s'])
        self.duplicate(source,before['dispatch_id'])
        ready_before=wait_value(lambda:(lambda q:q if q.get('messages_ready',0)>=1 else None)(self.management('queues/cpag-canary/'+quote(QUEUE,safe=''))))
        pvc_before=json.loads(L.output(L.K+['-n','cpag','get','pvc','cpag-rabbit-data','-o','json']))['metadata']['uid']
        self.broker(False);self.broker(True)
        ready_after=wait_value(lambda:(lambda q:q if q.get('messages_ready',0)>=1 else None)(self.management('queues/cpag-canary/'+quote(QUEUE,safe=''))))
        pvc_after=json.loads(L.output(L.K+['-n','cpag','get','pvc','cpag-rabbit-data','-o','json']))['metadata']['uid'];assert pvc_before==pvc_after
        self.report['persistent_restart']={'pvc_unchanged':True,'ready_before':ready_before['messages_ready'],'ready_after':ready_after['messages_ready'],'durable':ready_after['durable'],'queue_type':ready_after['type']};self.save()
        assert ready_after['durable'] and ready_after['type']=='quorum'
        L.run(L.K+['-n','cpag','scale','deployment/cpag-worker','--replicas=1'])
        L.run(L.K+['-n','cpag','rollout','status','deployment/cpag-worker','--timeout=180s'])
        wait_value(lambda:self.management('queues/cpag-canary/'+quote(QUEUE,safe='')).get('messages',1)==0)
        assert rows(source)==before
        self.broker(False)
        result=L.OUT/'rabbit-outage-workbench.json';result.unlink(missing_ok=True)
        child=subprocess.Popen(['node',str(L.HERE/'workbench.cjs'),str(replay),str(offline_profile),str(replay_profile),str(result)],env={**env,'CPAG_TEST_DATASET':outage_dataset})
        try:
            def submitted():
                if result.exists():
                    runs=json.loads(result.read_text()).get('runs',[])
                    if runs:return runs[0]['id']
            job=wait_value(submitted,90);queued=rows(job)
            assert queued['state']=='queued' and queued['attempt']==0 and queued['dispatch_partition']=='rabbit-v3'
            pending=int(sql("SELECT count(*) FROM m4_dispatch_outbox WHERE job_id='"+job+"' AND confirmed_at IS NULL AND invalidated_at IS NULL"));assert pending==1
            # Poll remains available only for its own explicitly separate partition.
            poll=secrets.token_hex(16)
            sql("INSERT INTO m4_jobs(id,max_attempts,payload,dispatch_partition) SELECT '"+poll+"',2,payload,'poll' FROM m4_jobs WHERE id='"+source+"'")
            poll_done=wait_value(lambda:(lambda r:r if r['state']=='succeeded' else None)(rows(poll)))
            assert rows(job)['state']=='queued', 'poll scan consumed Rabbit partition during outage'
            self.report['outage_before_restore']={'rabbit_job':queued,'pending_outbox':pending,'poll_job':poll_done,'rabbit_still_queued':True};self.save()
            self.broker(True)
            assert child.wait(timeout=300)==0, 'outage workbench failed'
            result_json=json.loads(result.read_text());completed=[rows(r['id']) for r in result_json['runs']]
            assert len(completed)==2 and all(r['state']=='succeeded' and r['attempt']==1 and r['published']==1 for r in completed)
            self.report['outage_catchup']={'runs':completed,'workbench':result_json,'no_new_attempts_or_duplicate_publications':True};self.save()
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=10)
            # Broker is a test fixture; restore it for cancellation/restart drills.
            self.broker(True)
