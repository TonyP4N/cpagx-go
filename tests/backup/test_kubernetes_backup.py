"""Format7 compatibility without relaxing identity/integrity gates."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[2]/'scripts/backup'),str(Path(__file__).resolve().parents[2]/'services/analysis/src')]
import bundle
import terminal_shared as terminal
from postgres_target import KubernetesPostgres,DeploymentDatabases,deployment_databases,database_command
import kubernetes_ops as ops

JOB='ea28a1ad-8246-4420-8993-ddcee4256df1';POD='0c3a6291-1ec0-4550-9220-62c135c8cedc'
class KubernetesBackup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.a={'job_id':'a'*32,'attempt':1,'worker':'worker-01','attempt_token':'fixture-token','exited_at':'2026-11-05T00:00:00Z',
                'location':'kubernetes:'+POD,'container_id':JOB,'executor_kind':'kubernetes-job-v1','publication_state':'published'}
        self.k={'version':'kubernetes-termination-1','run_id':self.a['job_id'],'attempt':1,'worker':self.a['worker'],'namespace':'cpag',
                'job_uid':JOB,'pod_uid':POD,'container_id':'containerd://'+'b'*64,'finished_at':'2026-11-05T00:00:00Z','exit_code':0}
        self.a['exit_receipt']={'id':self.a['job_id'],'attempt':1,'worker':self.a['worker'],'token':self.a['attempt_token'],
                               'scope':'kubernetes-job','location':self.a['location'],'container_id':JOB,'exited':True,'kubernetes':self.k}
    def test_kube_receipt_accepts_exact_binding_rejects_mutation(self):
        terminal._attempt_exit(self.a)
        for key,value in [('attempt',2),('job_uid',POD),('pod_uid',JOB),('container_id','containerd://missing'),('finished_at',''),('exit_code',True),('exit_code',143)]:
            a=copy.deepcopy(self.a);a['exit_receipt']['kubernetes'][key]=value
            with self.subTest(key=key,value=value),self.assertRaisesRegex(ValueError,'Kubernetes'):terminal._attempt_exit(a)
    def test_nonstart_is_not_publishable(self):
        self.a['publication_state']='fenced'
        self.a['exit_receipt']['kubernetes']={**{k:self.k[k] for k in ('run_id','attempt','worker','namespace','job_uid','finished_at')},
                                              'version':'kubernetes-not-started-1','removed':True,'suspended':True}
        terminal._attempt_exit(self.a)
        self.a['publication_state']='published'
        with self.assertRaises(ValueError):terminal._attempt_exit(self.a)
    def test_sidecar_v1_history_and_v2_nonce_are_both_bound(self):
        run=self.a['job_id'];nonce='c'*64
        v={'job_id':run,'attempt':1,'state':'exited','exited_at':'2026-11-05T00:00:00Z','container_name':nonce}
        row={'id':run,'attempt':1,'state':'succeeded','payload':{'storage_format':'shared-observation-dag-6'},'artifact_sha256':'d'*64}
        receipt={'version':'service-sidecar-verification-2','verification_id':nonce,'run_id':run,'attempt_id':1,'publication_sha256':'d'*64,
                 'status':200,'ended_at':'2026-11-05T00:00:00Z','cleanup_completed':True}
        path=self.root/f'compact-verification-{run}-1-{nonce[:12]}.json'
        def check(r):
            path.write_text(json.dumps(r));return terminal.audit_exits([row],[self.a],[v],self.root,bundle.safe)
        self.assertTrue(check(receipt)['valid'])
        legacy={**receipt,'version':'service-sidecar-verification-1'};legacy.pop('verification_id');self.assertTrue(check(legacy)['valid'])
        for k,val in [('verification_id','e'*64),('attempt_id',2),('status',500),('cleanup_completed',False),('publication_sha256','e'*64),('ended_at','bad')]:
            with self.subTest(k=k),self.assertRaises(ValueError):check({**receipt,k:val})
    def test_scoped_transport_pins_pod_and_does_not_change_docker(self):
        self.assertEqual(database_command('pg',['psql']),['docker','exec','-i','pg','psql'])
        endpoint=KubernetesPostgres('default','cpag','cpag-postgres-abc',POD)
        policy=DeploymentDatabases(endpoint.pod,'cpag_app','cpag_restore',endpoint)
        with deployment_databases(policy),patch('postgres_target.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=POD)):
            args=database_command(endpoint.pod,['createdb','-U','postgres','cpag_restore'],False)
            self.assertEqual(args[-4:],['createdb','-U','postgres','cpag_restore']);self.assertIn('kubectl',args)
            with self.assertRaises(ValueError):database_command('other-pod',['psql'])
        with deployment_databases(policy),patch('postgres_target.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=JOB)):
            with self.assertRaisesRegex(ValueError,'replaced'):database_command(endpoint.pod,['psql'])
        self.assertEqual(database_command('pg',['psql']),['docker','exec','-i','pg','psql'])
    def test_runtime_mapping_uses_captured_ledger_after_inventory_check(self):
        (self.root/'capacity.json').write_text(json.dumps({'root':'/state/shared','reservations':{'job:1':1234}}))
        with self.assertRaisesRegex(ValueError,'explicit container runtime mapping'):
            terminal.capacity_source_root(self.root,'/host/pvc')
        original=terminal.capacity_source_root(self.root,'/host/pvc',True)
        result=terminal.rebase_capacity(self.root,original,'/state/restored')
        self.assertEqual(result['old'],'/state/shared');self.assertEqual(result['new'],'/state/restored')
        self.assertEqual(json.loads((self.root/'capacity.json').read_text())['reservations'],{'job:1':1234})
        with self.assertRaises(ValueError):terminal.rebase_capacity(self.root,'/incorrect/source','/new')
    def test_live_backup_refused_and_failed_backup_resumes_same_deployment(self):
        c={'context':'default','namespace':'cpag','namespace_uid':POD,'app_uid':JOB,'app_deployment':'cpag-api'}
        app={'spec':{'replicas':1,'selector':{'matchLabels':{'app':'cpag-api'}}},'metadata':{'resourceVersion':'1'}}
        with patch.object(ops,'deployment',return_value=app),patch.object(ops,'replicas') as scale:
            with self.assertRaisesRegex(ValueError,'running deployment'):
                with ops.stopped(c,False):self.fail('must not run backup')
            scale.assert_not_called()
        zero=copy.deepcopy(app);zero['spec']['replicas']=0
        with patch.object(ops,'deployment',side_effect=[app,zero,zero]),patch.object(ops,'replicas') as scale,patch.object(ops,'kubectl',return_value={'items':[]}):
            with self.assertRaisesRegex(RuntimeError,'backup failed'):
                with ops.stopped(c,True):raise RuntimeError('backup failed')
            self.assertEqual([x.args[2] for x in scale.call_args_list],[0,1])

if __name__=='__main__':unittest.main()
