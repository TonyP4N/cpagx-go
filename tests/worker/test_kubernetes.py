"""Kubernetes lifecycle regression: real owner logic, controlled API responses."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'services/worker'))
from cpag_worker.kube_service import KubernetesWorker
from cpag_worker.kube_job import compute_job
from cpag_worker.worker import APIError

UID='ea28a1ad-8246-4420-8993-ddcee4256df1'; POD='0c3a6291-1ec0-4550-9220-62c135c8cedc'
IMAGE='test/image@sha256:'+'f'*64

def claim():
    p={'kind':'dual-source','capacity_profile':'engineering-core-capacity-3','storage_format':'shared-observation-dag-6',
       'resource_profile':'storage-budget-2','storage_budget_version':'shared-storage-budget-2',
       'network':{'path':'inputs/a.pcap','sha256':'a'*64},'process':{'path':'inputs/p.csv','sha256':'b'*64},'profile':{'path':'inputs/c.json','sha256':'c'*64}}
    return {'id':'a'*32,'attempt':1,'worker':'worker-01','token':'private-fixture-token','output_dir':'jobs/'+'a'*32+'/attempt-1','payload':p}

class Kube:
    def __init__(self,c):
        self.job=compute_job(c,c['worker'],IMAGE);self.job['metadata']['uid']=UID
        self.job['spec']['suspend']=False
        self.pod={'metadata':{'uid':POD,'namespace':'cpag','labels':self.job['metadata']['labels'],
                             'ownerReferences':[{'uid':UID,'kind':'Job','controller':True}]},'status':{'phase':'Running','containerStatuses':[]}}
        self.removed=False;self.stops=0
    def get(self,name):return None if self.removed else self.job
    def pods(self,uid):return [] if self.removed or self.job['spec']['suspend'] else [self.pod]
    def stop(self,job):self.stops+=1;job['spec']['activeDeadlineSeconds']=1
    def remove(self,name,uid):self.removed=True
    def release_exit(self,uid):pass
    def terminated(self,code=143):
        cid='containerd://'+'b'*64
        self.pod['status']={'phase':'Failed','containerStatuses':[{'name':'compute','restartCount':0,'containerID':cid,
                             'state':{'terminated':{'containerID':cid,'exitCode':code,'finishedAt':'2026-11-05T01:00:00Z'}}}]}

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.c=claim();self.calls=[];self.st={'state':'running','attempt':1,'lease_valid':True,'payload':self.c['payload']}
        self.w=KubernetesWorker.__new__(KubernetesWorker);self.w.root=self.root/'shared';self.w.root.mkdir()
        self.w.control=self.root/'control';self.w.control.mkdir();self.w.journal=self.w.control/'kube-active.json'
        self.w.location='kubernetes:'+POD;self.w.worker=self.c['worker'];self.w.config={'image':IMAGE}
        self.w.kube=Kube(self.c)
        outer=self
        class API:
            def post(self,path,body):
                outer.calls.append((path,body))
                if path=='/v1/claim':return copy.deepcopy(outer.c)
                if path.endswith('/heartbeat'):
                    if outer.st['state']!='running':raise APIError(409,{'state':outer.st['state']})
                    return {'ok':'true'}
                if path.endswith('/fail'):outer.st['state']='failed'
                if path.endswith('/ack-cancel'):outer.st['state']='cancelled'
                return {'ok':'true'}
        class Helper:
            stopping=False
            def get_json(self,api,path):return [] if '/executions?' in path else copy.deepcopy(outer.st)
            def capacity(self,*a,**k):pass
            def keep_lease(self,c,done,health):done.wait()
        self.w.api=self.w.coord=API();self.w.helper=Helper()
    def running_record(self):
        r={'claim':self.c,'manifest':{},'uid':UID,'registered':True,'create_requested':True,'activation_requested':True}
        self.w.save(r);return r
    def test_running_cancel_retains_pod_until_proof_then_next_claim(self):
        self.running_record();self.st['state']='cancelling'
        self.assertEqual(self.w.once(),'stopping');self.assertFalse(self.w.kube.removed)
        self.assertFalse(any(p.endswith('/ack-cancel') for p,_ in self.calls))
        self.w.kube.terminated();self.assertEqual(self.w.once(),'settled')
        self.assertEqual(self.st['state'],'cancelled');self.assertFalse(self.w.journal.exists())
        self.assertEqual([p.rsplit('/',1)[-1] for p,_ in self.calls],['exit','ack-cancel'])
    def test_unsupported_payload_fails_without_poisoning_owner(self):
        self.c['payload']['kind']='unsupported';self.w.kube.removed=True
        with patch('cpag_worker.kube_service.stage_attempt',side_effect=ValueError('unsupported mode')):
            self.assertEqual(self.w.once(),'failure_recorded')
        self.assertEqual(self.w.once(),'settled');self.assertEqual(self.st['state'],'failed')
        self.assertFalse(self.w.journal.exists())
        self.assertTrue(any(p.endswith('/not-started') for p,_ in self.calls))
    def test_missing_registered_job_never_becomes_cancelled(self):
        self.running_record();self.st['state']='cancelling';self.w.kube.removed=True
        with self.assertRaisesRegex(ValueError,'missing without exit'):self.w.once()
        self.assertTrue(self.w.journal.exists());self.assertEqual(self.st['state'],'cancelling')
    def test_receipt_survives_lost_exit_ack_and_job_removal(self):
        self.running_record();self.st['state']='cancelling';self.w.kube.terminated()
        original=self.w.coord.post
        def lost(path,body):
            if path.endswith('/exit'):raise TimeoutError('response lost')
            return original(path,body)
        self.w.coord.post=lost
        with self.assertRaises(TimeoutError):self.w.once()
        self.w.coord.post=original;self.w.kube.removed=True
        self.assertEqual(self.w.once(),'settled');self.assertEqual(self.st['state'],'cancelled')
    def test_suspended_never_activated_job_is_removed_with_bound_proof(self):
        r=self.running_record();r.pop('activation_requested');self.w.save(r)
        self.w.kube.job['spec']['suspend']=True;self.st['state']='cancelling'
        self.assertEqual(self.w.once(),'settled')
        proof=[b for p,b in self.calls if p.endswith('/exit')][0]
        self.assertEqual(proof['kubernetes']['version'],'kubernetes-not-started-1')
        self.assertTrue(proof['kubernetes']['removed']);self.assertFalse(self.w.journal.exists())
    def test_replay_build_uses_same_compact_core_and_preserves_limits(self):
        offline=compute_job(self.c,self.c['worker'],IMAGE)
        self.c['payload'].update(kind='dual-source-replay',history_format='shared-observation-dag-6',replay_version='dual-replay-1')
        replay=compute_job(self.c,self.c['worker'],IMAGE)
        container=replay['spec']['template']['spec']['containers'][0]
        self.assertEqual(container['command'][container['command'].index('--mode')+1],'replay')
        self.assertEqual(container['resources'],offline['spec']['template']['spec']['containers'][0]['resources'])
        self.assertEqual(replay['spec']['template']['metadata']['finalizers'],['cpag.montp3.pro/exit-evidence'])
    def test_old_attempt_with_exit_is_settled_without_publication(self):
        self.running_record();self.w.kube.terminated(0);self.st.update(state='queued',lease_valid=False)
        self.assertEqual(self.w.once(),'settled')
        self.assertFalse(any(p.endswith('/complete') or p.endswith('/fail') for p,_ in self.calls))

if __name__=='__main__':unittest.main()
