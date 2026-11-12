"""Kubernetes control plane for a claimed CPAG attempt. No host runtime socket."""
import json
from pathlib import Path
from urllib.error import HTTPError
import ssl
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from .kube_exit import termination


class JobControl:
    def __init__(self, account=Path('/var/run/secrets/kubernetes.io/serviceaccount')):
        self.account = account
        if (account/'namespace').read_text().strip() != 'cpag':
            raise ValueError('wrong compute namespace')
        tls = ssl.create_default_context(cafile=str(account/'ca.crt'))
        self.client = build_opener(ProxyHandler({}), HTTPSHandler(context=tls))

    def request(self, method, path, value=None, patch=False):
        token = (self.account/'token').read_text().strip()
        req = Request('https://kubernetes.default.svc'+path, method=method,
                      data=None if value is None else json.dumps(value).encode(),
                      headers={'Authorization': 'Bearer '+token, 'Content-Type':
                               'application/json-patch+json' if patch else 'application/json'})
        with self.client.open(req, timeout=10) as res:
            data = res.read(4*1024*1024+1)
        if len(data) > 4*1024*1024:
            raise ValueError('control response exceeded limit')
        return json.loads(data)

    jobs = '/apis/batch/v1/namespaces/cpag/jobs'

    def get(self, name):
        try:
            return self.request('GET', self.jobs+'/'+name)
        except HTTPError as error:
            if error.code == 404:
                return None
            raise

    def pods(self, uid):
        value = self.request('GET', '/api/v1/namespaces/cpag/pods?labelSelector=batch.kubernetes.io%2Fcontroller-uid%3D'+uid)
        if value['metadata'].get('continue'):
            raise ValueError('incomplete pod inventory')
        return value['items']

    def stop(self, job):
        # Keep the Job and Pod until kubelet termination is durably recorded.
        # Deleting them here would destroy the evidence needed by cancellation.
        if job['spec'].get('activeDeadlineSeconds') == 1:
            return
        return self.request('PATCH', self.jobs+'/'+job['metadata']['name'], [
            {'op':'test', 'path':'/metadata/uid', 'value':job['metadata']['uid']},
            {'op':'add', 'path':'/spec/activeDeadlineSeconds', 'value':1}], patch=True)

    def release_exit(self, uid):
        # Called only after the private receipt and coordinator acknowledgement.
        for pod in self.pods(uid):
            meta=pod['metadata'];finalizers=meta.get('finalizers',[])
            if 'cpag.montp3.pro/exit-evidence' not in finalizers:
                continue
            owners=[r for r in meta.get('ownerReferences',[]) if r.get('controller')]
            if len(owners)!=1 or owners[0]['uid']!=uid or owners[0]['kind']!='Job':
                raise ValueError('pod owner mismatch during release')
            self.request('PATCH','/api/v1/namespaces/cpag/pods/'+meta['name'],[
                {'op':'test','path':'/metadata/uid','value':meta['uid']},
                {'op':'test','path':'/metadata/finalizers','value':finalizers},
                {'op':'replace','path':'/metadata/finalizers','value':[v for v in finalizers if v!='cpag.montp3.pro/exit-evidence']}],patch=True)

    def create_suspended(self, manifest):
        if manifest['spec']['suspend'] is not True:
            raise ValueError('job must start suspended')
        return self.request('POST', self.jobs, manifest)

    def activate(self, job):
        # The patch cannot start a replacement Job with the same name.
        m = job['metadata']
        return self.request('PATCH', self.jobs+'/'+m['name'], [
            {'op': 'test', 'path': '/metadata/uid', 'value': m['uid']},
            {'op': 'test', 'path': '/spec/suspend', 'value': True},
            {'op': 'replace', 'path': '/spec/suspend', 'value': False}], patch=True)

    def observe_exit(self, name, uid, claim):
        job = self.request('GET', self.jobs+'/'+name)
        if job['metadata']['uid'] != uid:
            raise ValueError('replacement job cannot prove termination')
        return termination(job, self.pods(uid), job_uid=uid, run_id=claim['id'],
                           attempt=claim['attempt'], worker=claim['worker'])

    def remove(self, name, uid):
        return self.request('DELETE', self.jobs+'/'+name, {
            'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground',
            'preconditions':{'uid':uid}})
