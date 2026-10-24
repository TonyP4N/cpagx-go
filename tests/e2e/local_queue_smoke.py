#!/usr/bin/env python3
"""Exercise only the named isolated local validation stack's worker lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
from celery import Celery

ROOT = Path(__file__).resolve().parents[2]
sys.argv = ['synthetic_http_smoke.py','--base-url','http://127.0.0.1:13000']
helpers=runpy.run_path(str(ROOT/'tests/e2e/synthetic_http_smoke.py'),run_name='helpers')
command=[sys.executable,str(ROOT/'scripts/local_validation_stack.py')]
def worker(action):
    subprocess.run(command+[action,'--only','worker'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL,timeout=25)
worker('stop')
try:
    code,raw=helpers['upload']()
    assert code == 202,(code,raw)
    task_id=json.loads(raw)['task_id']
    time.sleep(.5)
    code,raw=helpers['call']('/status/'+task_id)
    assert json.loads(raw)['status']=='queued',raw
finally:
    worker('start')
finished=helpers['poll'](task_id)
assert finished['status']=='completed',finished
root=ROOT/'.local-stack/outputs/v2'/task_id
before=(root/'result_manifest.json').read_bytes()
manifest=json.loads(before)
for entry in manifest['retained_inputs']:
    path=root/entry['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256']
app=Celery('duplicate-check',broker='amqp://cpag_validation:local-validation-only@127.0.0.1:15673/',backend='redis://127.0.0.1:16379/0')
# New envelope ID with same logical task models broker redelivery without cached result reuse.
result=app.send_task('api.v2.synthetic.execute_synthetic',args=[task_id],queue='cpag_generation')
result.get(timeout=30)
assert (root/'result_manifest.json').read_bytes()==before
code,raw=helpers['call']('/status/batch?task_ids='+task_id)
assert code==200,(code,raw)
print(json.dumps({'synthetic_only':True,'task_id':task_id,'queued_without_worker':True,'completed_after_worker_restart':True,'duplicate_delivery_preserved_manifest':True,'source_checksums_verified':True,'batch_status_http':code},indent=2))
