#!/usr/bin/env python3
"""Actual API outage + SIGKILL Worker, recovery reads PostgreSQL directly."""
import os
import signal
import subprocess
import time
import worker_http_faults as f

job=f.enqueue(attempts=1)
claim=f.claim_for('recovery-outage')
assert claim['id']==job
worker=f.spawn_attempt(claim)
pid=f.pid_for(claim)
f.api.post('/v1/jobs/'+job+'/cancel',{})
os.kill(int(os.environ['CPAG_TEST_API_PID']),signal.SIGTERM)
worker.kill();worker.wait(timeout=5)
f.wait_for(lambda:f.absent(pid))
# API stays down. No Worker or new claim request is made during recovery.
def query():
    result=subprocess.run(['docker','compose','-p','cpag-m4-worker-validation','-f',str(f.ROOT/'deployments/compose.m4-worker-validation.yml'),'exec','-T','postgres','psql','-U','postgres','-d','m4_validation','-At','-c',"SELECT state || ':' || coalesce(recovery_reason,'') FROM m4_jobs WHERE id='"+job+"'"],capture_output=True,text=True,check=True)
    return result.stdout.strip()
f.wait_for(lambda:query().startswith('cancelled:guardian proved'),seconds=15)
print('PASS independent recovery during actual API outage, Worker SIGKILL, no new claims; guardian proves computation exit')
f.cleanup()
