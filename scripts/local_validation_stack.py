#!/usr/bin/env python3
"""Start/stop local source services; infra managed separately by validation Compose."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT/'.local-stack'
STATE.mkdir(exist_ok=True)
parser = argparse.ArgumentParser()
parser.add_argument('action', choices=['start','stop','status'])
parser.add_argument('--only', choices=['python-v1','python-v2','worker','go','web'])
args = parser.parse_args()
pidfile = STATE/'processes.json'
processes = json.loads(pidfile.read_text()) if pidfile.exists() else {}
def alive(pid):
    try: os.kill(pid,0); return True
    except ProcessLookupError: return False
if args.action == 'status':
    print(json.dumps({k:{'pid':v,'alive':alive(v)} for k,v in processes.items()},indent=2)); sys.exit()
if args.action == 'stop':
    selected = {k:v for k,v in processes.items() if not args.only or k == args.only}
    for name,pid in selected.items():
        if alive(pid): os.killpg(pid,signal.SIGTERM)
    deadline = time.monotonic() + 15
    while any(alive(pid) for pid in selected.values()) and time.monotonic() < deadline:
        time.sleep(.1)
    if any(alive(pid) for pid in selected.values()):
        raise SystemExit('Some processes have not exited; PID registry retained')
    for name in selected: processes.pop(name)
    pidfile.write_text(json.dumps(processes,indent=2)+'\n')
    sys.exit()
if any(alive(pid) for name,pid in processes.items() if not args.only or name == args.only):
    raise SystemExit('Services already running; stop them before restart')
env = dict(os.environ, PYTHONUNBUFFERED='1',
    REDIS_URL='redis://127.0.0.1:16379/0', REDIS_HOST='127.0.0.1', REDIS_PORT='16379',
    RABBITMQ_URL='amqp://cpag_validation:local-validation-only@127.0.0.1:15673/',
    NEO4J_URI='bolt://127.0.0.1:17687', NEO4J_USER='neo4j', NEO4J_PASSWORD='local-validation-only',
    INFLUXDB_URL='http://127.0.0.1:18086', INFLUXDB_TOKEN='local-validation-token-only',
    INFLUXDB_ORG='cpag_validation', INFLUXDB_BUCKET='cpag_validation',
    UPLOAD_DIR=str(STATE/'uploads'), OUTPUT_DIR=str(STATE/'outputs/v2'),
    PYTHON_SERVICE_URL='http://127.0.0.1:18000', PYTHON_V1_SERVICE_URL='http://127.0.0.1:18000',
    PYTHON_V2_SERVICE_URL='http://127.0.0.1:18002', SERVER_HOST='127.0.0.1', SERVER_PORT='18080',
    MAX_CONCURRENT_TASKS_V2='1', MPLCONFIGDIR=str(STATE/'matplotlib'))
python = str(ROOT/'.venv/bin/python')
service = ROOT/'services/python-cpag-generator'
commands = {
    'python-v1':([python,'-m','uvicorn','api.v1.app:app','--host','127.0.0.1','--port','18000'],service,dict(env,PORT='18000',OUTPUT_DIR=str(STATE/'outputs/v1'))),
    'python-v2':([python,'-m','uvicorn','api.v2.app:app','--host','127.0.0.1','--port','18002'],service,dict(env,PORT='18002')),
    'worker':([python,'-m','celery','-A','infrastructure.celery_app:celery_app','worker','--loglevel=info','--pool=solo','--concurrency=1','-Q','cpag_generation,celery','--hostname=cpag-validation@%h'],service,env),
    'go':([str(STATE/'cpagx'),'server','--config','configs/config.json'],ROOT,env),
    'web':([python,str(ROOT/'scripts/serve_validation_web.py'),'--directory',str(ROOT/'webui/out')],ROOT,env),
}
for name,(command,cwd,environment) in commands.items():
    if args.only and name != args.only: continue
    with (STATE/(name+'.log')).open('ab') as log:
        process=subprocess.Popen(command,cwd=cwd,env=environment,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    processes[name]=process.pid
    pidfile.write_text(json.dumps(processes,indent=2)+'\n')
print(json.dumps(processes,indent=2))
