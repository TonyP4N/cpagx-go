#!/usr/bin/env python3
"""Resume only this private R20 environment after rebuilding the Go binary."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import round19_formal_service_acceptance as formal
r=formal.r

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);a=p.parse_args()
    state=json.loads(a.state.read_text());work=a.state.resolve().parent;config=json.loads((work/'app-config.json').read_text())
    r.run('docker','start',state['pg_container'],stdout=subprocess.DEVNULL)
    for _ in range(150):
        if subprocess.run(['docker','exec',state['pg_container'],'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode==0:break
        time.sleep(.1)
    app=worker=None
    try:
        config_path=work/('app-resume-'+str(os.getpid())+'-config.json');r.write_private(config_path,config)
        log=(work/'app-resume.log').open('ab')
        app=subprocess.Popen([str(work/'cpagx-v3'),'--config',str(config_path)],cwd=r.REPO,stdout=log,stderr=subprocess.STDOUT);log.close()
        r.wait_ready(state['url'],app)
        env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(r.REPO/'services/worker'),str(r.REPO/'services/analysis/src')]),NO_PROXY='127.0.0.1,localhost',no_proxy='127.0.0.1,localhost')
        worker=r.start_worker(work,'worker-resume',work/'worker-config.json',env)
        state.update(app_pid=app.pid,worker_pid=worker.pid,harness_pid=os.getpid())
        a.state.write_text(json.dumps(state,indent=2)+'\n');a.state.chmod(0o600)
        print(json.dumps({'status':'ready','url':state['url']}),flush=True)
        halt=False
        def stop(*_):
            nonlocal halt
            halt=True
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        while not halt:
            if app.poll() is not None or worker.poll() is not None:raise RuntimeError('retained_service_exited')
            time.sleep(.5)
    finally:
        r.stop(worker);r.stop(app)
        with (work/'resumed-database.sql').open('wb') as stream:subprocess.run(['docker','exec',state['pg_container'],'pg_dump','-U','postgres','m4_restore_validation'],stdout=stream,stderr=subprocess.PIPE)
        subprocess.run(['docker','stop',state['pg_container']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
