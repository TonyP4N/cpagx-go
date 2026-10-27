"""Explicit single-machine Worker service; reuses existing execution and recovery.

Its private configuration contains no database or user session credentials.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import threading
import time
from urllib.parse import urlsplit
from .worker import API
from .isolated import DockerExecutor

REQUIRED={'api_url','shared_root','control_root','worker_token','coordinator_token'}
OPTIONAL={'worker_id','image','poll_seconds','recovery_seconds'}

def read_config(path):
    path=Path(path)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:
        raise ValueError('worker config must be a private regular file (0600)')
    config=json.loads(path.read_text())
    if not isinstance(config,dict) or not REQUIRED.issubset(config) or set(config)-REQUIRED-OPTIONAL:
        raise ValueError('worker config fields invalid; database/user credentials are not accepted')
    target=urlsplit(config['api_url'])
    if (target.scheme!='http' or target.hostname!='127.0.0.1' or target.port is None
        or target.username or target.password or target.path not in ('','/') or target.query or target.fragment):
        raise ValueError('worker requires loopback internal API')
    if any(not isinstance(config[k],str) or len(config[k])<24 for k in ('worker_token','coordinator_token')) or config['worker_token']==config['coordinator_token']:
        raise ValueError('distinct internal credentials required')
    for key in ('shared_root','control_root'):
        if not isinstance(config[key],str) or not Path(config[key]).is_absolute():
            raise ValueError('absolute persistent storage paths required')
    shared,control=(Path(config[k]).resolve() for k in ('shared_root','control_root'))
    if shared==control or control.is_relative_to(shared):
        raise ValueError('control evidence must be outside computation storage')
    for key,default in [('poll_seconds',1),('recovery_seconds',5)]:
        value=config.get(key,default)
        if type(value) not in (int,float) or not 0.2<=value<=60:raise ValueError('service interval out of bounds')
        config[key]=value
    return config

def serve(config):
    worker=DockerExecutor(API(config['api_url'].rstrip('/'),config['worker_token']),
        API(config['api_url'].rstrip('/'),config['coordinator_token']),config['shared_root'],
        config['control_root'],config.get('worker_id','cpag-v3-worker'),image=config.get('image','cpag-isolated:round5'))
    stopped=threading.Event()
    def stop(*_):stopped.set();worker.stop()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def recover():
        while not stopped.is_set():
            try:
                results=worker.recover()
                pending=sum(bool(x.get('pending')) for x in results)
                if results:
                    # Recovery reasons are fixed engine codes, never receipt tokens or paths.
                    reasons={}
                    for item in results:
                        reason=item.get('pending')
                        if isinstance(reason,str) and reason.replace('_','').isalnum():
                            reasons[reason]=reasons.get(reason,0)+1
                    print(json.dumps({'event':'recovery_scan','items':len(results),'pending':pending,'reasons':reasons}),flush=True)
            except Exception:
                print(json.dumps({'event':'recovery_unavailable','retry_seconds':config['recovery_seconds']}),flush=True)
            stopped.wait(config['recovery_seconds'])
    recovery=threading.Thread(target=recover,daemon=True);recovery.start()
    try:
        while not stopped.is_set():
            try:
                result=worker.once()
                if result!='idle':print(json.dumps({'event':'attempt_finished','result':result}),flush=True)
            except Exception:
                print(json.dumps({'event':'executor_unavailable','retry_seconds':config['poll_seconds']}),flush=True)
            stopped.wait(config['poll_seconds'])
    finally:
        stop();recovery.join(timeout=20)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True)
    args=parser.parse_args()
    try:config=read_config(args.config)
    except (OSError,ValueError,TypeError):parser.error('invalid private worker configuration')
    serve(config)
if __name__=='__main__':main()
