"""Run the existing UI against a restored persistent API (private state file).

No default deployment is changed. Stop with SIGTERM after browser acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'services/worker'),str(ROOT/'scripts/validation')]
from round13_celery import start_ui, free_port


def main():
    parser=argparse.ArgumentParser();parser.add_argument('state',type=Path);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--ui-port',type=int,default=18314)
    args=parser.parse_args();state=json.loads(args.state.read_text());args.output.mkdir(parents=True,exist_ok=False)
    os.environ.update(CPAG_PERSISTENT_ENABLED='1',CPAG_PERSISTENT_ROOT=state['shared_root'],CPAG_PERSISTENT_API_URL=state['api_url'],CPAG_PERSISTENT_TOKEN=state['worker_token'])
    spec=importlib.util.spec_from_file_location('persistent_dual',ROOT/'services/python-cpag-generator/api/v2/persistent_dual.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    from fastapi import FastAPI
    import uvicorn
    app=FastAPI();module.register(app);port=free_port();server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='warning'))
    threading.Thread(target=server.run,daemon=True).start()
    for _ in range(1800):
        if server.started:break
        time.sleep(.1)
    else:raise RuntimeError('bridge startup timeout')
    ui=start_ui(f'http://127.0.0.1:{port}',args.ui_port)
    from cpag_worker.worker import API
    from cpag_worker.isolated import DockerExecutor
    executor=DockerExecutor(API(state['api_url'],state['worker_token']),API(state['api_url'],state['coordinator_token']),state['shared_root'],args.output/'control','r14-ui',timeout=120,heartbeat=.5,lease=15)
    stop=threading.Event()
    def work():
        while not stop.is_set():
            try:
                result=executor.once()
                if result not in (None, 'idle'):
                    with (args.output/'worker-results.jsonl').open('a') as log:log.write(json.dumps({'result':result})+'\n')
            except Exception as exc:
                with (args.output/'worker-errors.log').open('a') as log:log.write(repr(exc)+'\n')
            stop.wait(.3)
    thread=threading.Thread(target=work,daemon=True);thread.start()
    public={k:v for k,v in state.items() if 'token' not in k}
    public.update(ui_url=f'http://127.0.0.1:{args.ui_port}/dual-source/',bridge_url=f'http://127.0.0.1:{port}')
    (args.output/'ready.json').write_text(json.dumps(public,indent=2)+'\n')
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    try:
        while not stop.wait(.5):pass
    finally:
        executor.stop();thread.join(timeout=20);ui.shutdown();server.should_exit=True
if __name__=='__main__':main()
