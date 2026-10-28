import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'services/worker'))
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_worker.worker import Worker, APIError
from cpag_core.pipeline import run

class FakeAPI:
    def __init__(self,state='running'): self.calls=[]; self.state=state
    def post(self,path,body):
        self.calls.append((path,body))
        if path.endswith('/heartbeat'):
            if self.state=='unavailable': raise OSError('synthetic API outage')
            if self.state!='running': raise APIError(409,{'state':self.state})
            return {'state':'running'}
        return {}

def fixture(root):
    import shutil
    payload={}
    for name,source in [('network',ROOT/'tests/fixtures/synthetic/network.normalized.jsonl'),('process',ROOT/'tests/fixtures/synthetic/process.csv'),('profile',ROOT/'profiles/synthetic-demo.json')]:
        target=root/source.name
        shutil.copyfile(source,target)
        payload[name]={'path':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    manifest=run(root/payload['network']['path'],root/payload['process']['path'],root/payload['profile']['path'],root/'baseline',synthetic=True)
    payload['config_fingerprint']=manifest['config_fingerprint']
    return {'id':'test-job','attempt':1,'token':'token','payload':payload,'output_dir':'jobs/test-job/attempt-1'}

def alive(pid):
    try: os.kill(pid,0); return True
    except ProcessLookupError: return False

class WorkerTests(unittest.TestCase):
    def test_real_core_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);claim=fixture(root);api=FakeAPI()
            old=os.environ.get('PYTHONPATH')
            os.environ['PYTHONPATH']=str(ROOT/'services/analysis/src')
            try: result=Worker(api,root,'unit',heartbeat=.05).attempt(claim)
            finally:
                if old is None: os.environ.pop('PYTHONPATH',None)
                else: os.environ['PYTHONPATH']=old
            self.assertEqual(result,'succeeded')
            self.assertTrue(api.calls[-1][0].endswith('/complete'))
            manifest=json.loads((root/claim['output_dir']/'manifest.json').read_text())
            for item in manifest['artifacts']:
                self.assertEqual(item['sha256'],hashlib.sha256((root/claim['output_dir']/item['path']).read_bytes()).hexdigest())
    def test_once_cli_reports_unavailable_dependency(self):
        from unittest.mock import patch
        from contextlib import redirect_stderr
        from io import StringIO
        from cpag_worker.worker import main
        captured=StringIO()
        with patch.object(sys,'argv',['worker','--enable-m4-worker','--once']), patch.dict(os.environ,{'CPAG_WORKER_TOKEN':'never-log-this','CPAG_API_URL':'http://offline','CPAG_SHARED_ROOT':'/tmp'}), patch.object(Worker,'once',side_effect=OSError('offline')), redirect_stderr(captured):
            self.assertEqual(main(),75)
        diagnostic=json.loads(captured.getvalue())
        self.assertEqual(diagnostic['outcome'],'dependency_unavailable')
        self.assertTrue(diagnostic['retryable'])
        self.assertNotIn('never-log-this',captured.getvalue())

    def test_duplicate_invocation_does_not_fail_existing_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);claim=fixture(root);api=FakeAPI()
            control=root/'jobs/test-job/attempt-1.worker';control.mkdir(parents=True)
            evidence=control/'exit.json';evidence.write_text('existing identity')
            self.assertEqual(Worker(api,root,'unit').attempt(claim),'reconciliation_required')
            self.assertEqual(api.calls,[])
            self.assertEqual(evidence.read_text(),'existing identity')

    def test_ambiguous_completion_does_not_send_fail(self):
        from unittest.mock import patch
        for error,expected in [(OSError('response lost'),'publication_pending'),
                               (APIError(503,{}),'publication_pending'),
                               (APIError(409,{}),'lost_lease')]:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);claim=fixture(root)
                class CompletionAPI(FakeAPI):
                    def post(self,path,body):
                        value=super().post(path,body)
                        if path.endswith('/complete'):raise error
                        return value
                api=CompletionAPI()
                with patch.dict(os.environ, {'PYTHONPATH':str(ROOT/'services/analysis/src')}):
                    result=Worker(api,root,'unit',heartbeat=.05).attempt(claim)
                self.assertEqual(result,expected)
                self.assertFalse(any(path.endswith('/fail') for path,_ in api.calls))
                self.assertTrue((root/claim['output_dir']/'manifest.json').is_file())

    def hanging(self,state='running',timeout=.3):
        context=tempfile.TemporaryDirectory(); self.addCleanup(context.cleanup)
        root=Path(context.name);claim=fixture(root);api=FakeAPI(state)
        script=root/'hang.py';script.write_text('import os,time\nprint("x"*100000,flush=True)\ntime.sleep(60)\n')
        result=Worker(api,root,'unit',heartbeat=.05,timeout=timeout,log_bytes=1024,command=[sys.executable,str(script)]).attempt(claim)
        control=root/'jobs/test-job/attempt-1.worker'
        pid=int((control/'child.pid').read_text())
        self.assertFalse(alive(pid))
        self.assertLessEqual((control/'stdout.log').stat().st_size,1024)
        return result,api,control
    def test_timeout_real_process_and_bounded_logs(self):
        result,api,control=self.hanging()
        self.assertEqual(result,'failed')
        self.assertEqual(json.loads((control/'exit.json').read_text())['reason'],'timeout')
        self.assertTrue(api.calls[-1][0].endswith('/fail'))
        self.assertTrue(api.calls[-1][1]['retryable'])
    def test_cancel_ack_after_exit(self):
        result,api,_=self.hanging('cancelling',60)
        self.assertEqual(result,'cancelled')
        self.assertTrue(api.calls[-1][0].endswith('/ack-cancel'))
        self.assertFalse(any(path.endswith('/fail') for path,_ in api.calls))
    def test_lost_lease_stops_without_terminal_write(self):
        result,api,_=self.hanging('running_elsewhere',60)
        self.assertEqual(result,'lost_lease')
        self.assertFalse(any(path.endswith(('/fail','/complete','/ack-cancel')) for path,_ in api.calls))
    def test_api_unavailable_stops_child_without_terminal_write(self):
        result,api,_=self.hanging('unavailable',60)
        self.assertEqual(result,'lost_lease')
        self.assertFalse(any(path.endswith(('/fail','/complete','/ack-cancel')) for path,_ in api.calls))
    def test_invalid_input_is_not_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);claim=fixture(root);api=FakeAPI()
            claim['payload']['network']['sha256']='0'*64
            self.assertEqual(Worker(api,root,'invalid').attempt(claim),'failed')
            self.assertFalse(api.calls[-1][1]['retryable'])
    def test_core_does_not_receive_control_credentials(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); claim=fixture(root); api=FakeAPI()
            script=root/'environment.py'
            script.write_text('import os,json\nprint(json.dumps(sorted(os.environ)),flush=True)\n')
            with patch.dict(os.environ, {'CPAG_WORKER_TOKEN':'test-secret','M4_DATABASE_URL':'test-database'}):
                Worker(api,root,'environment',command=[sys.executable,str(script)]).attempt(claim)
            names=json.loads((root/'jobs/test-job/attempt-1.worker/stdout.log').read_text())
            self.assertNotIn('CPAG_WORKER_TOKEN',names)
            self.assertNotIn('M4_DATABASE_URL',names)

    @unittest.skipUnless(os.name == 'posix', 'POSIX resource limits required')
    def test_cpu_and_file_resource_limits(self):
        for kind in ('cpu','file'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); claim=fixture(root); api=FakeAPI()
                script=root/'limit.py'; target=root/'oversized.bin'
                script.write_text('while True: pass\n' if kind=='cpu' else 'with open('+repr(str(target))+',"wb") as f: f.write(b"x"*1048576)\n')
                result=Worker(api,root,'limit',heartbeat=.05,timeout=5,cpu_seconds=1,file_bytes=4096,command=[sys.executable,str(script)]).attempt(claim)
                self.assertEqual(result,'failed')
                record=json.loads((root/'jobs/test-job/attempt-1.worker/exit.json').read_text())
                self.assertEqual(record['reason'],'exited')
                self.assertNotEqual(record['returncode'],0)
                if kind=='file': self.assertLessEqual(target.stat().st_size,4096)
                else: self.assertLess(record['returncode'],0)

    def test_abnormal_supervisor_no_terminal_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);claim=fixture(root);api=FakeAPI()
            script=root/'kill-supervisor.py'
            script.write_text('import os,signal\nos.kill(os.getppid(),signal.SIGKILL)\n')
            result=Worker(api,root,'supervisor-fault',heartbeat=.05,command=[sys.executable,str(script)]).attempt(claim)
            self.assertEqual(result,'lost_lease')
            self.assertFalse(any(path.endswith(('/fail','/complete','/ack-cancel')) for path,_ in api.calls))
    def test_worker_graceful_stop_stops_child(self):
        self.worker_stop(False)
    def test_worker_sigkill_parent_pipe_stops_child(self):
        self.worker_stop(True)
    def worker_stop(self, force):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);claim=fixture(root)
            script=root/'hang.py';script.write_text('import time\ntime.sleep(60)\n')
            driver=root/'driver.py'
            driver.write_text('import sys\nsys.path[:0]='+repr([str(ROOT/'services/worker'),str(ROOT/'tests/worker')])+'\nfrom test_worker import FakeAPI\nfrom cpag_worker.worker import Worker\nimport json,signal\nfrom pathlib import Path\nw=Worker(FakeAPI(),'+repr(str(root))+',"crash",command='+repr([sys.executable,str(script)])+')\nsignal.signal(signal.SIGTERM,w.stop)\nw.attempt(json.loads('+repr(json.dumps(claim))+'))\n')
            worker=subprocess.Popen([sys.executable,str(driver)])
            pidfile=root/'jobs/test-job/attempt-1.worker/child.pid'
            try:
                deadline=time.monotonic()+5
                while not pidfile.exists() and time.monotonic()<deadline: time.sleep(.02)
                self.assertTrue(pidfile.exists())
                pid=int(pidfile.read_text());self.assertTrue(alive(pid))
                if force: worker.kill()
                else: worker.terminate()
                worker.wait(timeout=3)
                deadline=time.monotonic()+5
                while alive(pid) and time.monotonic()<deadline: time.sleep(.05)
                self.assertFalse(alive(pid))
                # Reaping the calculation child precedes the guardian's atomic
                # exit receipt. Do not remove its directory while it is writing.
                receipt=pidfile.with_name('exit.json')
                deadline=time.monotonic()+5
                while not receipt.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(receipt.exists(),'guardian did not persist exit proof')
                proof=json.loads(receipt.read_text())
                self.assertEqual(proof['child_pid'],pid)
                self.assertTrue(proof['group_exited'])
                self.assertEqual(proof['reason'],'parent_disconnected')
                self.assertEqual(proof['attempt'],claim['attempt'])
            finally:
                if worker.poll() is None: worker.kill();worker.wait()

if __name__=='__main__': unittest.main()
