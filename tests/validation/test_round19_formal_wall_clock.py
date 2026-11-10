"""Wall-clock performance contracts reject host pauses and clock changes."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
import round19_formal_service_acceptance as acceptance
from round19_formal_service_acceptance import Harness,InvalidEnvironment,MEASUREMENT_VERSION


class FormalWallClockTests(unittest.TestCase):
    def harness(self,directory):
        harness=Harness(SimpleNamespace(mode='s100',image='sha256:'+'a'*64,output=Path(directory)))
        harness.state={'run_ids':[]};harness.flush=Mock();harness.worker=SimpleNamespace(poll=lambda:None)
        return harness
    def test_confirmed_pause_cancels_and_never_accepts_terminal_success(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=self.harness(directory);clock={'wall':1000.,'mono':100.};calls=[]
            def request(method,path,*args,**kwargs):
                calls.append((method,path))
                if path=='/api/v3/runs':return {'run':{'id':'run'}}
                if path.endswith('/cancel'):return {'run':{'state':'succeeded'}}
                if len(calls)==2:
                    clock.update(wall=1260.,mono=104.)
                    return {'run':{'state':'succeeded','attempt':1,'attempt_history':[]}}
                return {'run':{'state':'succeeded','attempt':1,'attempt_history':[]}}
            harness.client=SimpleNamespace(expect=request)
            with patch.object(acceptance.time,'time',side_effect=lambda:clock['wall']),patch.object(acceptance.time,'monotonic',side_effect=lambda:clock['mono']):
                with self.assertRaises(InvalidEnvironment):harness.submit_wait({'dataset_id':'dataset'},'fixed')
            self.assertEqual(harness.report['measurement_version'],MEASUREMENT_VERSION)
            self.assertEqual(harness.report['status'],'invalid_environment')
            row=harness.report['runs'][0]
            self.assertEqual(row['invalid_environment']['run_clock']['wall_minus_monotonic_seconds'],256.)
            self.assertTrue(row['invalid_environment_cancel_requested'])
            self.assertTrue(row['invalid_environment_cleanup']['terminal_observed'])
            self.assertIn(('POST','/api/v3/runs/run/cancel'),calls)
            self.assertNotIn('terminal_seconds',row)
    def test_wall_seconds_drive_success_with_monotonic_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=self.harness(directory);clock={'wall':1000.,'mono':100.}
            def request(method,path,*args,**kwargs):
                if path=='/api/v3/runs':return {'run':{'id':'run'}}
                clock.update(wall=1012.,mono=111.)
                return {'run':{'state':'succeeded','attempt':1,'attempt_history':[]}}
            harness.client=SimpleNamespace(expect=request)
            with patch.object(acceptance.time,'time',side_effect=lambda:clock['wall']),patch.object(acceptance.time,'monotonic',side_effect=lambda:clock['mono']):
                run,row=harness.submit_wait({'dataset_id':'dataset'},'fixed')
            self.assertEqual(row['terminal_seconds'],12.)
            self.assertEqual(row['terminal_monotonic_seconds'],11.)
            self.assertEqual(row['submit_wall'],1000.)
    def test_query_wall_limit_rejects_duration_even_when_monotonic_is_shorter(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=self.harness(directory);clock={'wall':1000.,'mono':100.}
            harness.report['runs']=[{'id':'run','submit_wall':1000.,'submit_monotonic':100.}]
            def request(*args,**kwargs):
                clock.update(wall=1011.,mono=107.)
                return {'manifest':{}}
            harness.client=SimpleNamespace(expect=request)
            with patch.object(acceptance.time,'time',side_effect=lambda:clock['wall']),patch.object(acceptance.time,'monotonic',side_effect=lambda:clock['mono']):
                with self.assertRaisesRegex(RuntimeError,'bounded_shared_query_exceeded'):
                    harness.shared('run','metadata')
            self.assertNotIn('invalid_environment',harness.report['runs'][0])
    def test_download_checks_real_wall_deadline_after_final_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=self.harness(directory);harness.origin='http://127.0.0.1:1';clock={'wall':1000.,'mono':100.}
            harness.report['runs']=[{'id':'run','submit_wall':1000.,'submit_monotonic':100.}]
            class Response:
                status=200
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def read(self,size):
                    clock.update(wall=1121.,mono=217.)
                    return b''
            harness.client=SimpleNamespace(expect=Mock(return_value={'artifacts':[{'path':'shared/shared.sqlite3','sha256':'0'*64}]}),opener=SimpleNamespace(open=lambda *args,**kwargs:Response()))
            with patch.object(acceptance.time,'time',side_effect=lambda:clock['wall']),patch.object(acceptance.time,'monotonic',side_effect=lambda:clock['mono']):
                with self.assertRaisesRegex(RuntimeError,'stream_download_deadline_after_eof'):
                    harness.stream_download('run')
            self.assertNotIn('invalid_environment',harness.report['runs'][0])

    def test_clock_backward_jump_is_invalid_and_cleanup_pending_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=self.harness(directory);row={'id':'run','submit_wall':1000.,'submit_monotonic':100.};harness.report['runs']=[row]
            harness.client=SimpleNamespace(expect=Mock(side_effect=TimeoutError('cleanup unavailable')))
            with patch.object(acceptance.time,'time',return_value=990.),patch.object(acceptance.time,'monotonic',return_value=101.):
                with self.assertRaises(InvalidEnvironment):harness.guard_clock('run',row,{'wall':1000.,'monotonic':100.},'query')
            self.assertFalse(row['invalid_environment_cleanup']['terminal_observed'])
            self.assertIn('required_action',row['invalid_environment_cleanup'])
            self.assertEqual(harness.report['status'],'invalid_environment')


if __name__=='__main__':unittest.main()
