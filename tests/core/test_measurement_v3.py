"""Version3 progress is bounded atomic measurement, never terminal success."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cpag_core import measurement_v3 as m


class PhaseV3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'metrics.jsonl');self.progress=Path(self.tmp.name)/'progress.json'
        m._states.clear();m._closed=False;m._worker=None;m._stop=threading.Event()
        self.clock=[100.0]
        self.fake_clock=patch.object(m.time,'monotonic',side_effect=lambda:self.clock[0]);self.fake_clock.start()
        self.no_thread=patch.object(m,'_start_worker_locked');self.no_thread.start()

    def tearDown(self):
        m.flush_summaries();self.no_thread.stop();self.fake_clock.stop()

    def read(self):return json.loads(self.progress.read_text())

    def test_time_gating_and_only_ended_calls(self):
        m.begin(self.path);row=self.read()
        self.assertEqual(row['all_observed_calls'],0);self.assertEqual(row['measurement_state'],'in_progress')
        self.assertFalse(row['terminal']);self.assertIsNone(row['compute_success'])
        m.record(self.path,'parse','returned',1,.5,100)
        self.assertEqual(self.read()['all_observed_calls'],1)
        m.record(self.path,'parse','failed',2,.75,200)
        previous=self.progress.read_bytes();self.clock[0]=104.999;m.publish_progress()
        self.assertEqual(previous,self.progress.read_bytes())
        self.clock[0]=105;m.publish_progress();row=self.read()
        self.assertEqual(row['all_observed_calls'],2)
        self.assertEqual(row['phases']['parse'],{'calls':2,'returned':1,'failed':1,'wall_seconds':3,'cpu_seconds':1.25,'rss_high_water_bytes':200})
        self.assertNotIn('total_seconds',row);self.assertNotIn('allocation_bytes',row)
        self.assertFalse(any(json.loads(line)['kind']=='terminal_measurement_summary' for line in Path(self.path).read_text().splitlines()))

    def test_raw_limit_and_exactly_one_normal_terminal(self):
        for number in range(300):m.record(self.path,'parse','failed' if number==299 else 'returned',.5,.25,1024+number)
        m.record(self.path,'export','returned',200,80,2048)
        self.clock[0]=105;m.publish_progress();row=self.read()
        self.assertEqual(row['all_observed_calls'],301);self.assertEqual(row['raw_rows_retained'],256);self.assertEqual(row['raw_rows_not_retained'],45)
        m.flush_summaries();rows=[json.loads(line) for line in Path(self.path).read_text().splitlines()]
        self.assertEqual(len(rows),257);summary=rows[-1]
        self.assertEqual(summary['kind'],'terminal_measurement_summary')
        self.assertEqual(summary['phases']['parse'],{'calls':300,'returned':299,'failed':1,'wall_seconds':150,'cpu_seconds':75,'rss_high_water_bytes':1323})
        self.assertEqual(summary['version'],'phase-resources-3')
        self.assertFalse(self.read()['terminal'])
        m.flush_summaries();self.assertEqual(len(Path(self.path).read_text().splitlines()),257)
        with self.assertRaisesRegex(ValueError,'already_terminal'):m.record(self.path,'parse','returned',1,0,1)

    def test_exception_is_ended_failure_without_invented_success(self):
        from cpag_core.measurement import phase
        @phase('business')
        def fail():raise RuntimeError('original business failure')
        with patch.dict(os.environ,{'CPAG_PHASE_METRICS':self.path,'CPAG_PHASE_STRATEGY':'phase-resources-3'}):
            with self.assertRaisesRegex(RuntimeError,'original business failure'):fail()
        row=self.read();self.assertEqual(row['phases']['business']['failed'],1);self.assertEqual(row['phases']['business']['returned'],0)
        self.assertIsNone(row['compute_success']);self.assertFalse(row['terminal'])

    def test_unchanged_cpu_counters_do_not_create_negative_rounding(self):
        from cpag_core import measurement
        @measurement.phase('zero_tick')
        def ended():return 'ended'
        usage=SimpleNamespace(ru_utime=.1,ru_stime=.01,ru_maxrss=100)
        with patch.dict(os.environ,{'CPAG_PHASE_METRICS':self.path,'CPAG_PHASE_STRATEGY':'phase-resources-3'}),patch.object(measurement.resource,'getrusage',return_value=usage):
            self.assertEqual(ended(),'ended')
        self.assertEqual(self.read()['phases']['zero_tick']['cpu_seconds'],0)

    def test_failed_atomic_replace_preserves_previous_complete_document(self):
        m.record(self.path,'parse','returned',1,0,10);before=self.progress.read_bytes()
        m.record(self.path,'parse','returned',1,0,10)
        def refused(source,destination):
            self.assertEqual(Path(source).parent,self.progress.parent)
            self.assertEqual(json.loads(Path(source).read_text())['all_observed_calls'],2)
            self.assertEqual(self.progress.read_bytes(),before)
            raise OSError('simulated replace failure')
        with patch.object(m.os,'replace',side_effect=refused):m.publish_progress(force=True)
        self.assertEqual(self.progress.read_bytes(),before)
        self.assertEqual(list(self.progress.parent.glob('.progress-*.tmp')),[])
        m.publish_progress(force=True);row=self.read()
        self.assertEqual(row['all_observed_calls'],2);self.assertEqual(row['progress_write_failures'],1);self.assertEqual(row['last_progress_error_type'],'OSError')

    def test_progress_byte_limit_keeps_previous_atomic_snapshot(self):
        m.record(self.path,'parse','returned',1,0,10);before=self.progress.read_bytes()
        with patch.object(m,'MAX_PROGRESS_BYTES',32),patch.object(m.os,'replace') as replaced:
            m.publish_progress(force=True);replaced.assert_not_called()
        self.assertEqual(before,self.progress.read_bytes())
        m.publish_progress(force=True);self.assertEqual(self.read()['progress_write_failures'],1)

    def test_phase_target_and_numeric_bounds_fail_without_increment(self):
        for bad in ('x'*129,'name with space',''):
            with self.assertRaises(ValueError):m.record(self.path,bad,'returned',1,0,10)
        for values in ((-1,0,10),(float('nan'),0,10),(1,float('inf'),10),(1,0,-1),(1,0,True)):
            with self.assertRaises(ValueError):m.record(self.path,'parse','returned',*values)
        self.assertEqual(m._states,{})
        for number in range(64):m.record(self.path,'phase_'+str(number),'returned',0,0,0)
        with self.assertRaisesRegex(ValueError,'phase_limit'):m.record(self.path,'extra','returned',0,0,0)
        with self.assertRaisesRegex(ValueError,'output_changed'):m.begin(str(Path(self.tmp.name)/'other.jsonl'))
        with self.assertRaisesRegex(ValueError,'target_collision'):m.begin(str(self.progress))
        self.clock[0]=105;m.publish_progress();self.assertEqual(self.read()['all_observed_calls'],64)
        self.assertLessEqual(self.progress.stat().st_size,m.MAX_PROGRESS_BYTES)

    def test_aggregate_overflow_is_rejected_before_mutating_counts(self):
        m.record(self.path,'parse','returned',1e308,0,10)
        with self.assertRaisesRegex(ValueError,'aggregate_limit'):m.record(self.path,'parse','returned',1e308,0,10)
        m.publish_progress(force=True);self.assertEqual(self.read()['all_observed_calls'],1)

    def test_concurrent_ended_calls_do_not_lose_aggregates(self):
        errors=[]
        def record(number):
            try:
                for _ in range(100):m.record(self.path,'thread_'+str(number),'returned',.5,.1,100+number)
            except BaseException as error:errors.append(error)
        threads=[threading.Thread(target=record,args=(number,)) for number in range(4)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(errors,[]);self.clock[0]=105;m.publish_progress();row=self.read()
        self.assertEqual(row['all_observed_calls'],400);self.assertEqual(row['raw_rows_retained'],256)
        for phase in row['phases'].values():self.assertEqual(phase['calls'],100)


class PhaseV3AbruptExitTests(unittest.TestCase):
    def test_actual_kill_keeps_periodic_progress_but_no_terminal(self):
        code="""import os,time
from pathlib import Path
from cpag_core.measurement import phase
@phase('parse')
def ended(fail=False):
 if fail:raise ValueError('expected phase failure')
for number in range(300):
 try:ended(number==299)
 except ValueError:pass
@phase('unfinished')
def unfinished():
 Path(os.environ['CPAG_TEST_READY']).write_text('ready')
 time.sleep(30)
unfinished()
"""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);target=root/'metrics.jsonl';ready=root/'ready';progress=root/'progress.json'
            env=dict(os.environ,CPAG_PHASE_METRICS=str(target),CPAG_PHASE_STRATEGY='phase-resources-3',CPAG_TEST_READY=str(ready))
            child=subprocess.Popen([sys.executable,'-c',code],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+12;observed=None
                while time.monotonic()<deadline:
                    if child.poll() is not None:self.fail('measurement child exited: '+str(child.communicate()))
                    if ready.exists() and progress.exists():
                        observed=json.loads(progress.read_text())
                        if observed['all_observed_calls']==300:break
                    time.sleep(.02)
                self.assertIsNotNone(observed);self.assertEqual(observed['all_observed_calls'],300)
                self.assertNotIn('unfinished',observed['phases'])
                self.assertEqual(observed['phases']['parse']['failed'],1)
                child.kill();child.wait(timeout=5)
                self.assertNotEqual(child.returncode,0)
                self.assertEqual(json.loads(progress.read_text())['measurement_state'],'in_progress')
                rows=[json.loads(line) for line in target.read_text().splitlines()]
                self.assertEqual(len(rows),256);self.assertTrue(all(row['kind']=='sample' for row in rows))
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
                child.communicate()


if __name__=='__main__':unittest.main()
