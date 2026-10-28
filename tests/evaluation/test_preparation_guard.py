"""Preparation launcher limits and inherited lock survive caller disappearance."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

CODE = '''
import sys,time
from unittest.mock import patch
from cpag_core import evaluation_preparation_guard as guard
sys.argv=['guard','--seconds','1','--module','cpag_core.evaluation_artifacts']
with patch.object(guard.runpy,'run_module',side_effect=lambda *a,**k:time.sleep(30)):
    guard.main()
'''


def test_independent_alarm_and_actual_resource_receipt(tmp_path):
    receipt=tmp_path/'guard.jsonl'
    env=dict(os.environ,CPAG_PREPARATION_METRICS=str(receipt))
    start=time.monotonic()
    result=subprocess.run([sys.executable,'-c',CODE],env=env,capture_output=True,timeout=10)
    assert result.returncode==124,result.stderr
    assert time.monotonic()-start<8
    row=json.loads(receipt.read_text())
    assert row['version']=='evaluation-preparation-resources-1'
    assert row['wall_seconds']==1 and row['cpu_seconds']==1800
    assert row['memory_limit_enforced']==sys.platform.startswith('linux')


def test_inherited_execution_lock_lasts_until_actual_child_exit(tmp_path):
    receipt=tmp_path/'guard.jsonl'
    lock=(tmp_path/'coordinator.lock').open('w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    child=subprocess.Popen([sys.executable,'-c',CODE],pass_fds=(lock.fileno(),),
        env=dict(os.environ,CPAG_PREPARATION_METRICS=str(receipt)),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    lock.close()  # Models a dead Go owner; no explicit unlock is allowed.
    try:
        for _ in range(100):
            if receipt.exists():break
            time.sleep(.01)
        assert receipt.exists()
        with (tmp_path/'coordinator.lock').open('r') as contender:
            with pytest.raises(BlockingIOError):fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
            assert child.wait(timeout=10)==124
            fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:
        if child.poll() is None:child.kill();child.wait()
