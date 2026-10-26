"""Trusted host coordinator loop; never runs inside the compute container."""
import os
import signal
import time
import threading
from cpag_worker.isolated import DockerExecutor
from cpag_worker.worker import API
w=DockerExecutor(API(os.environ['CPAG_API_URL'],os.environ['CPAG_WORKER_TOKEN']),API(os.environ['CPAG_API_URL'],os.environ['CPAG_COORDINATOR_TOKEN']),os.environ['CPAG_SHARED_ROOT'],os.environ['CPAG_CONTROL_ROOT'],'engineering-offline',image=os.environ['CPAG_COMPUTE_IMAGE'])
signal.signal(signal.SIGTERM,w.stop);signal.signal(signal.SIGINT,w.stop)
def recover_loop():
    while not w.stopping:
        try:print('recovery '+str(w.recover()),flush=True)
        except Exception as error:print('recovery '+type(error).__name__+': retry',flush=True)
        for _ in range(25):
            if w.stopping:return
            time.sleep(.2)
threading.Thread(target=recover_loop,daemon=True).start()
while not w.stopping:
    try:print(w.once(),flush=True)
    except Exception as error:print(type(error).__name__+': retry',flush=True)
    time.sleep(1)
