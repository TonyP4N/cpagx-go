"""Fixed preparation child bounds, independent of a surviving Go parent.

An inherited coordinator lock remains open through runpy and releases on real
process exit. No arbitrary module or resource expression is accepted.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import runpy
import signal
import sys

VERSION='evaluation-preparation-resources-1'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds',type=int,required=True)
    parser.add_argument('--module',choices=('cpag_core.evaluation_artifacts','cpag_core.replay_spool_cli'),required=True)
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    if not 1<=args.seconds<=1800:parser.error('preparation wall budget must be 1..1800 seconds')
    resource.setrlimit(resource.RLIMIT_CPU,(1800,1800))
    resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024**3,4*1024**3))
    resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    memory_enforced=sys.platform.startswith('linux')
    if memory_enforced:resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(args.seconds)
    metrics=os.environ.get('CPAG_PREPARATION_METRICS')
    if metrics:
        with Path(metrics).open('a') as stream:
            stream.write(json.dumps({'version':VERSION,'pid':os.getpid(),'wall_seconds':args.seconds,'cpu_seconds':1800,
                'memory_bytes':2*1024**3,'memory_limit_enforced':memory_enforced,'file_bytes':4*1024**3,'nofile':128})+'\n')
            stream.flush();os.fsync(stream.fileno())
    arguments=args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments
    sys.argv=[args.module,*arguments]
    runpy.run_module(args.module,run_name='__main__')


if __name__=='__main__':main()
