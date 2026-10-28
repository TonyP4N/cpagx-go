"""Development-only actual M core -> isolated DAG prototype; no formal publication."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_core.dual_source import analyze
from cpag_core.dual_source_export import event_graph
from cpag_core.shared_artifact_store import SharedArtifactWriter,SharedArtifactReader,FORMAT
from cpag_core.pipeline import canonical,fingerprint,file_hash


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fixture',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=180);args=parser.parse_args()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    start=time.perf_counter();deadline=time.monotonic()+args.seconds
    runtime_files=['dual_source.py','dual_source_export.py','pipeline.py','capacity.py','shared_artifact_store.py']
    hashes={name:file_hash(ROOT/'services/analysis/src/cpag_core'/name) for name in runtime_files}
    record={'scope':'actual local synthetic M core and isolated store only; not formal M pipeline, new storage publication, evaluation or L acceptance',
            'source_sha256_before':hashes,'status':'running','fixture':str(args.fixture),'samples':[]}
    def persist():
        record['wall_seconds']=time.perf_counter()-start
        record['process_peak_rss_bytes']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
        (args.output/'measurement.json').write_text(json.dumps(record,indent=2)+'\n')
    def stage(name,call):
        row={'name':name,'event':'entered','wall_at_start':time.perf_counter()-start};record['samples'].append(row);persist()
        before,cpu=time.perf_counter(),time.process_time()
        value=call();row.update(event='completed',wall_seconds=time.perf_counter()-before,cpu_seconds=time.process_time()-cpu);persist();return value
    writer=reader=None
    try:
        config=json.loads((args.fixture/'offline-profile.json').read_text())
        record['input_sha256']={name:file_hash(args.fixture/name) for name in ('network.pcap','process.csv','offline-profile.json')};persist()
        analysis=stage('actual_core_analysis',lambda:analyze(args.fixture/'network.pcap',args.fixture/'process.csv',config))
        record['actual_counts']={key:len(analysis[key]) for key in ('network','process','operations','changes','candidates')};persist()
        projected=stage('actual_standard_graph_and_events',lambda:event_graph(analysis))
        context={'run_id':'prototype-M','attempt_id':1,'input_fingerprint':analysis['input_fingerprint'],'config_fingerprint':analysis['config_fingerprint']}
        writer=SharedArtifactWriter(args.output/'store',context=context,version=FORMAT,deadline=deadline)
        docs={'analysis.json':analysis,'dual/analysis.json':analysis,'events.json':projected['events.json'],
              'graph.json':projected['graph.json'],'quality.json':analysis['quality']}
        record['roots']={}
        for name,value in docs.items():
            descriptor=stage('store_'+name,lambda name=name,value=value:writer.add(name,value))
            record['roots'][name]=descriptor;record['node_count_so_far']=writer.node_count
            record['sqlite_bytes_so_far']=(args.output/'store/shared.sqlite3').stat().st_size;persist()
        sealed=stage('seal_store',writer.seal);record['sealed']=sealed;persist()
        reader=stage('restore_and_verify_nodes',lambda:SharedArtifactReader(args.output/'store',expected_manifest_sha256=sealed['manifest_sha256'],expected_context=context,deadline=deadline))
        checks={}
        for name in ('events.json','quality.json'):
            actual=stage('full_logical_hash_'+name,lambda name=name:reader.canonical_sha256(name,max_bytes=record['roots'][name]['logical_bytes']))
            expected=hashlib.sha256(canonical(docs[name])).hexdigest()
            checks[name]=actual==expected
        page=stage('complete_candidate_page',lambda:reader.page('analysis.json',path=['candidates'],offset=100,limit=2))
        checks['candidate_page_complete']=page['items']==analysis['candidates'][100:102]
        record['checks']=checks
        record['status']='prototype_actual_M_store_success' if all(checks.values()) else 'failed'
    except BaseException as error:
        record.update(status='failed',error_type=type(error).__name__,error=str(error))
        (args.output/'failure-traceback.log').write_text(traceback.format_exc())
        if writer is not None:
            record['node_count_at_failure']=writer.node_count
            if (args.output/'store/shared.sqlite3').exists():record['sqlite_bytes_at_failure']=(args.output/'store/shared.sqlite3').stat().st_size
    finally:
        if reader is not None:reader.close()
        if writer is not None:writer.close()
        record['source_sha256_after']={name:file_hash(ROOT/'services/analysis/src/cpag_core'/name) for name in runtime_files}
        record['fixed_source_during_measurement']=hashes==record['source_sha256_after'];persist()
    print(json.dumps(record,indent=2))
    return 0 if record['status']=='prototype_actual_M_store_success' else 1


if __name__=='__main__':raise SystemExit(main())
