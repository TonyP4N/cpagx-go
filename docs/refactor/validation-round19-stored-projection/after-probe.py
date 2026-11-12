"""Complete content microbenchmark; no S/M/L performance acceptance."""
import hashlib,json,sys,time
from pathlib import Path
sys.path[:0]=[str(Path.cwd()/'services/analysis/src'),str(Path.cwd()/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import execute
from cpag_core.dual_source_export import event_graph
from cpag_core.compact_projection import store_standard_projection
from cpag_core.shared_artifact_store_compact import SharedArtifactWriter,LogicalHasher,FORMAT
from cpag_core.pipeline import canonical

root=Path(sys.argv[1]);networks,process,path,config=fixture(root/'fixture',case='normal',split=False)
run=execute(networks,process,config);analysis=run['analysis'];run['inputs'].close()
expected=event_graph(analysis,replay=True,identity_strategy='merkle-json-dag-1')
graph_digest=LogicalHasher().digest(expected['graph.json'])['digest']
events_digest=LogicalHasher().digest(expected['events.json'])['digest']
context={'run_id':'projection-micro','attempt_id':1,'input_fingerprint':analysis['input_fingerprint'],'config_fingerprint':analysis['config_fingerprint']}
samples=[]
for repeat in range(3):
 for label in (('existing','composed') if repeat%2==0 else ('composed','existing')):
  writer=SharedArtifactWriter(root/f'{repeat}-{label}',context=context,version=FORMAT)
  start=time.perf_counter()
  try:
   for _ in range(30):
    writer.intern(analysis)
    if label=='existing':
     actual=event_graph(analysis,replay=True,identity_strategy='merkle-json-dag-1')
     graph=writer.intern(actual['graph.json']);events=writer.intern(actual['events.json'])
    else:
     stored=store_standard_projection(analysis,writer,replay=True)
     actual=stored['projection'];graph=stored['graph'];events=stored['events']
    if canonical(actual)!=canonical(expected):raise AssertionError('complete projection changed')
    if graph['digest']!=graph_digest or events['digest']!=events_digest:raise AssertionError('typed digest changed')
   samples.append({'repeat':repeat,'path':label,'rounds':30,'seconds':time.perf_counter()-start,'nodes':writer.node_count})
  finally:writer.close()
sources={name:hashlib.sha256((Path.cwd()/name).read_bytes()).hexdigest() for name in (
 'services/analysis/src/cpag_core/dual_source_export.py','services/analysis/src/cpag_core/compact_projection.py',
 'services/analysis/src/cpag_core/compact_replay.py','services/analysis/src/cpag_core/shared_artifact_store_compact.py')}
record={'version':'r19-standard-projection-microbenchmark-2','scope':'complete small replay final projection and full state store, no capacity acceptance',
 'reference_accepted':False,'projection_sha256':hashlib.sha256(canonical(expected)).hexdigest(),'complete_projection_equal':True,
 'fields':{name:len(analysis[name]) for name in ('network','process','changes','candidates')},'samples':samples,'sources':sources}
(root/'report.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
