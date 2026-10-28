"""Complete small-case projection prototype; no capacity/throughput claim."""
from pathlib import Path
import cProfile,hashlib,json,pstats,sys,time
from unittest.mock import patch
sys.path[:0]=[str(Path.cwd()/'services/analysis/src'),str(Path.cwd()/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import execute
from cpag_core import dual_source_export as projection
from cpag_core.shared_artifact_store_compact import SharedArtifactWriter,LogicalHasher,FORMAT
from cpag_core.pipeline import canonical
root=Path(sys.argv[1]);fixture_root=root/'fixture'
networks,process,path,config=fixture(fixture_root,case='normal',split=False)
run=execute(networks,process,config);analysis=run['analysis'];run['inputs'].close()
profile=cProfile.Profile();timing={'logical_identity_seconds':0.0,'schema_validation_seconds':0.0,'logical_identity_calls':0,'schema_validation_calls':0}
original_digest=LogicalHasher.digest;original_validate=projection.validate

def digest(self,value):
 start=time.perf_counter();timing['logical_identity_calls']+=1
 try:return original_digest(self,value)
 finally:timing['logical_identity_seconds']+=time.perf_counter()-start

def validate(*args):
 start=time.perf_counter();timing['schema_validation_calls']+=1
 try:return original_validate(*args)
 finally:timing['schema_validation_seconds']+=time.perf_counter()-start

with patch.object(LogicalHasher,'digest',digest),patch.object(projection,'validate',validate):
 start=time.perf_counter();profile.enable()
 for _ in range(30):expected=projection.event_graph(analysis,replay=True,identity_strategy='merkle-json-dag-1')
 profile.disable();timing['projection_total_seconds']=time.perf_counter()-start
with (root/'projection-profile.txt').open('w') as stream:pstats.Stats(profile,stream=stream).sort_stats('cumtime').print_stats(25)
context={'run_id':'projection-micro','attempt_id':1,'input_fingerprint':analysis['input_fingerprint'],'config_fingerprint':analysis['config_fingerprint']}
measurements={}
for label in ('existing','compose_prototype'):
 writer=SharedArtifactWriter(root/label,context=context,version=FORMAT)
 start=time.perf_counter();rounds=15
 try:
  for _ in range(rounds):
   state=writer.intern(analysis)
   if label=='existing':
    actual=projection.event_graph(analysis,replay=True,identity_strategy='merkle-json-dag-1')
    graph=writer.intern(actual['graph.json']);events=writer.intern(actual['events.json'])
   else:
    stored={}
    def composed(sans):
     values={};references={}
     for name,value in sans.items():
      if type(value) in (dict,list,tuple):references[name]=writer.intern(value)['digest']
      else:values[name]=value
     identity=writer.compose(None,values,references)
     stored['graph']=writer.compose(None,{**values,'graph_id':'dual-graph-merkle-'+identity['digest']},references)
     return identity
    with patch.object(projection.__import__('builtins') if False else sys.modules['cpag_core.shared_artifact_store_compact'],'LogicalHasher') as factory:
     factory.return_value.digest.side_effect=composed
     actual=projection.event_graph(analysis,replay=True,identity_strategy='merkle-json-dag-1')
    graph=stored['graph'];events=writer.intern(actual['events.json'])
   if canonical(actual)!=canonical(expected):raise AssertionError('complete projection changed')
   if graph['digest']!=LogicalHasher().digest(expected['graph.json'])['digest']:raise AssertionError('composed graph identity changed')
  measurements[label]={'seconds':time.perf_counter()-start,'rounds':rounds,'nodes':writer.node_count}
 finally:writer.close()
sources={str(p.relative_to(Path.cwd())):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(projection.__file__),Path(sys.modules['cpag_core.compact_replay'].__file__)]} if 'cpag_core.compact_replay' in sys.modules else {str(Path(projection.__file__).relative_to(Path.cwd())):hashlib.sha256(Path(projection.__file__).read_bytes()).hexdigest()}
record={'version':'r19-standard-projection-microbenchmark-1','scope':'one-request small replay, complete content equal; no S/M/L performance acceptance','reference_accepted':False,'fields':{'network':len(analysis['network']),'process':len(analysis['process']),'changes':len(analysis['changes']),'candidates':len(analysis['candidates'])},'timing_profiled':timing,'writer_micro':measurements,'source':sources,'projection_sha256':hashlib.sha256(canonical(expected)).hexdigest()}
(root/'report.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
