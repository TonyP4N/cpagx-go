"""Fixed 60-arrival prefix diagnostic, never full S100 acceptance."""
import argparse,ast,json,subprocess,time
from pathlib import Path
from unittest.mock import patch
from cpag_core import dual_source,shared_artifact_store_compact as store
from cpag_core.source_merkle_sink import TypedMerkleSourceSink
from cpag_core.compact_replay import CompactHistorySink,CompactReplayCore
from cpag_core.replay_export import execute
from cpag_core.pipeline import canonical

def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 root=Path(a.output);root.mkdir(parents=True,exist_ok=False);f=Path(a.fixture)
 config=json.loads((f/'replay-profile.json').read_text());config['replay']['sequence']=config['replay']['sequence'][:60]
 config['replay']['finish_at']=config['replay']['sequence'][-1]['available_at']
 profile=root/'profile.json';profile.write_bytes(canonical(config))
 source=subprocess.check_output(['git','show','98cb2b7:services/analysis/src/cpag_core/dual_source.py'],text=True)
 node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='references')
 namespace=dict(vars(dual_source));exec(compile(ast.Module(body=[node],type_ignores=[]),'baseline-references','exec'),namespace)
 old_refs=namespace['references'];new_refs=dual_source.references;new_hash=store._hash
 rows=[]
 for old in (True,False):
  # Import before patch so both callers use the selected implementation.
  from cpag_core import compact_replay
  start=time.monotonic()
  with patch.object(dual_source,'references',old_refs if old else new_refs),patch.object(compact_replay,'references',old_refs if old else new_refs),patch.object(store,'_hash',store._uncached_hash if old else new_hash):
   writer=TypedMerkleSourceSink();sink=CompactHistorySink(writer)
   try:execute([f/'network.pcap'],f/'process.csv',config,history_sink=sink,_core_class=CompactReplayCore)
   except ValueError as error:
    if str(error)!='input_not_exhausted':raise
   else:raise AssertionError('prefix unexpectedly exhausted inputs')
  roots={'snapshots':sink.snapshots,'revisions':sink.revisions}
  writer.close()
  rows.append({'implementation':'baseline' if old else 'optimized','seconds':time.monotonic()-start,'roots':roots})
  (root/'result.json').write_text(json.dumps({'scope':'60-arrival source computation diagnostic; intentionally incomplete input, no trusted export','results':rows},indent=2))
 assert rows[0]['roots']==rows[1]['roots'],'complete business roots changed'
if __name__=='__main__':main()
