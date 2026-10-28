"""DAG6 source sink versus physical writer, without trusting retained roots."""
from copy import deepcopy
from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from dual_source_fixtures import make_case
from round17_profile import profile
from round18_profile import fixture as replay_fixture
from cpag_core.shared_artifact_store_compact import FORMAT,SharedArtifactWriter
from cpag_core.source_merkle_sink import TypedMerkleSourceSink,STRATEGY_VERSION
from cpag_core.shared_export import _build_business_roots,writer_options,verify_task,issue_approval
from cpag_core.pipeline import canonical,file_hash

CONTEXT={'run_id':'source-sink-test','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}


def populate(writer):
    refs=[{'record_number':index,'frame_number':None,'record_sha256':str(index%10)*64,'column':'泵','raw_time':None} for index in range(20)]
    value={'operation':{'id':'op-1','response':'pending'},'unknown':['clock'],
           'claims':[{'id':'claim-1','status':'hypothetical','counterevidence':refs}],
           'values':[None,True,False,1,1.0,-0.0,'中文',[],{}],'ordered':list(range(1025))}
    snapshots=[];revisions=[];returned=[]
    for number in range(3):
        if number==1:value['operation']['response']='success'
        if number==2:value['unknown'].append('identity-not-proven');value['claims'][0]['counterevidence'].append({'note':'all retained'})
        state=writer.intern(value);returned.append(state)
        metadata={'number':number,'identity_strategy':'merkle-json-dag-1'}
        before=writer.compose(None,metadata,{'analysis':state['digest']})
        metadata['snapshot_id']='snapshot-'+before['digest']
        snapshot=writer.compose(None,metadata,{'analysis':state['digest']});returned.append(snapshot);snapshots.append(snapshot['digest'])
        revision=writer.intern({'number':number,'new_snapshot':snapshot['digest'],'evidence':refs});revisions.append(revision['digest'])
    returned.append(writer.sequence('history/snapshots',snapshots))
    returned.append(writer.sequence('history/revisions',revisions))
    returned.append(writer.add('analysis.json',value));returned.append(writer.alias('dual/analysis.json','analysis.json'))
    returned.append(writer.add('graph.json',{'nodes':refs,'claims':value['claims'],'edges':[{'id':'claim-1'}]}))
    returned.append(writer.add('metrics.json',{'counts':{'accepted':3,'unknown':1},'samples':[1,2,3]}))
    returned.append(writer.add('runtime_metrics.json',{'wall_seconds':0.25,'samples':[0.0,-0.0]}))
    return returned


class SourceMerkleSinkTests(unittest.TestCase):
    def test_every_descriptor_node_count_and_root_index_equal_the_physical_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'producer',context=CONTEXT,version=FORMAT)
            expected=populate(writer);sealed=writer.seal()
            before=set(Path(directory).rglob('*'))
            with patch.object(sqlite3,'connect',side_effect=AssertionError('source sink must not create SQLite')):
                sink=TypedMerkleSourceSink(context=CONTEXT)
                actual=populate(sink);source=sink.seal()
            self.assertEqual(actual,expected)
            self.assertEqual(source['node_count'],sealed['manifest']['node_count'])
            self.assertEqual(source['root_count'],sealed['manifest']['root_count'])
            self.assertEqual(source['roots_index_sha256'],sealed['manifest']['roots_index_sha256'])
            self.assertEqual(source['physical_artifacts_created'],0)
            self.assertEqual(set(Path(directory).rglob('*')),before)
            self.assertEqual(source['verification_strategy'],STRATEGY_VERSION)
            self.assertLessEqual(source['flat_value_cache_owned_bytes'],source['limits']['cache_bytes'])
            sink.close();self.assertEqual(len(sink._nodes),0)

    def test_compose_cannot_accept_an_original_or_guessed_root_not_rebuilt_from_values(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'original',context=CONTEXT,version=FORMAT)
            retained=writer.intern({'genuine':'original value'});writer.add('original',[1]);writer.seal()
            sink=TypedMerkleSourceSink()
            with self.assertRaisesRegex(ValueError,'not_computed'):sink.compose('forged',{}, {'analysis':retained['digest']})
            self.assertTrue(sink.failed)
            with self.assertRaises(ValueError):sink.seal()
            sink.close()
        sink=TypedMerkleSourceSink()
        expected=sink.intern({'counterevidence':[{'record_sha256':'a'*64}]})
        altered=sink.intern({'counterevidence':[{'record_sha256':'b'*64}]})
        self.assertNotEqual(expected['digest'],altered['digest'])
        sink.close()

    def test_unchanged_limits_and_failed_rebuild_never_seals(self):
        cases=({'max_nodes':1},{'max_node_bytes':2},{'max_depth':1},{'max_array_items':1},{'max_logical_root_bytes':4})
        for options in cases:
            with self.subTest(options=options):
                sink=TypedMerkleSourceSink(**options)
                with self.assertRaises(ValueError):sink.add('bad',{'nested':{'values':[1,2]}})
                with self.assertRaises(ValueError):sink.seal()
                self.assertTrue(sink.report()['failed']);sink.close()
        sink=TypedMerkleSourceSink(max_roots=1);sink.add('one',1)
        with self.assertRaises(ValueError):sink.alias('second','one')
        sink.close()
        sink=TypedMerkleSourceSink();sink.deadline=time.monotonic()-1
        with self.assertRaises(ValueError):sink.intern({'late':True})
        sink.close()
        with patch('cpag_core.source_merkle_sink.MAX_INDEX_BYTES',1):
            sink=TypedMerkleSourceSink()
            with self.assertRaisesRegex(ValueError,'index_memory_limit'):sink.intern('bounded')
            sink.close()
        for version in ('future','shared-observation-dag-5'):
            with self.assertRaises(ValueError):TypedMerkleSourceSink(version=version)

    def test_complete_offline_and_replay_shared_source_flow_roots_match_without_sqlite(self):
        for mode in ('offline','replay'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                if mode=='offline':
                    network,process,path=make_case(root/'inputs');networks=[network];config=profile()
                else:
                    networks,process,path,config=replay_fixture(root/'inputs')
                    config['replay'].update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2',standard_projection='standard-graph-events-1')
                config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT,storage_budget_version='shared-storage-budget-2')
                path.write_text(json.dumps(config))
                rows=[{'kind':kind,'sha256':file_hash(source),'size_bytes':source.stat().st_size} for kind,source in [('network',p) for p in networks]+[('process',process)]]
                options=writer_options(config,1024**3)
                physical=SharedArtifactWriter(root/'producer',context=CONTEXT,version=FORMAT,**options)
                expected=_build_business_roots(physical,networks,process,config,rows,mode);physical.seal()
                sink=TypedMerkleSourceSink(context=CONTEXT,**options)
                with patch.object(sqlite3,'connect',side_effect=AssertionError('source flow must not create second SQLite')):
                    actual=_build_business_roots(sink,networks,process,config,rows,mode)
                expected_roots={row['name']:row for row in expected['logical_artifacts']};actual_roots={row['name']:row for row in actual['logical_artifacts']}
                self.assertEqual(set(actual_roots),set(expected_roots))
                for name in expected_roots:
                    # Every raw wall-clock sample remains retained/authenticated,
                    # but cannot be regenerated by running a later real clock.
                    if name!='runtime_metrics.json':self.assertEqual(actual_roots[name],expected_roots[name],(mode,name))
                for key in expected:
                    if key!='logical_artifacts':self.assertEqual(actual[key],expected[key],(mode,key))
                for name in ('analysis.json','graph.json','metrics.json','history/snapshots','history/revisions') if mode=='replay' else ('analysis.json','graph.json'):
                    self.assertIn(name,actual_roots)
                self.assertEqual(sink.report()['physical_artifacts_created'],0);sink.close()

    def test_new_verification_strategy_still_rejects_a_self_consistent_forged_artifact(self):
        from test_shared_source_tampering import build,rehash_everything
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build(root)
            def mutate(documents,manifest):
                documents['analysis.json']['operations'][0]['response']['state']='error'
                documents['dual/analysis.json']=deepcopy(documents['analysis.json'])
            rehash_everything(root/'output',mutate)
            for strategy in (STRATEGY_VERSION,'source-sqlite-reexport-1'):
                with self.subTest(strategy=strategy),self.assertRaisesRegex(ValueError,'does_not_match_sources'):
                    verify_task(root/'output',verification_strategy=strategy)
                with self.subTest(strategy=strategy),self.assertRaises(ValueError):issue_approval(root/'output',b'k'*32,verification_strategy=strategy)


if __name__=='__main__':unittest.main()
