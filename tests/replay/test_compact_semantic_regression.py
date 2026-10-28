"""Independent legacy-core versus compact-storage full snapshot comparison.

The reference retains old ReplayCore and old ReplayInputs. Only its profile
validation dispatch is patched to recognize the same explicitly new profile;
judgement, closure, copying, history and canonical container identities stay old.
No business event/candidate/claim/reference ID is normalized or removed.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round18_profile import fixture,at
from cpag_core import shared_export as core
from cpag_core.contracts import validate as strict_validate
from cpag_core.pipeline import canonical
from cpag_core.replay_core import ReplayCore
from cpag_core.replay_inputs import ReplayInputs
from cpag_core.replay_export import execute
from cpag_core.shared_artifact_store_compact import FORMAT,LogicalHasher


class UncachedLegacyInputs(ReplayInputs):
    pass


def reference_inputs(*args,**kwargs):
    # __new__ dispatch applies only to the exact original class. This subclass
    # keeps its original methods while validating the same explicit hard limits.
    return UncachedLegacyInputs(*args,**kwargs)


def reference_validate(name,value):
    return strict_validate('ReplayCompactProfile' if name=='ReplayProfile' else name,value)


def scenario(root,name,*,projection=True,future=False):
    networks,process,path,config=fixture(root,case='allowed_late' if name=='allowed_late' else 'normal',split=False)
    config.update(capacity_profile='engineering-core-capacity-3',storage_format=FORMAT)
    config['replay'].update(history_format=FORMAT,identity_strategy='merkle-json-dag-1',prefix_digest_strategy='incremental-prefix-digest-2')
    if projection:config['replay']['standard_projection']='standard-graph-events-1'
    sequence=config['replay']['sequence']
    if name in ('duplicate','conflict'):
        step={'source_slot':'network-0','record_number':1,'available_at':at(10.75)}
        if name=='conflict':step['record_sha256']='f'*64
        sequence.insert(4,step)
    if name=='too_late':
        for step in sequence:
            if step.get('source_slot')=='process' and step.get('record_number',0)>=4:
                step['available_at']=at(19+step['record_number']-4)
            if step.get('kind')=='source_eof':step['available_at']=at(22)
            if step.get('kind')=='advance':step['available_at']=at(23)
        config['replay']['finish_at']=at(24)
    if name=='response_outside':config['clocks']['network']['valid_to']=at(10.5)
    if name=='request_outside':config['clocks']['network']['valid_from']=at(10.5)
    if name=='basis':config['clocks']['network']['basis']=None
    if name=='overlap':config['clocks']['network']['precision_seconds']=0.6
    if name=='touch':config['clocks']['network']['precision_seconds']=0.5
    if name=='mapping':config['mappings'].append(dict(config['mappings'][0],rule_id='other-independent-mapping'))
    if future:
        raw=bytearray(networks[0].read_bytes());raw[-1]^=1;networks[0].write_bytes(raw)
        process.write_text(process.read_text()+'2026-01-01T00:00:20Z,777\n')
        for step in sequence:
            if step.get('source_slot')=='network-0' and step.get('record_number')==2:step['available_at']=at(11.5)
            if step.get('kind')=='source_eof':step['available_at']=at(21)
            if step.get('kind')=='advance':step['available_at']=at(22)
        insertion=next(index for index,step in enumerate(sequence) if step.get('kind')=='source_eof')
        sequence.insert(insertion,{'source_slot':'process','record_number':7,'available_at':at(20)})
        config['replay'].update(finish_at=at(23),speed=10,realtime=True)
    path.write_text(json.dumps(config))
    return networks,process,path,config


class CompactSemanticRegression(unittest.TestCase):
    def compare(self,root,name,*,projection=True,future=False):
        networks,process,path,config=scenario(root/'source',name,projection=projection,future=future)
        with patch('cpag_core.replay_core.validate',side_effect=reference_validate),patch('cpag_core.replay_export.ReplayInputs',side_effect=reference_inputs):
            old=execute(networks,process,config,_core_class=ReplayCore)
        try:
            manifest=core.export_task(networks,process,path,root/'new',mode='replay')
            with core.open_reader(root/'new') as reader:
                new=reader.get('history/snapshots');revisions=reader.get('history/revisions');metrics=reader.get('metrics.json')
            expected=json.loads(canonical(old['snapshots']));expected_revisions=json.loads(canonical(old['revisions']))
            self.assertEqual(len(new),len(expected),name)
            self.assertEqual(len(revisions),len(expected_revisions),name)
            snapshot_ids={};state_ids={};reverse_snapshots={};reverse_states={}
            for index,(before,after) in enumerate(zip(expected,new)):
                for forward,reverse,key in ((snapshot_ids,reverse_snapshots,'snapshot_id'),(state_ids,reverse_states,'state_fingerprint')):
                    if before[key] in forward:self.assertEqual(forward[before[key]],after[key],(name,index,key))
                    if after[key] in reverse:self.assertEqual(reverse[after[key]],before[key],(name,index,key))
                    forward[before[key]]=after[key];reverse[after[key]]=before[key]
                self.assertEqual(canonical(before['analysis']),canonical(after['analysis']),(name,index,'complete analysis'))
                self.assertEqual(after['state_fingerprint'],LogicalHasher().digest(after['analysis'])['digest'])
                self.assertEqual(after['snapshot_id'],'snapshot-'+LogicalHasher().digest({key:value for key,value in after.items() if key!='snapshot_id'})['digest'])
                normalized=deepcopy(after)
                normalized['snapshot_id']=before['snapshot_id'];normalized['state_fingerprint']=before['state_fingerprint']
                if 'graph' in normalized:
                    graph=normalized['graph']
                    self.assertEqual(graph['graph_id'],'dual-graph-merkle-'+LogicalHasher().digest({key:value for key,value in graph.items() if key!='graph_id'})['digest'])
                    graph['graph_id']=before['graph']['graph_id']
                self.assertEqual(canonical(before),canonical(normalized),(name,index,'complete snapshot including graph/events'))
            self.assertEqual(len({row['revision_id'] for row in expected_revisions}),len(expected_revisions))
            self.assertEqual(len({row['revision_id'] for row in revisions}),len(revisions))
            for index,(before,after) in enumerate(zip(expected_revisions,revisions)):
                self.assertEqual(after['revision_id'],'revision-'+LogicalHasher().digest({key:value for key,value in after.items() if key!='revision_id'})['digest'])
                normalized=deepcopy(before)
                for key in ('old_snapshot_id','new_snapshot_id'):
                    if normalized[key] is not None:normalized[key]=snapshot_ids[normalized[key]]
                for key in ('old_state_fingerprint','new_state_fingerprint'):
                    if normalized[key] is not None:normalized[key]=state_ids[normalized[key]]
                normalized['revision_id']=after['revision_id']
                self.assertEqual(canonical(normalized),canonical(after),(name,index,'complete revision'))
            self.assertEqual(canonical(old['metrics']),canonical(metrics),(name,'complete deterministic metrics'))
            counts=metrics['counts']
            if name=='duplicate':self.assertEqual(counts['duplicate'],1)
            if name=='conflict':self.assertEqual(counts['conflict'],1)
            if name=='allowed_late':self.assertGreater(counts['late'],0)
            if name=='too_late':self.assertGreater(counts['too_late'],0)
            reasons={'response_outside':'response_clock_validity_outside','request_outside':'request_clock_validity_outside',
                'basis':'response_clock_basis_missing','overlap':'response_order_uncertain','touch':'response_order_uncertain','mapping':'mapping_conflict'}
            if name in reasons:self.assertIn(reasons[name],new[-1]['analysis']['operations'][0]['unknown_reasons'])
            return new,revisions,manifest
        finally:old['inputs'].close()

    def test_default_omission_preserves_the_pre_projection_dag6_reader_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);networks,process,path,_=scenario(root/'source','normal',projection=False)
            manifest=core.export_task(networks,process,path,root/'old-default',mode='replay')
            self.assertEqual(core.verify_task(root/'old-default'),manifest)
            with core.open_reader(root/'old-default') as reader:
                for row in reader.get('history/snapshots'):
                    self.assertNotIn('graph',row)
                    self.assertNotIn('events',row)

    def test_normal_all_snapshot_fields_and_container_id_bijections(self):
        with tempfile.TemporaryDirectory() as directory:self.compare(Path(directory),'normal')

    def test_duplicate_conflict_and_allowed_too_late_preserve_all_business_fields(self):
        for name in ('duplicate','conflict','allowed_late','too_late'):
            with self.subTest(case=name),tempfile.TemporaryDirectory() as directory:self.compare(Path(directory),name)

    def test_r17_clock_and_mapping_unknowns_survive_every_historical_state(self):
        for name in ('response_outside','request_outside','basis','overlap','touch','mapping'):
            with self.subTest(case=name),tempfile.TemporaryDirectory() as directory:self.compare(Path(directory),name)

    def test_future_raw_bytes_schedule_and_speed_cannot_rewrite_prefix(self):
        results=[]
        with tempfile.TemporaryDirectory() as directory:
            for variant in (False,True):
                snapshots,revisions,_=self.compare(Path(directory)/str(variant),'normal',future=variant)
                prefix=[row for row in snapshots if row['arrival_seq']<=4]
                last=prefix[-1]['snapshot_number']
                history=[row for row in revisions if row['new_snapshot_number']<=last]
                results.append((canonical(prefix),canonical(history)))
            self.assertEqual(results[0],results[1])


if __name__=='__main__':unittest.main()
