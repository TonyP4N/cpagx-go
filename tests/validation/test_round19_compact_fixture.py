"""Core-only DAG6 fixtures preserve raw density and refuse formal Go dispatch."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
import round19_scale_fixture as fixture
import round19_capacity as formal


class CompactFixtureControls(unittest.TestCase):
    def test_each_scale_explicit_core_version_preserves_raw_and_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            for scale,count in (('S',100),('M',1000),('L',10000)):
                root=Path(directory)/scale;report=fixture.generate(root,scale,version=fixture.COMPACT_VERSION)
                self.assertEqual(report['execution_scope'],'core_only');self.assertFalse(report['integration_ready'])
                for name,digest in fixture.RAW_SHA256[scale].items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest)
                matrix=json.loads((root/'matrix.json').read_text());self.assertIsNone(matrix['operator_resource_profile']);self.assertEqual(matrix['schema_version'],'r19-density-core-matrix-1')
                self.assertEqual(matrix['core_limits']['output_bytes'],1024**3)
                for mode in ('dual_source','dual_source_replay'):
                    preflight=fixture.read_preflight(root/(mode+'-1.json'))
                    self.assertEqual(preflight['status'],'admissible_for_core_attempt');self.assertEqual(preflight['execution_scope'],'core_only')
                    self.assertEqual(preflight['capacity_profile'],fixture.COMPACT_PROFILE);self.assertEqual(preflight['storage_format'],fixture.COMPACT_FORMAT)
                    self.assertEqual(preflight['density_math']['operations'],count)
                    cfg=json.loads((root/preflight['profile']).read_text());self.assertEqual(cfg['window_seconds'],5)
                    if mode=='dual_source_replay':
                        self.assertEqual(cfg['replay']['history_format'],fixture.COMPACT_FORMAT)
                        self.assertEqual(len(cfg['replay']['sequence']),3*count+4)
                        self.assertEqual(cfg['replay']['max_snapshots'],65000)
                        self.assertEqual(cfg['replay']['allowed_lateness_seconds'],2)
                        self.assertEqual(cfg['replay']['buffer_seconds'],300)

    def test_upgrade_copies_existing_raw_bytes_and_preserves_business_config(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'shared3';target=Path(directory)/'core4'
            fixture.generate(source,'S',version=fixture.SHARED_VERSION)
            before={p.name:p.read_bytes() for p in source.iterdir() if p.is_file()}
            result=fixture.upgrade(source,target)
            self.assertEqual(result['schema_version'],fixture.COMPACT_VERSION)
            for name in fixture.RAW_SHA256['S']:self.assertEqual((source/name).read_bytes(),(target/name).read_bytes())
            self.assertEqual({p.name:p.read_bytes() for p in source.iterdir() if p.is_file()},before)
            self.assertEqual(result['upgrade']['source_fixture_version'],fixture.SHARED_VERSION)
            with self.assertRaises(FileExistsError):fixture.upgrade(source,target)
            cfg=json.loads((source/'offline-profile.json').read_text());cfg['window_seconds']=4
            (source/'offline-profile.json').write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError,'business_configuration'):fixture.upgrade(source,Path(directory)/'reject')
            self.assertFalse((Path(directory)/'reject').exists())

    def test_core_case_never_dispatches_formal_go_or_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'core';fixture.generate(root,'S',version=fixture.COMPACT_VERSION)
            environment={'reference_environment_qualified':False,'reference_refusal_reasons':['development_host']}
            with patch.object(formal,'probe',return_value=environment),patch.object(formal,'formal_case') as launch,patch.object(formal.Recorder,'command') as command:
                code,record=formal.execute(Path(directory)/'refused',dev_run=True,case_manifest=root/'dual_source-1.json',resource_profile=fixture.COMPACT_PROFILE)
            self.assertEqual(code,1);launch.assert_not_called();command.assert_not_called()
            self.assertIn('density_budget_design_refused',record['error'])
            (root/'preflight.json').unlink()
            with self.assertRaisesRegex(ValueError,'preflight_missing'):fixture.read_preflight(root/'dual_source-1.json')

    def test_version5_explicit_extent_and_standard_projection_preserve_version4(self):
        with tempfile.TemporaryDirectory() as directory:
            for scale in ('S','M','L'):
                old=Path(directory)/(scale+'-4');new=Path(directory)/(scale+'-5')
                fixture.generate(old,scale,version=fixture.COMPACT_VERSION)
                before={name:(old/name).read_bytes() for name in ('network.pcap','process.csv','offline-profile.json','replay-profile.json')}
                fixture.upgrade(old,new,version=fixture.COMPACT_STANDARD_VERSION)
                for name in fixture.RAW_SHA256[scale]:self.assertEqual((new/name).read_bytes(),before[name])
                self.assertEqual({name:(old/name).read_bytes() for name in before},before)
                if scale=='S':
                    self.assertEqual(hashlib.sha256(before['offline-profile.json']).hexdigest(),'492f689a6b04ef28bf2fbdb1023993d748efba9fed41f0e165c8a46b3409473e')
                    self.assertEqual(hashlib.sha256(before['replay-profile.json']).hexdigest(),'2bd7dcc4ff4682f1d0a201d88ad7f84fc902f96e6538df8d794f52e4ede029d0')
                for mode,name in (('dual_source','offline-profile.json'),('dual_source_replay','replay-profile.json')):
                    prior=json.loads(before[name]);current=json.loads((new/name).read_text())
                    self.assertNotIn('storage_budget_version',prior)
                    self.assertEqual(current.pop('storage_budget_version'),'shared-storage-budget-2')
                    if mode=='dual_source_replay':self.assertEqual(current['replay'].pop('standard_projection'),'standard-graph-events-1')
                    self.assertEqual(prior,current)
                    p4=fixture.read_preflight(old/(mode+'-1.json'));p5=fixture.read_preflight(new/(mode+'-1.json'))
                    self.assertEqual(p4['storage_budget']['max_logical_root_bytes'],512*1024**3)
                    self.assertEqual(p5['storage_budget']['max_logical_root_bytes'],4*1024**5)
                    b4=dict(p4['storage_budget']);b5=dict(p5['storage_budget'])
                    for key in ('version','max_logical_root_bytes'):b4.pop(key);b5.pop(key)
                    self.assertEqual(b4,b5)
                    self.assertFalse(p5['logical_extent_guard']['whole_root_materialization_authorized'])
                    self.assertIn('does not allocate',p5['logical_extent_guard']['meaning'])
                    self.assertEqual(p5['status'],'admissible_for_core_attempt')
                    self.assertEqual(p5['logical_extent_guard']['physical_output_bytes'],1024**3)
                self.assertEqual(json.loads((old/'matrix.json').read_text())['core_limits'],json.loads((new/'matrix.json').read_text())['core_limits'])
                with self.assertRaisesRegex(ValueError,'downgrade_forbidden'):fixture.upgrade(new,Path(directory)/(scale+'-reject4'),version=fixture.COMPACT_VERSION)

    def test_version5_tamper_or_missing_projection_cannot_reuse_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'5';fixture.generate(root,'S',version=fixture.COMPACT_STANDARD_VERSION)
            case=root/'dual_source_replay-1.json'
            source=(root/'replay-profile.json').read_bytes();cfg=json.loads(source)
            cfg['replay'].pop('standard_projection');(root/'replay-profile.json').write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError,'profile_or_schedule_changed'):fixture.read_preflight(case)
            (root/'replay-profile.json').write_bytes(source)
            preflight=json.loads((root/'preflight.json').read_text())
            preflight['modes']['dual_source_replay']['logical_extent_guard']['whole_root_materialization_authorized']=True
            (root/'preflight.json').write_text(json.dumps(preflight))
            with self.assertRaisesRegex(ValueError,'preflight_or_bindings_changed'):fixture.read_preflight(case)
            (root/'preflight.json').unlink()
            with self.assertRaisesRegex(ValueError,'preflight_missing'):fixture.read_preflight(case)

    def test_version5_core_only_still_refuses_formal_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'core5';fixture.generate(root,'S',version=fixture.COMPACT_STANDARD_VERSION)
            environment={'reference_environment_qualified':False,'reference_refusal_reasons':['development_host']}
            with patch.object(formal,'probe',return_value=environment),patch.object(formal,'formal_case') as launch,patch.object(formal.Recorder,'command') as command:
                code,record=formal.execute(Path(directory)/'refused',dev_run=True,case_manifest=root/'dual_source_replay-1.json',resource_profile=fixture.COMPACT_PROFILE)
            self.assertEqual(code,1);launch.assert_not_called();command.assert_not_called()
            self.assertIn('density_budget_design_refused',record['error'])


if __name__=='__main__':unittest.main()
