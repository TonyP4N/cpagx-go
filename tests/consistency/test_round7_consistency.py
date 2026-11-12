import importlib.util
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('round7_consistency',ROOT/'scripts/validation/round7_consistency.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'inputs').mkdir()
        self.payloads={};self.outputs={}
        for label in ('legacy','isolated'):
            payload={}
            for role,src in [('network','tests/fixtures/synthetic/network.normalized.jsonl'),('process','tests/fixtures/synthetic/process.csv'),('profile','profiles/synthetic-demo.json')]:
                source=ROOT/src;target=self.root/'inputs'/(label+'-'+role+source.suffix);shutil.copyfile(source,target)
                payload[role]={'path':target.relative_to(self.root).as_posix(),'sha256':module.file_hash(target)}
            output=self.root/label
            manifest=module.run(*(self.root/payload[role]['path'] for role in ('network','process','profile')),output,synthetic=True)
            payload['config_fingerprint']=manifest['config_fingerprint']
            self.payloads[label]=payload;self.outputs[label]=output
            self.resign(output,payload)
    def resign(self,output,payload):
        core=json.loads((output/'run_manifest.json').read_text())
        for a in core['artifacts']:
            path=output/a['path'];a['sha256']=module.file_hash(path);a['size_bytes']=path.stat().st_size
        core['result_hashes']={'events':module.fingerprint(json.loads((output/'events.json').read_text())),
                               'graph':module.fingerprint(json.loads((output/'graph.json').read_text()))}
        (output/'run_manifest.json').write_bytes(module.canonical(core)+b'\n')
        wrapper={'inputs':{role:payload[role]['sha256'] for role in ('network','process','profile')},
                 'config_fingerprint':payload['config_fingerprint'],'artifacts':[]}
        for name in sorted(module.NAMES):
            path=output/name;wrapper['artifacts'].append({'path':name,'sha256':module.file_hash(path),'size':path.stat().st_size})
        (output/'manifest.json').write_text(json.dumps(wrapper,sort_keys=True)+'\n')
    def compare(self):
        return module.compare_runs(self.outputs['legacy'],self.outputs['isolated'],self.root,
              self.payloads['legacy'],self.payloads['isolated'],{'legacy':platform.python_version(),'isolated':platform.python_version()})
    def test_exact_common_content_and_bounded_metadata_differences(self):
        result=self.compare()
        self.assertTrue(result['valid']);self.assertTrue(result['resolved_evidence_equal'])
        self.assertEqual(result['event_count'],8)
        self.assertEqual(result['observed_difference_paths']['dataset.json'],['/files/0/name','/files/1/name'])
        for name in ('events.json','graph.json','quality.json'):self.assertTrue(result['raw_equal'][name])
    def test_rehashed_quality_change_is_not_ignored(self):
        output=self.outputs['isolated'];path=output/'quality.json';value=json.loads(path.read_text())
        value['network']['reasons'].append('unexpected-change');path.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        with self.assertRaisesRegex(ValueError,'quality.json differs'):self.compare()
    def test_rehashed_manifest_warning_is_not_ignored(self):
        output=self.outputs['isolated'];path=output/'run_manifest.json';value=json.loads(path.read_text());value['warnings'].append('new warning')
        path.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        with self.assertRaisesRegex(ValueError,'unexpected differences'):self.compare()
    def test_evidence_mutation_and_unbound_filename_are_rejected(self):
        output=self.outputs['isolated'];path=output/'events.json';original=path.read_bytes();value=json.loads(original)
        value[0]['source_ref']['record_number']=999;path.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        with self.assertRaisesRegex(ValueError,'logical record'):self.compare()
        path.write_bytes(original)
        dataset=output/'dataset.json';value=json.loads(dataset.read_text());value['files'][0]['name']='unbound-name'
        dataset.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        with self.assertRaisesRegex(ValueError,'snapshot filename'):self.compare()
    def test_unobserved_runtime_version_and_wrapper_hash_are_rejected(self):
        output=self.outputs['isolated'];path=output/'run_manifest.json';value=json.loads(path.read_text());value['tool_versions']['python']='unobserved-runtime'
        path.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        with self.assertRaisesRegex(ValueError,'runtime version'):self.compare()
        value['tool_versions']['python']=platform.python_version();path.write_text(json.dumps(value));self.resign(output,self.payloads['isolated'])
        wrapper=output/'manifest.json';value=json.loads(wrapper.read_text());value['artifacts'][0]['sha256']='0'*64;wrapper.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'publication file hash'):self.compare()

    def test_same_core_source_requires_exact_bytes_and_schema_membership(self):
        observed=module.host_source_hashes()
        self.assertEqual(module.verify_image_sources(observed),observed)
        changed=json.loads(json.dumps(observed));name=next(iter(changed['analysis_files']));changed['analysis_files'][name]='0'*64
        with self.assertRaisesRegex(ValueError,'analysis_files differs'):module.verify_image_sources(changed)
        changed=json.loads(json.dumps(observed));del changed['schema_files'][next(iter(changed['schema_files']))]
        with self.assertRaisesRegex(ValueError,'schema_files differs'):module.verify_image_sources(changed)
