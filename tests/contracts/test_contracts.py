import copy
import json
from pathlib import Path
import unittest
from cpag_core.contracts import validate, ContractError, SCHEMAS

class ContractTests(unittest.TestCase):
    def test_strict_schema_documents(self):
        paths=list(SCHEMAS.glob('*.schema.json'))
        self.assertEqual({p.stem.removesuffix('.schema') for p in paths}, {'DualSourceProfile','Asset','Claim','DatasetManifest','DerivedEvent','EvaluationRecord','GraphArtifact','NetworkEvent','ProcessObservation','RunManifest','PacketObservationArtifact','EvaluationSplit','EvaluationPredictions','EvaluationAnnotations','EvaluationRegistration','ReplayProfile','ReplaySourceRef','ReplayClaim','ReplayDerivedEvent','ReplayGraphArtifact','ReplayNetworkEvent','ReplayProcessObservation','ReplayRevision','ReplayRunManifest'})
        for path in paths:
            schema=json.loads(path.read_text())
            self.assertFalse(schema['additionalProperties'])
            if path.name not in ('ReplayProfile.schema.json','ReplaySourceRef.schema.json'):
                self.assertEqual(schema['properties']['schema_version']['const'],'1.0.0')
                self.assertIn('synthetic',schema['required'])
            elif path.name=='ReplayProfile.schema.json':
                self.assertEqual(schema['properties']['version']['const'],'dual-source-replay-1')
                self.assertIn('arrival_time_basis',schema['required'])
            else:
                self.assertIn('record_sha256',schema['required'])
                self.assertIn('source_slot',schema['required'])
                self.assertNotIn('file_sha256',schema['properties'])
            import jsonschema
            jsonschema.Draft202012Validator.check_schema(schema)

    def test_reject_invalid_contracts(self):
        asset={'schema_version':'1.0.0','synthetic':True,'asset_id':'asset','role':'unknown','aliases':[],
               'process_stage':None,'valid_time':{'start':None,'end':None},'config_version':'m1'}
        validate('Asset',asset)
        variants=[]
        for key,value in [('unknown',True),('schema_version','2.0.0'),('synthetic','true'),('aliases',[1])]:
            bad=copy.deepcopy(asset);bad[key]=value;variants.append(bad)
        bad=copy.deepcopy(asset);del bad['asset_id'];variants.append(bad)
        bad=copy.deepcopy(asset);bad['valid_time']['unexpected']=True;variants.append(bad)
        for timestamp in ['2026-01-01T00:00:00','2026-02-30T00:00:00Z','arbitrary']:
            bad=copy.deepcopy(asset);bad['valid_time']['start']=timestamp;variants.append(bad)
        for bad in variants:
            with self.assertRaises(ContractError):validate('Asset',bad)

    def test_evaluation_independence_required(self):
        evaluation={'schema_version':'1.0.0','synthetic':True,'evaluation_id':'e','run_id':'r','data_split':'held-out',
                    'label_source':'human annotation','annotation_version':'v1','matching_strategy':'none','metrics':{},
                    'error_analysis':[],'independent_labels':False}
        for flag in (False,1,'true'):
            evaluation['independent_labels']=flag
            with self.assertRaises(ContractError):validate('EvaluationRecord',evaluation)

if __name__=='__main__':unittest.main()

class IndependentSchemaTests(unittest.TestCase):
    def test_export_against_independent_jsonschema(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        import tempfile
        from cpag_core.pipeline import run
        root=Path(__file__).resolve().parents[2]
        schemas={p.name:json.loads(p.read_text()) for p in SCHEMAS.glob('*.json')}
        registry=Registry().with_resources((name,Resource.from_contents(schema)) for name,schema in schemas.items())
        def check(name,value):
            schema=schemas[name+'.schema.json']
            validator=Draft202012Validator(schema,format_checker=FormatChecker(),registry=registry)
            validator.validate(value)
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'run'
            run(root/'tests/fixtures/synthetic/network.normalized.jsonl',root/'tests/fixtures/synthetic/process.csv',root/'profiles/synthetic-demo.json',output,synthetic=True)
            for name,file in [('DatasetManifest','dataset.json'),('GraphArtifact','graph.json'),('RunManifest','run_manifest.json')]:
                check(name,json.loads((output/file).read_text()))
            for event in json.loads((output/'events.json').read_text()):
                name='ProcessObservation' if 'tag' in event else 'NetworkEvent'
                check(name,event)
                event['unknown']=True
                with self.assertRaises(Exception):check(name,event)
                with self.assertRaises(ContractError):validate(name,event)

class SharedExampleTests(unittest.TestCase):
    def test_all_ten_examples_shared_with_go(self):
        examples=json.loads((Path(__file__).with_name('examples.json')).read_text())
        self.assertEqual(len(examples),10)
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        schemas={p.name:json.loads(p.read_text()) for p in SCHEMAS.glob('*.json')}
        registry=Registry().with_resources((name,Resource.from_contents(schema)) for name,schema in schemas.items())
        for name,value in examples.items():
            validate(name,value)
            if Draft202012Validator:
                schema=schemas[name+'.schema.json']
                Draft202012Validator(schema,format_checker=FormatChecker(),registry=registry).validate(value)
            value['schema_version']='unsupported'
            with self.assertRaises(ContractError):validate(name,value)

class SharedPacketNegativeTests(unittest.TestCase):
    def test_shared_packet_mutations_rejected_by_runtime_and_independent_schema(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        examples=json.loads(Path(__file__).with_name('examples.json').read_text())
        cases=json.loads(Path(__file__).with_name('packet-negative-mutations.json').read_text())
        schemas={p.name:json.loads(p.read_text()) for p in SCHEMAS.glob('*.json')}
        registry=Registry().with_resources((name,Resource.from_contents(schema)) for name,schema in schemas.items())
        for case in cases:
            with self.subTest(case=case['label']):
                value=copy.deepcopy(examples[case['schema']]);parent=value
                parts=case['path'].strip('/').split('/')
                for key in parts[:-1]:parent=parent[int(key)] if isinstance(parent,list) else parent[key]
                if case['operation']=='delete':del parent[parts[-1]]
                else:parent[parts[-1]]=case['value']
                with self.assertRaises(ContractError):validate(case['schema'],value)
                validator=Draft202012Validator(schemas[case['schema']+'.schema.json'],registry=registry)
                with self.assertRaises(Exception):validator.validate(value)
