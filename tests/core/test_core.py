import copy
import json
from pathlib import Path
import tempfile
import unittest

from cpag_core.contracts import ContractError, validate
from cpag_core.pipeline import file_hash, fingerprint, resolve_evidence, run

ROOT=Path(__file__).resolve().parents[2]
FIX=ROOT/'tests/fixtures/synthetic'

class CoreTests(unittest.TestCase):
    def invoke(self, output):
        return run(FIX/'network.normalized.jsonl',FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',output,synthetic=True)

    def test_repeated_runs_evidence_and_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifests=[self.invoke(Path(tmp)/str(i)) for i in range(3)]
            self.assertEqual(len({fingerprint(m['result_hashes']) for m in manifests}),1)
            self.assertEqual(len({m['run_id'] for m in manifests}),3)
            for i,manifest in enumerate(manifests):
                out=Path(tmp)/str(i)
                validate('RunManifest',manifest)
                for artifact in manifest['artifacts']:
                    self.assertEqual(file_hash(out/artifact['path']),artifact['sha256'])
                graph=json.loads((out/'graph.json').read_text())
                self.assertEqual(graph['edges'],[])
                self.assertEqual(graph['claims'],[])
                events=json.loads((out/'events.json').read_text())
                self.assertEqual(len(graph['nodes']),len(events))
                sources={file_hash(path):path for path in [FIX/'network.normalized.jsonl',FIX/'process.csv']}
                for event in events:
                    resolve_evidence(event['source_ref'],sources)
                    validate('ProcessObservation' if 'tag' in event else 'NetworkEvent',event)
            before=(Path(tmp)/'0/run_manifest.json').read_bytes()
            with self.assertRaises(FileExistsError): self.invoke(Path(tmp)/'0')
            self.assertEqual(before,(Path(tmp)/'0/run_manifest.json').read_bytes())

    def test_volatile_fields_excluded(self):
        self.assertEqual(fingerprint({'run_id':'x','nested':{'ingest_time':'x','value':0}}), fingerprint({'run_id':'y','nested':{'ingest_time':'y','value':0}}))
        self.assertNotEqual(fingerprint({'value':None}),fingerprint({'value':0}))

    def test_requires_synthetic_and_resolved_evidence(self):
        with self.assertRaises(ValueError): run('a','b',{},'unused',synthetic=False)
        with self.assertRaises(ContractError): resolve_evidence({'file_sha256':'0'*64}, {})
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source';path.write_text('original')
            digest=file_hash(path);path.write_text('changed')
            with self.assertRaises(ContractError): resolve_evidence({'file_sha256':digest},{digest:path})

    def test_config_fingerprint_changes(self):
        config=json.loads((ROOT/'profiles/synthetic-demo.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            baseline=self.invoke(Path(tmp)/'a')
            config['profile_id']='different-config-version'
            changed=run(FIX/'network.normalized.jsonl',FIX/'process.csv',config,Path(tmp)/'b',synthetic=True)
            self.assertNotEqual(baseline['config_fingerprint'],changed['config_fingerprint'])
            config['run_id']='retained-config-key'
            volatile_named=run(FIX/'network.normalized.jsonl',FIX/'process.csv',config,Path(tmp)/'c',synthetic=True)
            self.assertNotEqual(changed['config_fingerprint'],volatile_named['config_fingerprint'])

if __name__=='__main__': unittest.main()

class EvidenceBoundaryTests(unittest.TestCase):
    def test_logical_record_and_column_bounds(self):
        path=FIX/'process.csv'
        digest=file_hash(path)
        ref={'file_sha256':digest,'record_number':9999,'frame_number':None,'column':'level','raw_time':None}
        with self.assertRaises(ContractError):resolve_evidence(ref,{digest:path})
        ref.update(record_number=1,column='not-a-column')
        with self.assertRaises(ContractError):resolve_evidence(ref,{digest:path})
        ref.update(record_number=0,column='level')
        with self.assertRaises(ContractError):resolve_evidence(ref,{digest:path})

class SourceFailureTests(unittest.TestCase):
    def test_invalid_one_source_does_not_hide_behind_valid_other_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp)/'network.jsonl'
            bad.write_text('{broken-json\n')
            out = Path(tmp)/'run'
            with self.assertRaisesRegex(ValueError, 'network:'):
                run(bad,FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',out,synthetic=True)
            self.assertFalse(out.exists())
            with self.assertRaisesRegex(ValueError, 'process:'):
                run(FIX/'network.normalized.jsonl',FIX/'process.csv',{},out,synthetic=True)
            self.assertFalse(out.exists())
