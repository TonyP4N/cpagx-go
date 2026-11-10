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

class IndexedEvidenceTests(unittest.TestCase):
    def test_invalid_jsonl_before_valid_and_raw_content(self):
        from cpag_core.evidence import EvidenceIndex
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'network.jsonl'
            path.write_text('{invalid\n'+(FIX/'network.normalized.jsonl').read_text())
            index=EvidenceIndex(path)
            from cpag_core.parsers import parse_network
            event=parse_network(path,evidence=index)['events'][0]
            self.assertEqual(event['source_ref']['record_number'],2)
            raw=index.resolve(event['source_ref'])
            self.assertEqual(raw,json.loads(path.read_text().splitlines()[1]))
            out=Path(tmp)/'out'
            manifest=run(path,FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',out,synthetic=True)
            self.assertEqual(manifest['status'],'succeeded_with_warnings')

    def test_csv_blank_and_multiline_positions_and_raw_values(self):
        from cpag_core.evidence import EvidenceIndex
        from cpag_core.parsers import parse_process
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'process.csv'
            path.write_text('time,level,pump\n\n2026-01-01T00:00:00Z,0,"ON\nOFF"\n')
            index=EvidenceIndex(path)
            profile=json.loads((ROOT/'profiles/synthetic-demo.json').read_text())
            events=parse_process(path,profile,evidence=index)['events']
            self.assertEqual(len(events),2)
            for event in events:
                self.assertEqual(event['source_ref']['record_number'],2)
                self.assertEqual(index.resolve(event['source_ref']),{'time':'2026-01-01T00:00:00Z','level':'0','pump':'ON\nOFF'})

    def test_empty_either_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind,content in [('network',''),('process','time,level,pump\n')]:
                path=Path(tmp)/('empty.jsonl' if kind=='network' else 'empty.csv');path.write_text(content)
                out=Path(tmp)/kind
                with self.assertRaisesRegex(ValueError,kind+':'):
                    run(path if kind=='network' else FIX/'network.normalized.jsonl',path if kind=='process' else FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',out,synthetic=True)
                self.assertFalse(out.exists())

    def test_mutation_before_during_index_and_publication(self):
        from cpag_core.evidence import EvidenceIndex
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'network.jsonl';original=(FIX/'network.normalized.jsonl').read_bytes();path.write_bytes(original)
            digest=file_hash(path);path.write_bytes(original+b'\n')
            with self.assertRaises(ContractError):EvidenceIndex(path,digest)
            path.write_bytes(original)
            real_read=Path.read_bytes
            def mutate_read(p):
                data=real_read(p)
                if p==path:p.write_bytes(data+b'\n')
                return data
            with patch.object(Path,'read_bytes',mutate_read):
                with self.assertRaises(ContractError):EvidenceIndex(path)
            path.write_bytes(original)
            index=EvidenceIndex(path);path.write_bytes(original+b'\n')
            with self.assertRaises(ContractError):index.verify()
            path.write_bytes(original)
            import cpag_core.pipeline as pipeline
            real_validate=pipeline.validate
            def mutate_validate(name,value):
                real_validate(name,value)
                if name=='RunManifest':path.write_bytes(original+b'\n')
            out=Path(tmp)/'out'
            with patch.object(pipeline,'validate',mutate_validate):
                with self.assertRaises(ContractError):run(path,FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',out,synthetic=True)
            self.assertFalse((out/'run_manifest.json').exists())
            path.write_bytes(original)
            def mutate_graph(name,value):
                real_validate(name,value)
                if name=='GraphArtifact':path.write_bytes(original+b'\n')
            out2=Path(tmp)/'before-publication'
            with patch.object(pipeline,'validate',mutate_graph):
                with self.assertRaises(ContractError):run(path,FIX/'process.csv',ROOT/'profiles/synthetic-demo.json',out2,synthetic=True)
            self.assertFalse(out2.exists())


class RawEvidenceValidationTests(unittest.TestCase):
    def test_csv_raw_time_mismatch_fails_before_publication(self):
        from unittest.mock import patch
        from cpag_core.parsers import parse_process
        def wrong_time(*args, **kwargs):
            parsed = parse_process(*args, **kwargs)
            parsed['events'][0]['source_ref']['raw_time'] = '2026-01-01T00:00:01Z'
            return parsed
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'out'
            with patch('cpag_core.parsers.parse_process', wrong_time):
                with self.assertRaisesRegex(ContractError, 'raw time differs'):
                    run(FIX/'network.normalized.jsonl', FIX/'process.csv', ROOT/'profiles/synthetic-demo.json', out, synthetic=True)
            self.assertFalse(out.exists())

    def test_invalid_utf8_is_explicit_and_never_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind, suffix in [('network', '.jsonl'), ('process', '.csv')]:
                path = Path(tmp)/(kind+suffix)
                path.write_bytes(b'\xff')
                out = Path(tmp)/('out-'+kind)
                with self.assertRaisesRegex(ContractError, 'not valid UTF-8'):
                    run(path if kind=='network' else FIX/'network.normalized.jsonl', path if kind=='process' else FIX/'process.csv', ROOT/'profiles/synthetic-demo.json', out, synthetic=True)
                self.assertFalse(out.exists())
