"""Independent round trips for isolated DAG prototype, not M/L pipeline acceptance."""
import copy
import hashlib
import json
import math
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import unittest

from cpag_core.pipeline import canonical,file_hash
from cpag_core.shared_artifact_store import SharedArtifactWriter,SharedArtifactReader,FORMAT

CONTEXT={'run_id':'independent-prototype','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}


def source_documents():
    # Test author supplies all states, unknowns, claims and counterevidence.
    evidence={'source_slot':'process','record_sha256':'c'*64,'frame_number':None,'record_number':2,
              'column':'pump','raw_time':'2026-01-01T00:00:09.000000Z'}
    unknown={'reason':'independent-unknown','evidence_refs':[evidence]}
    claim={'claim_id':'claim-1','status':'hypothetical','counterevidence':[evidence],
           'evidence_refs':[evidence],'assumptions':['does-not-prove-causality']}
    candidate={'candidate_id':'candidate-1','state':'unknown','claim':claim,
               'counterevidence':[unknown],'unknown_reasons':['clock-basis-unverified']}
    analysis={'network':[{'event_id':'n-1','unknown':unknown}], 'process':[{'event_id':'p-1','source_ref':evidence}],
              'operations':[{'operation_id':'op-1','response':{'state':'success'},'counterevidence':[unknown]}],
              'changes':[{'event_id':'change-1','evidence_refs':[evidence]}], 'candidates':[candidate],
              'quality':{'status':'partial','reasons':['unknown-preserved']}}
    graph={'nodes':[{'id':'n-1','evidence_refs':[evidence]}], 'edges':[{'id':'candidate-1'}], 'claims':[claim]}
    return {'analysis.json':analysis,'graph.json':graph,'events.json':analysis['network']+analysis['process']+analysis['changes'],
            'history/snapshots/000000':{'phase':'pending_response','analysis':dict(analysis,candidates=[])},
            'history/snapshots/000001':{'phase':'finished','analysis':analysis}}


class SharedArtifactStoreTests(unittest.TestCase):
    def build(self,root,documents=None,**kwargs):
        documents=documents or source_documents()
        writer=SharedArtifactWriter(root,context=CONTEXT,version=FORMAT,**kwargs)
        for name,value in documents.items():writer.add(name,value)
        sealed=writer.seal()
        reader=SharedArtifactReader(root,expected_manifest_sha256=sealed['manifest_sha256'],expected_context=CONTEXT)
        self.addCleanup(reader.close)
        return writer,sealed,reader

    def test_complete_roundtrip_stream_hash_and_all_business_fields(self):
        documents=source_documents()
        with tempfile.TemporaryDirectory() as directory:
            writer,sealed,reader=self.build(Path(directory)/'store',documents)
            for name,expected in documents.items():
                payload=canonical(expected)
                self.assertEqual(reader.get(name),expected)
                self.assertEqual(reader.canonical_sha256(name,max_bytes=len(payload)),hashlib.sha256(payload).hexdigest())
                self.assertEqual(b''.join(reader.iter_canonical(name,max_bytes=len(payload))),payload)
            self.assertEqual(reader.get('analysis.json',path=['candidates',0,'counterevidence']),documents['analysis.json']['candidates'][0]['counterevidence'])
            self.assertEqual(reader.get('graph.json',path=['claims',0]),documents['graph.json']['claims'][0])
            self.assertEqual(len(reader.roots(limit=2)),2)
            first=reader.roots(limit=2)
            self.assertNotEqual(first[0]['name'],reader.roots(after=first[-1]['name'],limit=2)[0]['name'])
            self.assertIn('source_unverified',sealed['manifest']['status'])
            self.assertLessEqual(len(writer._recent),4096)
            self.assertEqual(len(writer._memo),0)
            self.assertLessEqual(len(reader._cache),4096)

    def test_scalar_types_unicode_array_order_and_chunk_boundaries(self):
        value={'中文':[None,True,False,1,1.0,-0.0,'a\nb\u2028c'], 'rows':list(range(4097)), 'empty':{'a':[],'b':{}},'tuple':('same','json-array')}
        with tempfile.TemporaryDirectory() as directory:
            _,_,reader=self.build(Path(directory)/'store',{'values':value})
            actual=reader.get('values')
            self.assertEqual(canonical(actual),canonical(value))
            self.assertEqual(math.copysign(1,actual['中文'][5]),-1)
            for offset in (0,63,64,127,4095,4096,4097):
                page=reader.page('values',path=['rows'],offset=offset,limit=2)
                self.assertEqual(page['items'],value['rows'][offset:offset+2])
                self.assertEqual(page['total'],4097)
                self.assertEqual(page['has_more'],offset+len(page['items'])<4097)

    def test_repeated_nested_evidence_shares_across_unique_candidates_and_graph(self):
        refs=[{'record':i,'raw':'x'*256,'reason':'unexpected-change'} for i in range(32)]
        counter={'reason':'counter-evidence-retained','evidence_refs':refs}
        candidates=[{'candidate_id':f'candidate-{i:06d}','unknown_reasons':['unknown'],
                     'counterevidence':[counter], 'claim':{'claim_id':f'candidate-{i:06d}','status':'hypothetical',
                                                          'evidence_refs':refs,'counterevidence':refs}} for i in range(500)]
        docs={'analysis.json':{'candidates':candidates},'graph.json':{'claims':[row['claim'] for row in candidates]}}
        with tempfile.TemporaryDirectory() as directory:
            writer,sealed,reader=self.build(Path(directory)/'store',docs,max_bytes=4*1024**2)
            logical=sum(len(canonical(value)) for value in docs.values())
            self.assertGreater(logical,8*1024**2)
            self.assertLess(sealed['manifest']['database']['size_bytes'],logical//5)
            for name,value in docs.items():self.assertEqual(reader.canonical_sha256(name,max_bytes=logical),hashlib.sha256(canonical(value)).hexdigest())
            page=reader.page('analysis.json',path=['candidates'],offset=491,limit=100)
            self.assertEqual(page['items'],candidates[491:])
            self.assertEqual(page['total'],500)
            self.assertEqual(page['items'][0]['counterevidence'],[counter])
            # A future >1GiB logical result may be hashed with an explicitly
            # admitted scan budget; physical output remains independently capped.
            with self.assertRaisesRegex(ValueError,'logical_byte_limit'):reader.get('analysis.json',max_bytes=100)

    def test_mutation_between_roots_does_not_reuse_an_old_identity_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'store';writer=SharedArtifactWriter(root,context=CONTEXT,version=FORMAT)
            value={'rows':[{'id':'same','status':'pending','evidence':['old']}]}
            original=copy.deepcopy(value);first=writer.add('history/0',value)
            value['rows'][0].update(status='withdrawn');value['rows'][0]['evidence'].append('new')
            second=writer.add('history/1',value)
            self.assertNotEqual(first['digest'],second['digest'])
            sealed=writer.seal();reader=SharedArtifactReader(root,expected_manifest_sha256=sealed['manifest_sha256']);self.addCleanup(reader.close)
            self.assertEqual(reader.get('history/0'),original)
            self.assertEqual(reader.get('history/1'),value)

    def test_duplicate_roots_unknown_versions_cycles_and_limits_never_seal(self):
        for failure in ('cycle','depth','node','root','node_bytes','array','duplicate','deadline','physical'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)/'store';options={}
                value={'x':'valid'}
                if failure=='depth':options['max_depth']=1;value={'x':{'nested':{'deeper':'value'}}}
                if failure=='node':options['max_nodes']=1
                if failure=='node_bytes':options['max_node_bytes']=10
                if failure=='array':options['max_array_items']=1;value=[1,2]
                if failure=='root':options['max_roots']=1
                if failure=='physical':options['max_bytes']=256*1024;value=['x'*8192+str(i) for i in range(50)]
                writer=SharedArtifactWriter(root,context=CONTEXT,version=FORMAT,**options)
                if failure=='cycle':value=[];value.append(value)
                if failure=='deadline':writer.deadline=time.monotonic()-1
                with self.assertRaises((ValueError,sqlite3.Error)):
                    writer.add('analysis',value)
                    if failure in ('root','duplicate'):writer.add('analysis' if failure=='duplicate' else 'graph',value)
                with self.assertRaises(ValueError):writer.seal()
                self.assertFalse((root/'manifest.json').exists())
                writer.close()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'format'):SharedArtifactWriter(Path(directory)/'unknown',context=CONTEXT,version='unknown')

    def test_page_byte_scan_and_query_budget_fail_without_silent_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            _,_,reader=self.build(Path(directory)/'store',{'values':{'rows':[{'large':'x'*200},{'second':'y'}]}})
            for args in ({'offset':-1},{'limit':0},{'limit':101},{'max_bytes':10}):
                with self.subTest(args=args),self.assertRaises(ValueError):reader.page('values',path=['rows'],**args)
            with self.assertRaisesRegex(ValueError,'logical_byte_limit'):reader.canonical_sha256('values',max_bytes=1)
            with self.assertRaises(ValueError):reader.get('values',path=['rows',99])
            reader.deadline=time.monotonic()-1
            with self.assertRaisesRegex(ValueError,'deadline'):reader.page('values',path=['rows'])

    def test_restore_and_tamper_refusals_including_authenticated_paging_extents(self):
        for mutation in ('copy','missing','extra','bytes','context','extent','payload','schema'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);_,sealed,reader=self.build(root/'original')
                target=root/'restored';shutil.copytree(root/'original',target)
                expected=sealed['manifest_sha256'];context=dict(CONTEXT)
                if mutation=='copy':
                    copied=SharedArtifactReader(target,expected_manifest_sha256=expected,expected_context=context)
                    self.addCleanup(copied.close);self.assertEqual(copied.get('graph.json'),source_documents()['graph.json']);continue
                if mutation=='missing':(target/'shared.sqlite3').unlink()
                if mutation=='extra':(target/'shared.sqlite3-wal').write_bytes(b'unknown')
                if mutation=='bytes':
                    with (target/'shared.sqlite3').open('ab') as stream:stream.write(b'x')
                if mutation=='context':context['attempt_id']=2
                if mutation in ('extent','payload','schema'):
                    connection=sqlite3.connect(target/'shared.sqlite3')
                    if mutation=='extent':connection.execute('UPDATE nodes SET items=items+1 WHERE kind=\'array_leaf\'')
                    if mutation=='payload':connection.execute('UPDATE nodes SET payload=? WHERE kind=\'scalar\'',(b'"invented"',))
                    if mutation=='schema':connection.execute('CREATE TABLE unregistered(secret TEXT)')
                    connection.commit();connection.close()
                    # Even rehashing the outer file cannot make malformed node
                    # references/extents or an unknown SQLite schema acceptable.
                    manifest=json.loads((target/'manifest.json').read_text())
                    manifest['database'].update(sha256=file_hash(target/'shared.sqlite3'),size_bytes=(target/'shared.sqlite3').stat().st_size)
                    raw=canonical(manifest)+b'\n';(target/'manifest.json').write_bytes(raw);expected=hashlib.sha256(raw).hexdigest()
                with self.assertRaises((ValueError,sqlite3.Error)):SharedArtifactReader(target,expected_manifest_sha256=expected,expected_context=context)
