"""Independent compact-DAG core checks, not S/M/L performance acceptance."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from cpag_core.pipeline import canonical,file_hash
from cpag_core import shared_artifact_store_compact as compact
from cpag_core import shared_artifact_store_compressed as previous

CONTEXT={'run_id':'compact-independent','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}


class CompactDAGTests(unittest.TestCase):
    def build(self,path,docs,**kwargs):
        writer=compact.SharedArtifactWriter(path,context=CONTEXT,version=compact.FORMAT,**kwargs)
        for name,value in docs.items():writer.add(name,value)
        sealed=writer.seal()
        reader=compact.SharedArtifactReader(path,expected_manifest_sha256=sealed['manifest_sha256'],expected_context=CONTEXT)
        self.addCleanup(reader.close)
        return writer,sealed,reader

    def test_full_values_stream_and_hash_preserve_unknowns_claims_evidence_and_order(self):
        ref={'file_sha256':'c'*64,'frame_number':2,'record_number':None,'raw_time':'2026-01-01T00:00:00Z'}
        expected={'network':[{'id':'net-1','response':'success','refs':[ref]}],
            'candidates':[{'id':f'candidate-{i}','state':'unknown','claim':{'status':'hypothetical','counterevidence':[ref]},'alternatives':[4,2,4,1]} for i in range(100)],
            'values':[None,True,False,1,1.0,-0.0,'中文😀',[],{}], 'rows':list(range(4097))}
        with tempfile.TemporaryDirectory() as directory:
            _,sealed,reader=self.build(Path(directory)/'store',{'analysis.json':expected})
            self.assertEqual(canonical(reader.get('analysis.json')),canonical(expected))
            self.assertEqual(reader.canonical_sha256('analysis.json',max_bytes=len(canonical(expected))),hashlib.sha256(canonical(expected)).hexdigest())
            self.assertEqual(reader.descriptor('analysis.json')['digest'],compact.LogicalHasher().digest(expected)['digest'])
            for offset in (0,15,16,63,64,4095,4096,4097):
                self.assertEqual(reader.page('analysis.json',path=['rows'],offset=offset,limit=2)['items'],expected['rows'][offset:offset+2])
            self.assertEqual(sealed['manifest']['version'],compact.FORMAT)
            self.assertLessEqual(reader._cache_bytes,previous.CACHE_BYTES)

    def test_physical_ids_are_not_logical_authority_and_are_smaller_than_blob_refs(self):
        refs=[{'record':i,'evidence':'x'*200} for i in range(100)]
        docs={'rows':[{'id':f'c-{i:04d}','refs':refs[:i%100]+refs[i%100+1:],'claim':{'unknown':['clock'],'refs':refs}} for i in range(500)]}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            _,sealed,reader=self.build(root/'compact',docs)
            writer=previous.SharedArtifactWriter(root/'previous',context=CONTEXT,version=previous.CONTENT_FORMAT)
            for name,value in docs.items():writer.add(name,value)
            prior=writer.seal()
            self.assertLess(sealed['manifest']['database']['size_bytes'],prior['manifest']['database']['size_bytes'])
            self.assertEqual(reader.canonical_sha256('rows',max_bytes=len(canonical(docs['rows']))),hashlib.sha256(canonical(docs['rows'])).hexdigest())

    def test_intern_compose_alias_sequence_and_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=compact.SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=compact.FORMAT)
            value={'state':'pending','evidence':['all']}
            first=writer.intern(value)
            a=writer.compose('snapshot/0',{'number':0},{'analysis':first['digest']})
            value['state']='withdrawn';value['evidence'].append('new')
            second=writer.intern(value)
            b=writer.compose('snapshot/1',{'number':1},{'analysis':second['digest']})
            writer.alias('latest','snapshot/1')
            sequence=writer.sequence('snapshots',[a['digest'],b['digest'],a['digest']])
            sealed=writer.seal();reader=compact.SharedArtifactReader(writer.root,expected_manifest_sha256=sealed['manifest_sha256']);self.addCleanup(reader.close)
            self.assertEqual(reader.get('snapshots'),[{'number':0,'analysis':{'state':'pending','evidence':['all']}},{'number':1,'analysis':value},{'number':0,'analysis':{'state':'pending','evidence':['all']}}])
            self.assertEqual(reader.get('latest'),reader.get('snapshot/1'))
            self.assertNotEqual(first['digest'],second['digest'])
            self.assertEqual(sequence['items'],3)

    def test_copied_restore_and_tampered_id_payload_extent_and_unknown_schema_refused(self):
        for mutation in ('copy','id','payload','extent','schema','extra'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);_,sealed,reader=self.build(root/'store',{'rows':{'items':[1,2,3]}})
                reader.close();shutil.copytree(root/'store',root/'copy')
                copied=root/'copy';manifest=sealed['manifest']
                if mutation=='copy':
                    restored=compact.SharedArtifactReader(copied,expected_manifest_sha256=sealed['manifest_sha256']);self.addCleanup(restored.close)
                    self.assertEqual(restored.get('rows'),{'items':[1,2,3]});continue
                if mutation=='extra':(copied/'shared.sqlite3-wal').write_bytes(b'bad')
                else:
                    connection=sqlite3.connect(copied/'shared.sqlite3')
                    if mutation=='id':connection.execute('UPDATE nodes SET id=id+10000 WHERE kind=\'scalar\'')
                    if mutation=='payload':connection.execute('UPDATE nodes SET payload=? WHERE kind=\'array_leaf\'',(b'R\x03\x01\x01\x01',))
                    if mutation=='extent':connection.execute('UPDATE nodes SET logical_bytes=logical_bytes+1 WHERE kind=\'array_leaf\'')
                    if mutation=='schema':connection.execute('CREATE TABLE surprise(value TEXT)')
                    connection.commit();connection.close()
                    manifest['database'].update(sha256=file_hash(copied/'shared.sqlite3'),size_bytes=(copied/'shared.sqlite3').stat().st_size)
                    raw=canonical(manifest)+b'\n';(copied/'manifest.json').write_bytes(raw)
                expected=file_hash(copied/'manifest.json')
                with self.assertRaises(ValueError):compact.SharedArtifactReader(copied,expected_manifest_sha256=expected)

    def test_varints_and_limits_no_seal(self):
        for number in (0,1,127,128,16384,2**63-1):
            raw=compact._varint(number);self.assertEqual(compact._integer(raw,0),(number,len(raw)))
        for raw in (b'',b'\x80',b'\x80\x00',b'\xff'*10):
            with self.assertRaises(ValueError):compact._integer(raw,0)
        for kwargs,value in (({'max_nodes':1},{'two':[1,2]}),({'max_logical_root_bytes':5},'too-long'),({'max_node_bytes':2},'too-long')):
            with tempfile.TemporaryDirectory() as directory:
                writer=compact.SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=compact.FORMAT,**kwargs)
                with self.assertRaises(ValueError):writer.add('bad',value)
                self.assertFalse((writer.root/'manifest.json').exists());writer.close()


if __name__=='__main__':unittest.main()
