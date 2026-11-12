"""Independent semantic/corruption/budget tests, not capacity acceptance."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
import zlib

from cpag_core.pipeline import canonical,file_hash
from cpag_core import shared_artifact_store as old
from cpag_core.shared_artifact_store_compressed import (
    SharedArtifactWriter,SharedArtifactReader,BINARY_FORMAT,CONTENT_FORMAT,
    CACHE_BYTES,_load,_pack,_unpack)

CONTEXT={'run_id':'independent-compressed','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}


class SharedArtifactCompressedTests(unittest.TestCase):
    def build(self,root,docs,version=CONTENT_FORMAT,**kwargs):
        writer=SharedArtifactWriter(root,context=CONTEXT,version=version,**kwargs)
        for name,value in docs.items():writer.add(name,value)
        sealed=writer.seal()
        reader=SharedArtifactReader(root,expected_manifest_sha256=sealed['manifest_sha256'],expected_context=CONTEXT)
        self.addCleanup(reader.close)
        return writer,sealed,reader

    def test_all_fields_order_scalar_types_and_complete_stream_hash_both_versions(self):
        evidence={'record':3,'raw':'原件\n内容','sha256':'c'*64,'reason':'counterevidence'}
        expected={'observations':[{'id':'n1','response':'success','evidence':[evidence]}],
                  'candidates':[{'id':'c1','claim':{'state':'hypothetical','counterevidence':[evidence]},
                                 'unknown':['clock','identity'],'alternatives':['c3','c2','c4']}],
                  'scalars':[None,True,False,1,1.0,-0.0,'中文😀'],
                  'rows':list(range(4097)), 'empty':[[],{}]}
        for version in (BINARY_FORMAT,CONTENT_FORMAT):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as directory:
                writer,sealed,reader=self.build(Path(directory)/'store',{'analysis':expected,'graph':{'claim':expected['candidates'][0]['claim']}},version)
                self.assertEqual(canonical(reader.get('analysis')),canonical(expected))
                raw=canonical(expected)
                self.assertEqual(reader.canonical_sha256('analysis',max_bytes=len(raw)),hashlib.sha256(raw).hexdigest())
                for offset in (0,15,16,63,64,4095,4096,4097):
                    page=reader.page('analysis',path=['rows'],offset=offset,limit=2)
                    self.assertEqual(page['version'],version)
                    self.assertEqual(page['items'],expected['rows'][offset:offset+2])
                    self.assertEqual(page['total'],4097)
                self.assertEqual(sealed['manifest']['codec'],'blob32-zlib-or-raw-1')
                row=reader.connection.execute('SELECT typeof(digest),length(digest) FROM nodes LIMIT 1').fetchone()
                self.assertEqual(row,('blob',32))
                self.assertLessEqual(reader._cache_bytes,CACHE_BYTES)
                self.assertEqual(writer._memo,{})

    def test_deleting_one_alternative_preserves_every_value_and_reuses_later_chunks(self):
        values=[f'candidate-{i:06d}' for i in range(1024)]
        docs={'full':values}
        for index in range(16):docs[f'omitted/{index:02d}']=values[:index]+values[index+1:]
        sizes={}
        for version in (BINARY_FORMAT,CONTENT_FORMAT):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as directory:
                writer,sealed,reader=self.build(Path(directory)/'store',docs,version)
                sizes[version]=writer.node_count
                for name,expected in docs.items():
                    self.assertEqual(reader.get(name),expected)
                    self.assertEqual(reader.canonical_sha256(name,max_bytes=100000),hashlib.sha256(canonical(expected)).hexdigest())
        self.assertLess(sizes[CONTENT_FORMAT],sizes[BINARY_FORMAT])

    def test_mutation_between_roots_and_restored_physical_files(self):
        for version in (BINARY_FORMAT,CONTENT_FORMAT):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                value={'states':['pending'],'counterevidence':['kept']}
                writer=SharedArtifactWriter(root/'store',context=CONTEXT,version=version)
                writer.add('history/0',value)
                value['states'].append('withdrawn')
                writer.add('history/1',value)
                sealed=writer.seal()
                shutil.copytree(root/'store',root/'restored')
                reader=SharedArtifactReader(root/'restored',expected_manifest_sha256=sealed['manifest_sha256'],expected_context=CONTEXT)
                self.addCleanup(reader.close)
                self.assertEqual(reader.get('history/0'),{'states':['pending'],'counterevidence':['kept']})
                self.assertEqual(reader.get('history/1'),value)

    def test_intern_and_composition_keep_full_value_without_double_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT)
            state={'candidates':[{'id':'c1','evidence':['first','second'],'unknown':['clock']}],'order':[2,1,2]}
            child=writer.intern(state)
            self.assertEqual(writer.root_count,0)
            composed=writer.compose('snapshot',{'number':0,'identity_strategy':'merkle-json-dag-1'},{'analysis':child['digest']})
            plain=writer.add('plain',{'number':0,'identity_strategy':'merkle-json-dag-1','analysis':state})
            self.assertEqual(composed['digest'],plain['digest'])
            sealed=writer.seal()
            reader=SharedArtifactReader(writer.root,expected_manifest_sha256=sealed['manifest_sha256'])
            self.addCleanup(reader.close)
            self.assertEqual(reader.get('snapshot')['analysis'],state)
            self.assertEqual(reader.get('plain'),reader.get('snapshot'))
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT)
            with self.assertRaisesRegex(ValueError,'reference_missing'):writer.compose('missing',{}, {'analysis':'f'*64})
            self.assertFalse((writer.root/'manifest.json').exists())
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT)
            with self.assertRaisesRegex(ValueError,'dict_item_limit'):writer.add('wide',{str(i):0 for i in range(4097)})
            self.assertFalse((writer.root/'manifest.json').exists())
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT,max_logical_root_bytes=10)
            with self.assertRaisesRegex(ValueError,'extent_invalid'):writer.add('large','long-string-over-limit')
            self.assertFalse((writer.root/'manifest.json').exists())

    def test_explicit_alias_keeps_complete_root_and_counts_and_rejects_bad_names(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT)
            original=writer.add('analysis',{'claims':[{'id':'claim-1','evidence':['all-original']}]})
            nodes=writer.node_count
            alias=writer.alias('dual/analysis','analysis')
            self.assertEqual(alias['digest'],original['digest'])
            self.assertEqual(writer.node_count,nodes)
            self.assertEqual(writer.root_count,2)
            sealed=writer.seal()
            reader=SharedArtifactReader(writer.root,expected_manifest_sha256=sealed['manifest_sha256'])
            self.addCleanup(reader.close)
            self.assertEqual(reader.get('analysis'),reader.get('dual/analysis'))
            self.assertEqual(reader.canonical_sha256('analysis',max_bytes=1000),reader.canonical_sha256('dual/analysis',max_bytes=1000))
        for name,target in (('second','missing'),('../bad','analysis'),('analysis','analysis')):
            with self.subTest(name=name,target=target),tempfile.TemporaryDirectory() as directory:
                writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=CONTENT_FORMAT)
                writer.add('analysis',[1,2])
                with self.assertRaises(ValueError):writer.alias(name,target)
                writer.close()

    def test_compressed_bombs_truncation_trailing_bytes_unknown_codec_rejected(self):
        compressed=b'Z'+zlib.compress(b'x'*1000000,1)
        for payload in (compressed,compressed[:-1],compressed+b'extra',b'Qunknown',b''):
            with self.subTest(payload=payload[:10]),self.assertRaises(ValueError):_load(payload,1024)
        self.assertEqual(_load(b'Rsmall',1024),b'small')
        self.assertEqual(_load(b'Z'+zlib.compress(b'small'),1024),b'small')
        for kind,raw in (('array_leaf',b'\xff\xff\xff\xff'),('dict',b'\xff\xff\xff\xff'),('dict',b'\0\0\0\0trailing')):
            with self.assertRaises(ValueError):_unpack(kind,raw)

    def test_byte_bounded_decoded_cache_with_high_compression_nodes(self):
        # Logical data exceeds cache cap while compressed physical data is small.
        docs={'large':[f'{i:04d}'+('x'*400000) for i in range(48)]}
        with tempfile.TemporaryDirectory() as directory:
            _,sealed,reader=self.build(Path(directory)/'store',docs,max_bytes=1024**2)
            self.assertGreater(reader.descriptor('large')['logical_bytes'],CACHE_BYTES)
            self.assertLess(sealed['manifest']['database']['size_bytes'],1024**2)
            for index in range(48):self.assertEqual(reader.get('large',path=[index]),docs['large'][index])
            self.assertLessEqual(reader._cache_bytes,CACHE_BYTES)
            self.assertLess(len(reader._cache),48)

    def test_rehashed_outer_file_cannot_hide_payload_extent_or_reference_tampering(self):
        for mutation in ('payload','extent','missing','wrong_kind','root','compressed_bomb'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)/'store'
                _,sealed,reader=self.build(root,{'values':{'rows':['one','two','three']}})
                reader.close()
                connection=sqlite3.connect(root/'shared.sqlite3')
                if mutation=='payload':connection.execute('UPDATE nodes SET payload=? WHERE kind=\'scalar\'',(b'R"changed"',))
                if mutation=='extent':connection.execute('UPDATE nodes SET items=items+1 WHERE kind=\'array_leaf\'')
                if mutation=='missing':connection.execute('DELETE FROM nodes WHERE kind=\'scalar\'')
                if mutation=='wrong_kind':connection.execute('UPDATE nodes SET kind=\'invented\' WHERE kind=\'scalar\'')
                if mutation=='root':connection.execute('UPDATE roots SET digest=?',(b'x'*32,))
                if mutation=='compressed_bomb':connection.execute('UPDATE nodes SET payload=? WHERE kind=\'scalar\'',(b'Z'+zlib.compress(b'x'*(9*1024**2),1),))
                connection.commit();connection.close()
                manifest=sealed['manifest']
                manifest['database'].update(sha256=file_hash(root/'shared.sqlite3'),size_bytes=(root/'shared.sqlite3').stat().st_size)
                raw=canonical(manifest)+b'\n';(root/'manifest.json').write_bytes(raw)
                with self.assertRaises(ValueError):SharedArtifactReader(root,expected_manifest_sha256=hashlib.sha256(raw).hexdigest())

    def test_limits_rollback_and_explicit_legacy_dispatch(self):
        for version in (BINARY_FORMAT,CONTENT_FORMAT):
            for limit in ('nodes','bytes','physical'):
                with self.subTest(version=version,limit=limit),tempfile.TemporaryDirectory() as directory:
                    options={'max_nodes':1} if limit=='nodes' else {'max_node_bytes':8} if limit=='bytes' else {'max_bytes':256*1024}
                    writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=version,**options)
                    # Distinct pseudo-random strings defeat compression for the
                    # physical-bound test; raising the cap is never a fallback.
                    value=[hashlib.sha256(str(i).encode()).hexdigest()*100 for i in range(2000)] if limit=='physical' else {'rows':[1,2]}
                    with self.assertRaises(ValueError):writer.add('root',value)
                    self.assertFalse((writer.root/'manifest.json').exists())
                    with self.assertRaises(ValueError):writer.seal()
                    writer.close()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaises(ValueError):SharedArtifactWriter(root/'wrong',context=CONTEXT,version=old.FORMAT)
            _,sealed,_=self.build(root/'new',{'x':[1]})
            with self.assertRaises(ValueError):old.SharedArtifactReader(root/'new',expected_manifest_sha256=sealed['manifest_sha256'])
            writer=old.SharedArtifactWriter(root/'old',context=CONTEXT,version=old.FORMAT)
            writer.add('x',[1]);sealed=writer.seal()
            with self.assertRaises(ValueError):SharedArtifactReader(root/'old',expected_manifest_sha256=sealed['manifest_sha256'])


if __name__=='__main__':unittest.main()
