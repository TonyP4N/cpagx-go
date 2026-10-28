import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(Path(__file__).parent)]
from cpag_core import evaluation_bundle as eb,reference_inventory as ri
from cpag_core.evaluation import digest
from cpag_core.evaluation_details import V2_MATCHING_VERSION,V2_DETAILS_VERSION
import test_round19_bundle as legacy


class ReferenceInventoryTests(unittest.TestCase):
    def setup_v2(self,root):
        labels,_=legacy.BundleTests.setup_case(self,root)
        originals=root/'controlled-originals';originals.mkdir()
        data=b'Independent handwritten fixture notes\nrequest at 10s; process transition upper 12s\n'
        (originals/'review.txt').write_bytes(data);sha=hashlib.sha256(data).hexdigest()
        inventory=ri.build_inventory(originals,{'review.txt':sha})
        split=eb.read(root/'frozen/split.json');registration=eb.read(root/'frozen/registration.json')
        legacy.Clock.current='2026-10-27T00:00:00+00:00'
        with patch.object(eb,'datetime',legacy.Clock):
            eb.freeze(root/'artifact',split,registration,root/'v2-frozen',batch='fixture',sample_sha256='b'*64,
                bundle_version=eb.V2_VERSION,matching_version=V2_MATCHING_VERSION,reference_inventory=inventory)
        refs={event['id']:{'source_ref':'independent reviewer notes','record':event['id'],'sha256':sha} for event in labels['events']}
        legacy.Clock.current='2026-10-28T00:00:01+00:00'
        with patch.object(eb,'datetime',legacy.Clock):
            result=eb.evaluate_bundle(root/'v2-frozen',root/'artifact',labels,refs,root/'v2-result')
        return data,inventory,result

    def test_v2_original_bytes_query_and_v1_declaration_read_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data,_,result=self.setup_v2(root)
            self.assertEqual(result['record']['metrics']['tp'],2)
            frozen=eb.read(root/'v2-frozen/freeze.json')
            self.assertEqual((frozen['matching'],frozen['details_version']),(V2_MATCHING_VERSION,V2_DETAILS_VERSION))
            self.assertEqual(eb.verify_bundle(root/'v2-result',root/'artifact'),result)
            evidence=eb.query_error(root/'v2-result',root/'artifact','manual-op',reference=True)
            self.assertEqual(evidence['status'],ri.STATUS)
            self.assertEqual(base64.b64decode(evidence['original']['content_base64']),data)
            self.assertIn('not_independently_resolved',evidence['record_locator_status'])
            document={path.name:eb.read(path,limit=eb.V2_DOCUMENT_BYTES) for path in (root/'v2-result').iterdir()}
            self.assertEqual(eb.verify_document(document,root/'artifact',identity='manual-op',reference=True)['evidence'],evidence)
            # Existing old-format tests above already created a v1 frozen set;
            # its status cannot acquire an originals-verified claim.
            self.assertEqual(eb.read(root/'frozen/freeze.json')['version'],eb.VERSION)

    def test_restore_to_new_directories_needs_no_original_external_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data,_,_=self.setup_v2(root)
            shutil.copytree(root/'v2-result',root/'restored-sidecar')
            shutil.copytree(root/'artifact',root/'restored-artifact')
            shutil.rmtree(root/'controlled-originals');shutil.rmtree(root/'artifact');shutil.rmtree(root/'v2-result')
            evidence=eb.query_error(root/'restored-sidecar',root/'restored-artifact','manual-change',reference=True)
            self.assertEqual(base64.b64decode(evidence['original']['content_base64']),data)

    def test_missing_tampered_or_rehashed_inventory_is_never_trusted(self):
        for mutation in ('missing_file','missing_entry','tampered_bytes','forged_status'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.setup_v2(root);sidecar=root/'v2-result'
                if mutation=='missing_file':(sidecar/'reference_inventory.json').unlink()
                else:
                    manifest=eb.read(sidecar/'manifest.json');inventory=eb.read(sidecar/'reference_inventory.json')
                    if mutation=='missing_entry':inventory['files']={}
                    if mutation=='tampered_bytes':
                        item=next(iter(inventory['files'].values()));item['content_base64']='A'+item['content_base64'][1:]
                    changed='reference_inventory.json';value=inventory
                    if mutation=='forged_status':
                        changed='result.json';value=eb.read(sidecar/changed)
                        value['bundle_binding']['reference_status']='external_annotation_independence_proven'
                    (sidecar/changed).write_text(json.dumps(value));manifest['files'][changed]=digest(value)
                    (sidecar/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises((ValueError,OSError)):eb.verify_bundle(sidecar,root/'artifact')

    def test_controlled_ingest_hash_path_symlink_hardlink_and_missing_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'good').write_bytes(b'original');sha=hashlib.sha256(b'original').hexdigest()
            (root/'link').symlink_to(root/'good');(root/'directory').mkdir()
            import os
            os.link(root/'good',root/'hardlink')
            cases=[{'../outside':sha},{str(root/'good'):sha},{'missing':sha},{'link':sha},{'directory':sha},{'hardlink':sha}]
            for files in cases:
                with self.subTest(files=files),self.assertRaises(ValueError):ri.build_inventory(root,files)
            (root/'hardlink').unlink()
            with self.assertRaisesRegex(ValueError,'hash_mismatch'):ri.build_inventory(root,{'good':'f'*64})
            good=ri.build_inventory(root,{'good':sha});ri.verify_inventory(good)
            (root/'good').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'hash_mismatch'):ri.build_inventory(root,{'good':sha})

    def test_raw_file_total_encoded_and_document_budgets_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'one').write_bytes(b'abcd');(root/'two').write_bytes(b'efgh')
            files={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('one','two')}
            with patch.object(ri,'FILE_BYTES',3),self.assertRaises(ValueError):ri.build_inventory(root,files)
            with patch.object(ri,'TOTAL_BYTES',7),self.assertRaisesRegex(ValueError,'total_bytes'):ri.build_inventory(root,files)
            inventory=ri.build_inventory(root,files)
            next(iter(inventory['files'].values()))['size_bytes']=ri.FILE_BYTES+1
            with self.assertRaisesRegex(ValueError,'encoded_size'):ri.verify_inventory(inventory)
            document={'manifest.json':{'version':eb.VERSION},'padding':'x'*100}
            with patch.object(eb,'LEGACY_DOCUMENT_BYTES',100),self.assertRaisesRegex(ValueError,'document_limit'):
                eb.enforce_document_limit(document)
            document['manifest.json']['version']=eb.V2_VERSION
            with patch.object(eb,'LEGACY_DOCUMENT_BYTES',100):self.assertEqual(eb.enforce_document_limit(document),eb.V2_VERSION)

    def test_unknown_or_crossed_matching_pair_and_inventory_mutation_after_freeze_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.setup_v2(root)
            frozen=eb.read(root/'v2-frozen/freeze.json');frozen['details_version']='1.0.0'
            (root/'v2-frozen/freeze.json').write_text(json.dumps(frozen))
            with self.assertRaises(ValueError):eb.frozen_inputs(root/'v2-frozen',root/'artifact')
            with self.assertRaises(ValueError):eb.matching_pair('unknown')
            with self.assertRaisesRegex(ValueError,'explicit_bundle_v2'):
                eb.freeze(root/'artifact',{}, {},root/'invalid',batch='fixture',sample_sha256='b'*64,matching_version=V2_MATCHING_VERSION)


if __name__=='__main__':unittest.main()
