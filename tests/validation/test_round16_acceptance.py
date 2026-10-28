"""Current format6 acceptance gate; historical reads belong to backup tests."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/validation'),str(ROOT/'services/analysis/src')]
import round16_acceptance as r16


class CatalogFormat6AcceptanceTests(unittest.TestCase):
    def fixture(self,ready=False):
        catalog={name:[] for name in r16.bundle.CATALOG_TABLES}
        audit={'valid':True,'ready_bytes':0,'documents':[]}
        copied=copy.deepcopy(audit)
        if ready:
            catalog['v3_evaluation_preparations']=[{'id':'handwritten-preparation','state':'ready','document_size':31,'document_sha256':'a'*64}]
            document={'id':'handwritten-preparation','size_bytes':31,'document_sha256':'a'*64,'source_projection_equal':True,'semantic_verification_executed':True}
            audit.update(ready_bytes=31,documents=[document]);copied=copy.deepcopy(audit)
            copied['documents'][0]['semantic_verification_executed']=False
        return {'format_version':6,'catalog':catalog,'catalog_audit':{'valid':True},'copied_catalog_audit':{'valid':True},
                'preparation_audit':audit,'copied_preparation_audit':copied}

    def test_current_empty_and_ready_preparation_catalogs_both_accept(self):
        for ready in (False,True):
            with self.subTest(ready=ready):r16.require_format6_catalog_snapshot(self.fixture(ready))

    def test_old_or_unknown_versions_never_widen_current_acceptance(self):
        for version in (4,5,7,None,True,'6'):
            value=self.fixture();value['format_version']=version
            with self.subTest(version=version),self.assertRaisesRegex(RuntimeError,'requires backup format6'):
                r16.require_format6_catalog_snapshot(value)

    def test_format6_requires_all_catalog_and_preparation_audits(self):
        for key in ('catalog_audit','copied_catalog_audit','preparation_audit','copied_preparation_audit'):
            for missing in (False,True):
                value=self.fixture()
                if missing:value.pop(key)
                else:value[key]['valid']=False
                with self.subTest(key=key,missing=missing),self.assertRaises(RuntimeError):r16.require_format6_catalog_snapshot(value)
        for table in ('v3_evaluation_preparations','v3_evaluation_preparation_attempts'):
            value=self.fixture();value['catalog'].pop(table)
            with self.assertRaises(RuntimeError):r16.require_format6_catalog_snapshot(value)

    def test_partial_rehashed_or_nonterminal_preparation_audits_refused(self):
        changes=[lambda value:value['preparation_audit']['documents'].clear(),
                 lambda value:value['preparation_audit'].update(ready_bytes=30),
                 lambda value:value['preparation_audit']['documents'][0].update(document_sha256='b'*64),
                 lambda value:value['preparation_audit']['documents'][0].update(source_projection_equal=False),
                 lambda value:value['preparation_audit']['documents'][0].update(semantic_verification_executed=False),
                 lambda value:value['copied_preparation_audit']['documents'][0].update(semantic_verification_executed=True),
                 lambda value:value['catalog']['v3_evaluation_preparations'][0].update(state='preparing')]
        for change in changes:
            value=self.fixture(True);change(value)
            with self.subTest(change=change),self.assertRaises(RuntimeError):r16.require_format6_catalog_snapshot(value)

    def test_restored_document_audit_must_match_original_ready_bytes(self):
        value=self.fixture(True);audit=copy.deepcopy(value['preparation_audit'])
        r16.require_preparation_audit(audit,value['catalog'],semantic_executed=True)
        audit['documents'][0]['document_sha256']='f'*64
        with self.assertRaises(RuntimeError):r16.require_preparation_audit(audit,value['catalog'],semantic_executed=True)
        with self.assertRaises(RuntimeError):r16.require_preparation_audit(None,value['catalog'],semantic_executed=True)


if __name__=='__main__':unittest.main()
