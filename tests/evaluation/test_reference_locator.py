"""Hand-authored CSV byte/record oracles, separate from analysis predictions."""
import base64
import copy
import csv
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
from cpag_core.contracts import validate,SCHEMAS
from cpag_core.evaluation import digest
from cpag_core.evaluation_details import V2_MATCHING_VERSION
import test_round19_bundle as legacy


def inventory(raw,name='review.csv'):
    sha=hashlib.sha256(raw).hexdigest()
    return {'version':ri.VERSION,'files':{sha:{'name':name,'size_bytes':len(raw),
        'content_base64':base64.b64encode(raw).decode()}}},sha


def reference(sha,number,columns=('event_id','time')):
    return {'source_ref':'independent reviewer CSV','sha256':sha,
        'locator':{'version':ri.LOCATOR_VERSION,'file_sha256':sha,'record_number':number,'columns':list(columns)}}


class ReferenceLocatorTests(unittest.TestCase):
    def test_logical_record_is_not_a_physical_line_and_bytes_are_exact(self):
        header=b'event_id,time,note\r\n'
        first=b'one,10,"first\r\nsecond ""quoted"""\r\n'
        last=b'two,12,last'
        raw=header+first+last;stored,sha=inventory(raw)
        result=ri.query_csv_original(stored,{'g':reference(sha,1,('event_id','note'))},'g')
        self.assertEqual(result['status'],ri.LOCATED_STATUS)
        row=result['resolved_record'];fragment=row['fragment']
        self.assertEqual(row['values'],{'event_id':'one','note':'first\r\nsecond "quoted"'})
        self.assertEqual((fragment['byte_offset'],fragment['size_bytes']),(len(header),len(first)))
        self.assertEqual((fragment['physical_line_start'],fragment['physical_line_end']),(2,3))
        self.assertEqual(base64.b64decode(fragment['content_base64']),first)
        self.assertEqual(fragment['sha256'],hashlib.sha256(first).hexdigest())
        self.assertEqual(base64.b64decode(row['header_fragment']['content_base64']),header)
        self.assertEqual(row['logical_data_record_count'],2)
        end=ri.query_csv_original(stored,{'g':reference(sha,2)},'g')['resolved_record']
        self.assertEqual(base64.b64decode(end['fragment']['content_base64']),last)
        self.assertEqual(end['fragment']['byte_offset'],len(header)+len(first))
        self.assertEqual(end['values'],{'event_id':'two','time':'12'})

    def test_utf8_bom_quoted_header_and_blank_quoted_line_keep_offsets(self):
        header=b'\xef\xbb\xbf"event,id",time,note\n'
        record='一,10,"line1\n\nline3"\n'.encode('utf-8')
        stored,sha=inventory(header+record)
        result=ri.query_csv_original(stored,{'g':reference(sha,1,('event,id','note'))},'g')['resolved_record']
        self.assertEqual(result['values'],{'event,id':'一','note':'line1\n\nline3'})
        self.assertEqual(result['fragment']['byte_offset'],len(header))
        self.assertEqual(base64.b64decode(result['fragment']['content_base64']),record)
        self.assertEqual(base64.b64decode(result['header_fragment']['content_base64']),header)

    def test_out_of_range_header_missing_columns_and_contract_errors_refused(self):
        stored,sha=inventory(b'event_id,time\none,10\ntwo,12\n')
        for value in (0,-1,3,999999,1000001,True,1.0,'1'):
            with self.subTest(number=value),self.assertRaises(ValueError):
                ri.query_csv_original(stored,{'g':reference(sha,value)},'g')
        for columns in ((),('missing',),('time','time'),(' ',),('time\n',)):
            with self.subTest(columns=columns),self.assertRaises(ValueError):
                ri.query_csv_original(stored,{'g':reference(sha,1,columns)},'g')
        for mutate in (lambda ref:ref['locator'].update(version='future'),
                       lambda ref:ref['locator'].update(file_sha256='f'*64),
                       lambda ref:ref.update(sha256='f'*64),
                       lambda ref:ref['locator'].update(extra=True),
                       lambda ref:ref.update(record='row:1')):
            ref=reference(sha,1);mutate(ref)
            with self.assertRaises(ValueError):ri.verify_locators(stored,{'g':ref})

    def test_malformed_format_rejected_even_after_requested_record(self):
        cases=[b'',b'event_id,time\n',b'event_id,event_id\na,b\n',b',time\na,10\n',
               b'event_id,time\none,10,extra\n',b'event_id,time\none,10\ntwo,"unterminated',
               b'event_id,time\none,10\n\n',b'event_id,time\n\xff,10\n',
               b'event_id,time\none,\x00\n',b'event_id,time\none,"closed"junk\n',
               b'event_id;time\none;10\n']
        for raw in cases:
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                stored,sha=inventory(raw);ri.verify_locators(stored,{'g':reference(sha,1)})
        stored,sha=inventory(b'event_id,time\none,10\n',name='review.txt')
        with self.assertRaisesRegex(ValueError,'format_required'):ri.verify_locators(stored,{'g':reference(sha,1)})

    def test_same_size_original_tamper_rejected_and_csv_limit_restored(self):
        raw=b'event_id,time\none,10\n';stored,sha=inventory(raw)
        next(iter(stored['files'].values()))['content_base64']=base64.b64encode(raw.replace(b'10',b'99')).decode()
        with self.assertRaisesRegex(ValueError,'hash_mismatch'):ri.verify_locators(stored,{'g':reference(sha,1)})
        limit=csv.field_size_limit();large=b'event_id,time,note\none,10,"'+b'x'*150000+b'"\n'
        stored,sha=inventory(large)
        ri.verify_locators(stored,{'g':reference(sha,1,('note',))})
        self.assertEqual(csv.field_size_limit(),limit)
        stored,sha=inventory(large+b'"broken')
        with self.assertRaises(ValueError):ri.verify_locators(stored,{'g':reference(sha,1)})
        self.assertEqual(csv.field_size_limit(),limit)

    def test_references_for_same_file_are_parsed_once_without_materializing_all_fragments(self):
        raw=b'event_id,time\n'+b'one,10\n'*1000;stored,sha=inventory(raw)
        refs={str(i):reference(sha,i) for i in range(1,1001)}
        with patch.object(ri,'_scan_csv',wraps=ri._scan_csv) as parser:
            self.assertIsNone(ri.verify_locators(stored,refs));self.assertEqual(parser.call_count,1)

    def test_new_schemas_match_independent_validator(self):
        import jsonschema
        from referencing import Registry,Resource
        schemas={p.name:json.loads(p.read_text()) for p in SCHEMAS.glob('*.schema.json')}
        registry=Registry().with_resources((name,Resource.from_contents(schema)) for name,schema in schemas.items())
        ref=reference('a'*64,1);checker=jsonschema.Draft202012Validator(schemas['EvaluationLocatedReference.schema.json'],registry=registry)
        validate('EvaluationLocatedReference',ref);checker.validate(ref)
        for mutate in (lambda r:r['locator'].update(record_number=0),lambda r:r['locator'].update(columns=[]),
                       lambda r:r['locator'].update(columns=['time','time']),lambda r:r['locator'].update(version='unknown')):
            bad=copy.deepcopy(ref);mutate(bad)
            with self.assertRaises(ValueError):validate('EvaluationLocatedReference',bad)
            with self.assertRaises(jsonschema.ValidationError):checker.validate(bad)


class LocatedBundleTests(unittest.TestCase):
    def setup_v3(self,root):
        annotations,_=legacy.BundleTests.setup_case(self,root)
        raw=b'event_id,time\r\nmanual-op,2026-01-01T00:00:10Z\r\nmanual-change,2026-01-01T00:00:12Z'
        stored,sha=inventory(raw);refs={event['id']:reference(sha,i) for i,event in enumerate(annotations['events'],1)}
        split=eb.read(root/'frozen/split.json');reg=eb.read(root/'frozen/registration.json')
        legacy.Clock.current='2026-10-27T00:00:00+00:00'
        with patch.object(eb,'datetime',legacy.Clock):
            eb.freeze(root/'artifact',split,reg,root/'located-frozen',batch='fixture',sample_sha256='b'*64,
                bundle_version=eb.V3_VERSION,matching_version=V2_MATCHING_VERSION,reference_inventory=stored)
        return annotations,refs,raw

    def test_save_verify_query_and_new_directory_restore_return_same_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);annotations,refs,raw=self.setup_v3(root)
            legacy.Clock.current='2026-10-28T00:00:01+00:00'
            with patch.object(eb,'datetime',legacy.Clock):
                result=eb.evaluate_bundle(root/'located-frozen',root/'artifact',annotations,refs,root/'result')
            self.assertEqual(result['record']['metrics']['tp'],2)
            self.assertEqual(result['bundle_binding']['reference_status'],ri.LOCATED_STATUS)
            self.assertEqual(result['bundle_binding']['reference_locator_version'],ri.LOCATOR_VERSION)
            self.assertEqual(eb.verify_bundle(root/'result',root/'artifact'),result)
            record=eb.query_error(root/'result',root/'artifact','manual-change',reference=True)
            expected=b'manual-change,2026-01-01T00:00:12Z'
            self.assertEqual(base64.b64decode(record['resolved_record']['fragment']['content_base64']),expected)
            document={path.name:eb.read(path,limit=eb.V2_DOCUMENT_BYTES) for path in (root/'result').iterdir()}
            self.assertEqual(eb.verify_document(document,root/'artifact',identity='manual-change',reference=True)['evidence'],record)
            shutil.copytree(root/'result',root/'restored');shutil.copytree(root/'artifact',root/'restored-artifact')
            self.assertEqual(eb.query_error(root/'restored',root/'restored-artifact','manual-change',reference=True),record)

    def test_v3_impossible_locator_is_refused_before_publishing_and_on_rehashed_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);annotations,refs,_=self.setup_v3(root)
            bad=copy.deepcopy(refs);bad['manual-op']['locator']['record_number']=999999
            legacy.Clock.current='2026-10-28T00:00:01+00:00'
            with patch.object(eb,'datetime',legacy.Clock):
                with self.assertRaisesRegex(ValueError,'out_of_range'):
                    eb.evaluate_bundle(root/'located-frozen',root/'artifact',annotations,bad,root/'rejected')
                eb.evaluate_bundle(root/'located-frozen',root/'artifact',annotations,refs,root/'valid')
            self.assertFalse((root/'rejected').exists())
            document={path.name:eb.read(path,limit=eb.V2_DOCUMENT_BYTES) for path in (root/'valid').iterdir()}
            document['references.json']=bad
            document['result.json']['bundle_binding']['references_sha256']=digest(bad)
            for name in ('references.json','result.json'):document['manifest.json']['files'][name]=digest(document[name])
            with self.assertRaisesRegex(ValueError,'out_of_range'):eb.verify_document(document,root/'artifact')

    def test_old_bytes_only_contract_never_upgrades_record_status(self):
        stored,sha=inventory(b'event_id,time\none,10\n')
        declaration={'g':{'source_ref':'independent','sha256':sha,'record':'row:999999'}}
        result=ri.query_original(stored,declaration,'g')
        self.assertEqual(result['status'],ri.STATUS)
        self.assertEqual(result['record_locator_status'],'declared_record_not_independently_resolved')
        with self.assertRaises(ValueError):ri.query_csv_original(stored,declaration,'g')


if __name__=='__main__':unittest.main()
