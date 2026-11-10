import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from cpag_core.dual_source import analyze,run_dual,query
from cpag_core.contracts import validate
from cpag_core.pipeline import canonical,file_hash

# This file was committed before implementation; never derive gold from predictions.
GOLD=json.loads((ROOT/'fixtures/dual-source/expectations.json').read_text())['cases']

class DualSourceTests(unittest.TestCase):
    def test_preregistered_scenarios_and_both_source_queries(self):
        for name,gold in GOLD.items():
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);paths=make_case(base/'inputs',name)
                result=run_dual(*paths,base/'run')
                for key in ('operations','changes','candidates'):self.assertEqual(len(result[key]),gold[key])
                if 'orphan_changes' in gold:self.assertEqual(len(result['orphan_change_ids']),gold['orphan_changes'])
                for op in result['operations']:
                    self.assertEqual(op['response']['state'],gold['response'])
                    self.assertEqual(op['assessment'],gold['assessment'])
                    if 'reason' in gold:self.assertIn(gold['reason'],op['unknown_reasons'])
                    view=query(base/'run',operation_id=op['operation_id'])
                    self.assertTrue(view['verified_original_evidence'])
                    if result['candidates']:
                        self.assertTrue(any(r['source_ref']['record_number'] for r in view['verified_original_evidence']))
                        self.assertTrue(view['verified_network_fields'])
                for c in result['candidates']:
                    self.assertEqual(c['state'],gold['candidate_state'])
                    self.assertEqual(c['claim']['status'],'hypothetical')
                    validate('Claim',c['claim'])
                for c in result['changes']:validate('DerivedEvent',c)
                if name=='error':self.assertIn('error_response',[c['reason'] for c in result['candidates'][0]['counterevidence']])
                if name=='no_change':self.assertIn('no_expected_change_in_observed_window',[c['reason'] for c in result['operations'][0]['counterevidence']])
                if name=='orphan_change':self.assertEqual(len(query(base/'run',change_id='first')['verified_original_evidence']),2)

    def test_repeatability_config_binding_and_unknown_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs')
            a=run_dual(*paths,base/'a');b=run_dual(*paths,base/'b')
            self.assertEqual(canonical(a),canonical(b))
            self.assertEqual((base/'a/analysis.json').read_bytes(),(base/'b/analysis.json').read_bytes())
            with self.assertRaisesRegex(ValueError,'already_exists'):run_dual(*paths,base/'a')
            with self.assertRaisesRegex(ValueError,'unknown_operation'):query(base/'a',operation_id='absent')
            config=json.loads(paths[2].read_text());config['config_version']='synthetic-map-v2'
            self.assertNotEqual(a['config_fingerprint'],analyze(paths[0],paths[1],config)['config_fingerprint'])

    def test_tamper_missing_and_rehashed_false_analysis(self):
        for name in ('sources/network.pcap','sources/process.csv','sources/profile.json','analysis.json'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);paths=make_case(base/'inputs');run_dual(*paths,base/'run')
                target=base/'run'/name;raw=target.read_bytes();target.write_bytes(raw+b' ')
                with self.assertRaises(ValueError):query(base/'run',operation_id='first')
                target.unlink()
                with self.assertRaises(OSError):query(base/'run',operation_id='first')
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs');run_dual(*paths,base/'run')
            path=base/'run/analysis.json';result=json.loads(path.read_text());result['operations'][0]['response']['state']='error'
            path.write_bytes(canonical(result));manifest=json.loads((base/'run/manifest.json').read_text())
            manifest['files']['analysis.json']=file_hash(path);(base/'run/manifest.json').write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError,'does_not_match'):query(base/'run',operation_id='first')

    def test_labels_profile_errors_and_empty_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            for key,val in [('synthetic',False),('gold',{}),('window_seconds',float('nan'))]:
                bad=copy.deepcopy(config);bad[key]=val
                with self.assertRaises(ValueError):analyze(n,p,bad)
            p.write_text('time,pump,attack_label\n2026-01-01T00:00:10Z,0,1\n')
            with self.assertRaisesRegex(ValueError,'label'):analyze(n,p,config)
            p.write_text('time,pump\n')
            with self.assertRaisesRegex(ValueError,'empty_process'):analyze(n,p,config)

    def test_unknown_mapping_and_duplicate_time_not_forced(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            p.write_text(p.read_text()+'2026-01-01T00:00:12Z,0\n')
            result=analyze(n,p,config)
            self.assertEqual(result['changes'],[]);self.assertEqual(result['candidates'],[])
            self.assertIn('duplicate_process_time',result['operations'][0]['unknown_reasons'])


class AdditionalBoundaryTests(unittest.TestCase):
    def test_malformed_record_not_bridged_and_size_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            original=p.read_text();lines=original.splitlines();lines.insert(3,'bad,record,width')
            p.write_text('\n'.join(lines)+'\n')
            with self.assertRaisesRegex(ValueError,'malformed_csv'):analyze(n,p,config)
            p.write_text('time,pump\n'+'2026-01-01T00:00:10Z,0\n'*1001)
            with self.assertRaisesRegex(ValueError,'record_limit'):analyze(n,p,config)

    def test_one_operation_multiple_changes_retains_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            p.write_text('time,pump\n2026-01-01T00:00:09Z,0\n2026-01-01T00:00:10.5Z,0\n'
                         '2026-01-01T00:00:12Z,1\n2026-01-01T00:00:13Z,0\n2026-01-01T00:00:14Z,1\n2026-01-01T00:00:16Z,1\n')
            result=analyze(n,p,config)
            self.assertEqual(len(result['candidates']),2)
            self.assertTrue(all(c['state']=='ambiguous' for c in result['candidates']))
            self.assertTrue(all(c['counterevidence'] for c in result['candidates']))

    def test_process_mapping_conflict_is_not_resolved_by_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            config['process']['columns']['other']=copy.deepcopy(config['process']['columns']['pump'])
            p.write_text('time,pump,other\n2026-01-01T00:00:09Z,0,1\n2026-01-01T00:00:12Z,1,0\n')
            result=analyze(n,p,config)
            self.assertEqual(result['candidates'],[])
            self.assertIn('process_mapping_conflict',result['operations'][0]['unknown_reasons'])

    def test_schema_independently_and_no_annotation_reads(self):
        import jsonschema
        schema=json.loads((ROOT/'schemas/DualSourceProfile.schema.json').read_text())
        config=json.loads((ROOT/'profiles/dual-source-synthetic.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(config)
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs')
            a=analyze(paths[0],paths[1],config)
            (base/'inputs/attack_annotations.json').write_text('{"attack":true}')
            b=analyze(paths[0],paths[1],config)
            self.assertEqual(canonical(a),canonical(b))

class TimeAndQueryTests(unittest.TestCase):
    def test_pcapng_epoch_clock_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs',capture_format='pcapng')
            result=run_dual(*paths,base/'run')
            self.assertEqual(len(result['candidates']),1)
            self.assertEqual(result['candidates'][0]['state'],'supported_candidate')
            self.assertEqual(result['operations'][0]['time']['interval'],[1767225610,1767225610])
            self.assertTrue(query(base/'run',operation_id='first')['verified_network_fields'])

    def test_disjoint_and_clock_unknown_query_explains_basis(self):
        for name in ('disjoint','clock_unknown','offset'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);paths=make_case(base/'inputs',name);run_dual(*paths,base/'run')
                view=query(base/'run',operation_id='first')
                self.assertIn('process',view['source_ranges'])
                self.assertEqual(view['selection']['operation']['mapping']['asset_id'],'synthetic-pump')
                if name=='offset':self.assertEqual(view['time_configuration']['process']['offset_seconds'],-100)

    def test_ambiguity_query_includes_competing_operation_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs','ambiguous');run_dual(*paths,base/'run')
            view=query(base/'run',operation_id='first')
            self.assertEqual(len(view['selection']['candidates'][0]['alternative_operation_ids']),1)
            frames={r['source_ref']['frame_number'] for r in view['verified_original_evidence'] if r['source_ref']['frame_number'] is not None}
            self.assertIn(3,frames)  # independent fixture: second request is frame 3

    def test_change_after_window_boundary_is_not_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c=make_case(base/'inputs');config=json.loads(c.read_text())
            p.write_text('time,pump\n2026-01-01T00:00:09Z,0\n2026-01-01T00:00:12Z,0\n2026-01-01T00:00:15Z,0\n2026-01-01T00:00:16Z,1\n')
            result=analyze(n,p,config)
            self.assertEqual(len(result['changes']),1)
            self.assertEqual(result['candidates'],[])

if __name__=='__main__':unittest.main()
