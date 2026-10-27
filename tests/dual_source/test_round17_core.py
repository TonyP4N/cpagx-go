"""Independent expected values fixed in round17-core-scenarios.md before changes."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from round17_profile import profile, START, END
from cpag_core.dual_source import analyze, corrected, query, run_dual
from cpag_core.dual_source_rules import clock_time, validate_profile
from cpag_core.dual_source_export import export_task, verify_task, query_task, artifact_files
from cpag_core.pipeline import canonical, fingerprint
from cpag_core.contracts import validate


class Round17CoreTests(unittest.TestCase):
    def fixture(self, base, *, synthetic=True, rules=False):
        n,p,c=make_case(base/'inputs')
        config=profile(synthetic=synthetic,rules=rules)
        c.write_text(json.dumps(config))
        return n,p,c,config

    def test_independent_clock_formula_and_precision_interval(self):
        clock=profile()['clocks']['network']
        clock.update(offset_seconds=2,uncertainty_seconds=.2,precision_seconds=.1,drift_ppm=1000)
        # Anchor 1767225600; t=anchor+10 -> +2 offset +.01 drift +/- .3.
        timing=clock_time('original',1767225610,1767225611,clock,corrected)
        self.assertAlmostEqual(timing['interval'][0],1767225611.71,places=5)
        self.assertAlmostEqual(timing['interval'][1],1767225613.311,places=5)
        self.assertEqual(timing['raw'],'original')
        for key,reason in [('drift_basis','drift_basis_missing'),('precision_basis','precision_basis_missing')]:
            bad=copy.deepcopy(clock);bad.pop(key)
            timing=clock_time('original',1767225610,1767225611,bad,corrected)
            self.assertIsNone(timing['interval']);self.assertIn(reason,timing['unknown_reasons'])
        timing=clock_time('outside',1767225661,1767225662,clock,corrected)
        self.assertIsNone(timing['interval']);self.assertIn('clock_validity_outside',timing['unknown_reasons'])

    def test_extended_missing_clock_and_mapping_materials_never_associate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base)
            for key in ('drift_ppm','drift_anchor','drift_basis','precision_seconds','precision_basis','version','valid_from','valid_to'):
                test=copy.deepcopy(config)
                if key in ('valid_from','valid_to'):
                    test['clocks']['network'].pop('valid_from');test['clocks']['network'].pop('valid_to')
                else:test['clocks']['network'].pop(key)
                result=analyze(n,p,test)
                self.assertEqual(result['candidates'],[],key)
                self.assertIsNone(result['operations'][0]['time']['interval'],key)
            test=copy.deepcopy(config);test['mappings'][0].pop('version')
            self.assertEqual(analyze(n,p,test)['candidates'],[])

    def test_microsecond_intervals_enclose_original_decimal_and_config_precision_rejected(self):
        from fractions import Fraction
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base)
            p.write_text('time,pump\n2026-01-01T00:00:09.000001Z,0\n2026-01-01T00:00:12.000001Z,1\n')
            result=analyze(n,p,config)
            low,high=result['process'][0]['time']['interval']
            exact=Fraction(1767225609)+Fraction(1,1000000)
            self.assertLessEqual(Fraction.from_float(low),exact)
            self.assertGreaterEqual(Fraction.from_float(high),exact)
            config['clocks']['network']['drift_anchor']='2026-01-01T00:00:00.0000001Z'
            with self.assertRaisesRegex(ValueError,'configuration_timestamp_precision_unsupported'):analyze(n,p,config)

    def test_real_materials_required_and_schema_strict(self):
        for field in ['source','release','authorization_ref','timezone_basis','mapping_evidence_ref','rules_evidence_ref','collection_range']:
            config=profile(synthetic=False);config['source_provenance'].pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):validate_profile(config)
        for target,key in [('clocks','precision_basis'),('clocks','drift_anchor'),('mappings','basis')]:
            config=profile(synthetic=False)
            item=config[target]['network'] if target=='clocks' else config[target][0]
            item.pop(key)
            with self.assertRaises(ValueError):validate_profile(config)
        for key,value in [('schema_version','2.0.0'),('arbitrary',True)]:
            config=profile();config[key]=value
            with self.assertRaises(ValueError):validate_profile(config)
        config=profile();config.pop('analysis_mode');config.pop('source_provenance')
        with self.assertRaisesRegex(ValueError,'r17_fields_require_analysis_mode'):validate_profile(config)
        config=profile(synthetic=False);config.pop('analysis_mode')
        with self.assertRaisesRegex(ValueError,'explicit_analysis_mode'):validate_profile(config)
        config=profile(synthetic=False);config['clocks']['network']['basis']='  '
        with self.assertRaisesRegex(ValueError,'clock_materials'):validate_profile(config)

    def test_real_branch_retains_provenance_and_never_marks_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,synthetic=False,rules=True)
            manifest=export_task(n,p,c,base/'run')
            self.assertFalse(manifest['synthetic'])
            self.assertEqual(manifest['status'],'succeeded_with_warnings')
            self.assertIn('real_source_unvalidated',manifest['limitations'])
            self.assertEqual(verify_task(base/'run'),manifest)
            result=json.loads((base/'run/analysis.json').read_text())
            self.assertEqual(result['source_provenance'],config['source_provenance'])
            self.assertTrue(all(not r['event']['synthetic'] for r in result['network']+result['process']))
            self.assertFalse(result['changes'][0]['synthetic']);self.assertFalse(result['candidates'][0]['claim']['synthetic'])
            for event in json.loads((base/'run/events.json').read_text()):self.assertFalse(event['synthetic'])
            dataset=json.loads((base/'run/dataset.json').read_text())
            self.assertEqual(dataset['authorization_ref'],config['source_provenance']['authorization_ref'])
            view=query_task(base/'run',operation_id='first')
            self.assertFalse(view['synthetic']);self.assertEqual(len(view['verified_original_evidence']),4)
            finding=next(f for f in result['rule_findings'] if f['state']=='supported')
            view=query_task(base/'run',change_id=finding['finding_id'])
            self.assertEqual(view['selection']['rule_finding']['finding_id'],finding['finding_id'])
            self.assertTrue(view['verified_original_evidence'])

    def test_mapping_versions_validity_and_ambiguity_order_invariant(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base)
            result=analyze(n,p,config)
            self.assertEqual(result['candidates'][0]['state'],'supported_candidate')
            self.assertEqual(result['operations'][0]['mapping']['versions'][0]['version'],'generated-mapping-v1')
            config['mappings'][0]['valid_to']='2026-01-01T00:00:09Z'
            result=analyze(n,p,config);self.assertEqual(result['candidates'],[])
            self.assertIn('mapping_outside_validity',result['operations'][0]['unknown_reasons'])
            config=profile();config['clocks']['network']['uncertainty_seconds']=1
            config['mappings'][0]['valid_from']='2026-01-01T00:00:10Z'
            result=analyze(n,p,config);self.assertEqual(result['candidates'],[])
            self.assertIn('mapping_validity_uncertain',result['operations'][0]['unknown_reasons'])
            config=profile();config['mappings'].append(dict(config['mappings'][0],rule_id='other',version='other-v2'))
            for mappings in [config['mappings'],list(reversed(config['mappings']))]:
                config['mappings']=mappings;result=analyze(n,p,config)
                self.assertEqual(result['candidates'],[])
                self.assertEqual(set(result['operations'][0]['mapping']['rule_ids']),{'other','set-pump-one'})
                self.assertEqual(result['operations'][0]['mapping']['status'],'conflict')

    def test_finite_threshold_boundary_refutation_and_state_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,rules=True)
            result=analyze(n,p,config);findings=result['rule_findings']
            threshold=[f for f in findings if f['rule_id']=='threshold-one']
            self.assertEqual([f['state'] for f in threshold],['refuted','refuted','supported','supported','supported'])
            self.assertEqual(threshold[2]['evidence_refs'][0]['record_number'],3)
            self.assertEqual(threshold[0]['counterevidence'][0]['reason'],'configured_predicate_false')
            states=[f for f in findings if f['kind']=='state_change']
            self.assertEqual([f['state'] for f in states],['unknown','refuted','supported','refuted','refuted'])
            self.assertEqual({r['record_number'] for r in states[2]['evidence_refs']},{2,3})
            config['finite_rules'][0]['operator']='gt'
            self.assertTrue(all(f['state']=='refuted' for f in analyze(n,p,config)['rule_findings'] if f['kind']=='threshold'))

    def test_constraint_controlled_math_units_applicability_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,rules=True)
            config['process']['columns']['level']={'tag':'level','asset_id':'synthetic-pump','value_type':'analog','unit':'synthetic_boolean'}
            p.write_text('time,pump,level\n2026-01-01T00:00:09Z,0,2\n2026-01-01T00:00:12Z,1,2\n')
            rule=dict(config['finite_rules'][0],rule_id='constraint',kind='process_constraint',other_tag='level',other_unit='synthetic_boolean',arithmetic='sum',operator='ge',value=3)
            config['finite_rules']=[rule]
            findings=analyze(n,p,config)['rule_findings']
            self.assertEqual([f['state'] for f in findings],['refuted','supported'])
            self.assertEqual({r['column'] for r in findings[1]['evidence_refs']},{'pump','level'})
            rule['other_unit']='m';findings=analyze(n,p,config)['rule_findings']
            self.assertTrue(all(f['state']=='unknown' for f in findings))
            rule['other_unit']='synthetic_boolean';rule['applies_when']={'tag':'level','unit':'synthetic_boolean','equals':0}
            self.assertTrue(all('applicability_not_met' in f['unknown_reasons'] for f in analyze(n,p,config)['rule_findings']))
            rule.pop('applies_when');rule['arithmetic']='ratio'
            p.write_text('time,pump,level\n2026-01-01T00:00:09Z,0,0\n2026-01-01T00:00:12Z,1,\n')
            findings=analyze(n,p,config)['rule_findings']
            self.assertIn('division_by_zero',findings[0]['unknown_reasons']);self.assertIn('missing_or_invalid_companion',findings[1]['unknown_reasons'])
            rule['expression']='__import__("os").system("touch unexpected")'
            with self.assertRaises(ValueError):analyze(n,p,config)

    def test_missing_timezone_precision_duplicates_and_gap_do_not_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,rules=True)
            p.write_text('time,pump\n2026-01-01T00:00:09,0\n2026-01-01T00:00:12,1\n')
            result=analyze(n,p,config);self.assertEqual(result['candidates'],[])
            self.assertTrue(all(f['state']=='unknown' for f in result['rule_findings']))
            config['process'].update(timezone='UTC',timezone_evidence='generated timezone declaration')
            result=analyze(n,p,config);self.assertEqual(len(result['changes']),1)
            p.write_text('time,pump\n2026-01-01T00:00:09Z,0\n2026-01-01T00:00:09Z,1\n')
            result=analyze(n,p,config);self.assertEqual(result['changes'],[])
            self.assertTrue(all(f['state']=='unknown' for f in result['rule_findings']))
            p.write_text('time,pump\n2026-01-01T00:00:09Z,0\n2026-01-01T00:00:10Z,\n2026-01-01T00:00:12Z,1\n')
            result=analyze(n,p,config);self.assertEqual(result['changes'],[])
            states=[f for f in result['rule_findings'] if f['kind']=='state_change']
            self.assertTrue(all(f['state']=='unknown' for f in states))

    def test_multicapture_integrity_query_and_reproducibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,synthetic=False,rules=True)
            data=n.read_bytes();length=struct.unpack_from('<I',data,24+8)[0];split=24+16+length
            first=base/'first.pcap';second=base/'second.pcap'
            first.write_bytes(data[:split]);second.write_bytes(data[:24]+data[split:])
            manifest=export_task([first,second],p,c,base/'run')
            result=json.loads((base/'run/analysis.json').read_text())
            self.assertEqual(len(result['network']),2);self.assertEqual(len(result['candidates']),1)
            self.assertEqual(result['candidates'][0]['state'],'supported_candidate')
            self.assertIn('dual/sources/network-001.pcap',artifact_files(base/'run'))
            self.assertEqual(verify_task(base/'run'),manifest)
            view=query_task(base/'run',operation_id='first')
            network_refs=[r['source_ref'] for r in view['verified_original_evidence'] if r['source_ref']['frame_number'] is not None]
            self.assertEqual([r['frame_number'] for r in network_refs],[1,1])
            self.assertEqual(len({r['file_sha256'] for r in network_refs}),2)
            self.assertEqual(canonical(analyze([first,second],p,config)),canonical(analyze([first,second],p,config)))
            target=base/'run/dual/sources/network-001.pcap';changed=bytearray(target.read_bytes());changed[-1]^=1;target.write_bytes(changed)
            with self.assertRaises(ValueError):verify_task(base/'run')

    def test_independent_cli_matches_api_and_finite_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,rules=True)
            environment=dict(__import__('os').environ,PYTHONPATH=str(ROOT/'services/analysis/src'))
            command=[sys.executable,'-m','cpag_core','--dual-source','--network',str(n),'--process',str(p),'--profile',str(c),'--output',str(base/'cli')]
            completed=subprocess.run(command,cwd=ROOT,env=environment,capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            self.assertEqual(canonical(json.loads((base/'cli/analysis.json').read_text())),canonical(analyze(n,p,config)))
            events=json.loads((base/'cli/events.json').read_text())
            finite=[event for event in events if event.get('event_type')=='finite_rule_finding']
            self.assertEqual(len(finite),10)
            for event in finite:validate('DerivedEvent',event)

    def test_overlapping_process_intervals_preserve_observations_without_state_order_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base,rules=True)
            original_events=[r['event'] for r in analyze(n,p,config)['process']]
            for material,width in (('precision_seconds',2),('uncertainty_seconds',2),('precision_seconds',0.75)):
                test=copy.deepcopy(config)
                test['clocks']['process'][material]=width
                test['max_sample_gap_seconds']=10
                result=analyze(n,p,test)
                self.assertEqual(len(result['process']),5)
                self.assertEqual([r['event'] for r in result['process']],original_events)
                self.assertEqual(result['changes'],[])
                self.assertEqual(result['candidates'],[])
                self.assertIn('process_order_uncertain',result['operations'][0]['unknown_reasons'])
                self.assertIn('process_order_uncertain',result['quality']['group_issues'][0]['reasons'])
                states=[f for f in result['rule_findings'] if f['kind']=='state_change']
                self.assertTrue(all(f['state']=='unknown' and 'process_order_uncertain' in f['unknown_reasons'] for f in states))
            # Historical mode is deliberately unchanged, including its prior result.
            legacy=json.loads((ROOT/'profiles/dual-source-synthetic.json').read_text())
            legacy['clocks']['process']['uncertainty_seconds']=2
            legacy['max_sample_gap_seconds']=10
            self.assertEqual(len(analyze(n,p,legacy)['changes']),1)

    def test_failed_input_never_publishes_partial_and_old_run_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);n,p,c,config=self.fixture(base)
            run_dual(n,p,c,base/'old');old=(base/'old/analysis.json').read_bytes()
            config['mappings'][0]['expected_value']=99;c.write_text(json.dumps(config))
            self.assertEqual((base/'old/analysis.json').read_bytes(),old)
            self.assertTrue(query(base/'old',operation_id='first')['verified_original_evidence'])
            p.write_text('time,pump\nbad,row,width\n')
            with self.assertRaises(ValueError):export_task(n,p,c,base/'failed')
            self.assertFalse((base/'failed').exists())

if __name__=='__main__':unittest.main()
