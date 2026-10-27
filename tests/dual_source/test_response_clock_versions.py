"""Response-clock expectations preregistered before correction, independent raw fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from round17_profile import profile
from cpag_core.dual_source import analyze, query, R17_VERSION, R17_LEGACY_VERSION, VERSION
from cpag_core.dual_source_export import export_task, verify_task, query_task, _warnings
from cpag_core.pipeline import canonical, file_hash

HISTORICAL=ROOT/'tests/fixtures/r17-response-clock-v1'
COMPATIBILITY={'analysis_version':'bounded-dual-source-1','status':'historical_semantics',
               'known_limitations':['response_clock_quality_not_enforced'],'reanalysis_required':True}


class ResponseClockVersionTests(unittest.TestCase):
    def fixture(self, base, layout='single', case='normal'):
        n,p,c=make_case(base/'inputs','missing_response' if case=='missing_response' else 'success')
        config=profile()
        clock=config['clocks']['network']
        if case=='request_outside':clock['valid_from']='2026-01-01T00:00:10.500000Z'
        elif case=='response_outside':clock['valid_to']='2026-01-01T00:00:10.500000Z'
        elif case=='closed_boundary':clock.update(valid_from='2026-01-01T00:00:10Z',valid_to='2026-01-01T00:00:11Z')
        elif case=='just_outside':clock['valid_to']='2026-01-01T00:00:10.999999Z'
        elif case=='basis_missing':clock['basis']=None
        elif case=='drift_basis_missing':clock.pop('drift_basis')
        elif case=='precision_basis_missing':clock.pop('precision_basis')
        elif case=='overlap':clock['precision_seconds']=0.6
        elif case=='touch':clock['precision_seconds']=0.5
        raw=n.read_bytes();first_end=24+16+struct.unpack_from('<I',raw,32)[0]
        if case=='precedes':
            raw=bytearray(raw);struct.pack_into('<I',raw,first_end,1767225609);raw=bytes(raw);n.write_bytes(raw)
        paths=n
        if layout=='split':
            second=base/'inputs/response.pcap'
            second.write_bytes(raw[:24]+raw[first_end:]);n.write_bytes(raw[:first_end]);paths=[n,second]
        c.write_text(json.dumps(config))
        return paths,p,c,config

    def test_independent_request_response_clock_oracle_single_and_split(self):
        cases={'normal':None,'closed_boundary':None,
               'request_outside':'request_clock_validity_outside','response_outside':'response_clock_validity_outside',
               'just_outside':'response_clock_validity_outside','basis_missing':'response_clock_basis_missing',
               'drift_basis_missing':'response_drift_basis_missing','precision_basis_missing':'response_precision_basis_missing',
               'overlap':'response_order_uncertain','touch':'response_order_uncertain','precedes':'response_precedes_request'}
        for layout in ('single','split'):
            for case,reason in cases.items():
                with self.subTest(layout=layout,case=case),tempfile.TemporaryDirectory() as tmp:
                    base=Path(tmp);net,p,c,config=self.fixture(base,layout,case)
                    export_task(net,p,c,base/'run');verify_task(base/'run')
                    result=json.loads((base/'run/analysis.json').read_text());graph=json.loads((base/'run/graph.json').read_text())
                    operation=result['operations'][0]
                    self.assertEqual(result['analysis_version'],'bounded-dual-source-2')
                    self.assertEqual(len(result['network']),2);self.assertEqual(len(result['process']),5)
                    self.assertEqual(operation['response']['state'],'success')
                    self.assertEqual(operation['response']['meaning'],'protocol_service_success_only')
                    self.assertEqual(len(result['changes']),1)
                    quality=json.loads((base/'run/quality.json').read_text())
                    if reason is None:
                        self.assertEqual(quality['operation_time_issues'],[])
                        self.assertEqual([candidate['state'] for candidate in result['candidates']],['supported_candidate'])
                        self.assertEqual(len(graph['edges']),1)
                    else:
                        self.assertIn(reason,operation['unknown_reasons'])
                        self.assertEqual(len(quality['operation_time_issues']),1)
                        self.assertEqual(quality['operation_time_issues'][0]['operation_id'],operation['operation_id'])
                        self.assertIn(reason,quality['operation_time_issues'][0]['reasons'])
                        self.assertEqual(quality,result['quality'])
                        self.assertEqual(operation['assessment'],'unknown')
                        self.assertEqual(result['candidates'],[]);self.assertEqual(graph['edges'],[])
                        view=query_task(base/'run',operation_id='first')
                        self.assertEqual(len(view['verified_original_evidence']),2)
                        self.assertTrue(all(item['source_ref']['frame_number'] is not None for item in view['verified_original_evidence']))
                        change=query_task(base/'run',change_id='first')
                        self.assertEqual(len(change['verified_original_evidence']),2)
                        self.assertTrue(all(item['source_ref']['record_number'] is not None for item in change['verified_original_evidence']))
                        if case=='response_outside':
                            self.assertIn('clock_validity_outside',operation['response']['time']['unknown_reasons'])
                            self.assertIn('operation: '+reason,verify_task(base/'run')['warnings'])
                    self.assertNotIn('compatibility',query_task(base/'run',operation_id='first'))

    def test_cli_core_preserves_missing_materials_but_real_material_gate_rejects(self):
        for case,reason in [('basis_missing','response_clock_basis_missing'),('drift_basis_missing','response_drift_basis_missing'),('precision_basis_missing','response_precision_basis_missing')]:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);net,p,c,config=self.fixture(base,'single',case)
                args=[sys.executable,'-m','cpag_core.dual_source_export','--network',str(net),'--process',str(p),'--profile',str(c),'--output',str(base/'cli')]
                completed=subprocess.run(args,env=dict(os.environ,PYTHONPATH=str(ROOT/'services/analysis/src')),capture_output=True,text=True,cwd=ROOT)
                self.assertEqual(completed.returncode,0,completed.stderr)
                result=json.loads((base/'cli/analysis.json').read_text())
                self.assertEqual(canonical(result),canonical(analyze(net,p,config)))
                self.assertIn(reason,result['operations'][0]['unknown_reasons']);self.assertEqual(result['candidates'],[])
                config['synthetic']=False
                with self.assertRaisesRegex(ValueError,'real_clock_materials_required'):analyze(net,p,config)

    def test_current_normal_three_run_canonical_hashes_and_cli_for_both_layouts(self):
        for layout in ('single','split'):
            for case in ('normal','response_outside'):
                with self.subTest(layout=layout,case=case),tempfile.TemporaryDirectory() as tmp:
                    base=Path(tmp);net,p,c,config=self.fixture(base,layout,case)
                    runs=[analyze(net,p,config) for _ in range(3)]
                    self.assertEqual(len({hashlib.sha256(canonical(result)).hexdigest() for result in runs}),1)
                    args=[sys.executable,'-m','cpag_core.dual_source_export']
                    for network in net if isinstance(net,list) else [net]:args+=['--network',str(network)]
                    args+=['--process',str(p),'--profile',str(c),'--output',str(base/'cli')]
                    completed=subprocess.run(args,env=dict(os.environ,PYTHONPATH=str(ROOT/'services/analysis/src')),capture_output=True,text=True,cwd=ROOT)
                    self.assertEqual(completed.returncode,0,completed.stderr)
                    self.assertEqual(canonical(json.loads((base/'cli/analysis.json').read_text())),canonical(runs[0]))

    def test_one_invalid_response_does_not_contaminate_other_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,p,c=make_case(base/'inputs','ambiguous')
            config=profile();config['clocks']['network']['valid_to']='2026-01-01T00:00:11.100000Z'
            c.write_text(json.dumps(config));export_task(net,p,c,base/'run')
            result=json.loads((base/'run/analysis.json').read_text())
            quality=json.loads((base/'run/quality.json').read_text())
            first,second=result['operations']
            self.assertEqual(quality['unknown_reasons'],[])
            self.assertEqual(quality['operation_time_issues'],[{'operation_id':second['operation_id'],'reasons':['response_clock_validity_outside']}])
            self.assertEqual([candidate['operation_id'] for candidate in result['candidates']],[first['operation_id']])
            self.assertEqual(result['candidates'][0]['state'],'supported_candidate')
            self.assertEqual(second['assessment'],'unknown');self.assertEqual(second['candidates'],[])

    def test_unknown_time_status_with_interval_cannot_bypass_guard(self):
        from unittest.mock import patch
        from cpag_core.dual_source_rules import clock_time as actual_clock_time
        for role,when in (('request',1767225610),('response',1767225611)):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                net,p,c,config=self.fixture(Path(tmp))
                def inconsistent_clock(raw,*args,**kwargs):
                    timing=actual_clock_time(raw,*args,**kwargs)
                    if isinstance(raw,list) and raw[0]['raw_timestamp']/raw[0]['ticks_per_second']==when:
                        timing['status']='unknown'
                    return timing
                with patch('cpag_core.dual_source.clock_time',side_effect=inconsistent_clock):
                    result=analyze(net,p,config)
                self.assertEqual(result['candidates'],[])
                self.assertEqual(result['operations'][0]['assessment'],'unknown')
                self.assertIn(role+'_clock_time_unknown',result['operations'][0]['unknown_reasons'])
                self.assertEqual(result['operations'][0]['response']['state'],'success')

    def test_no_response_does_not_broaden_existing_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            net,p,c,config=self.fixture(Path(tmp),'single','missing_response')
            old=analyze(net,p,config,_analysis_version=R17_LEGACY_VERSION)
            current=analyze(net,p,config)
            self.assertNotEqual(old['operations'][0]['response']['state'],'success')
            self.assertEqual(_warnings(current),_warnings(old))
            self.assertEqual(current['quality'].pop('operation_time_issues'),[])
            current['analysis_version']=old['analysis_version']
            self.assertEqual(canonical(current),canonical(old))

    def test_historical_full_bug_artifact_verified_without_mutation_and_explicit_reanalysis(self):
        paths=[path for path in HISTORICAL.rglob('*') if path.is_file()]
        before={path.relative_to(HISTORICAL).as_posix():file_hash(path) for path in paths}
        retained=json.loads((HISTORICAL/'analysis.json').read_text())
        manifest=verify_task(HISTORICAL)
        self.assertEqual(manifest,json.loads((HISTORICAL/'run_manifest.json').read_text()))
        view=query_task(HISTORICAL,operation_id='first')
        self.assertEqual(view['compatibility'],COMPATIBILITY)
        self.assertEqual([candidate['state'] for candidate in view['selection']['candidates']],['supported_candidate'])
        self.assertIsNone(view['selection']['operation']['response']['time']['interval'])
        self.assertEqual(len(view['verified_original_evidence']),4)
        self.assertEqual(before,{path.relative_to(HISTORICAL).as_posix():file_hash(path) for path in paths})
        self.assertEqual(retained['analysis_version'],R17_LEGACY_VERSION)
        self.assertNotIn('operation_time_issues',retained['quality'])
        with tempfile.TemporaryDirectory() as tmp:
            sources=HISTORICAL/'dual/sources'
            export_task([sources/'network.pcap',sources/'network-001.pcap'],sources/'process.csv',sources/'profile.json',Path(tmp)/'reanalyzed')
            current=json.loads((Path(tmp)/'reanalyzed/analysis.json').read_text())
            self.assertEqual(current['analysis_version'],R17_VERSION)
            self.assertEqual(current['candidates'],[])
            self.assertNotEqual(canonical(current),canonical(retained))

    def test_unknown_and_mixed_versions_rejected_and_public_execution_has_no_override(self):
        import shutil
        for version in ('bounded-dual-source-0','bounded-dual-source-999',VERSION,'',False):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);net,p,c,config=self.fixture(base)
                with self.assertRaisesRegex(ValueError,'unsupported_analysis_version'):analyze(net,p,config,_analysis_version=version)
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,p,c,config=self.fixture(base)
            with self.assertRaises(TypeError):export_task(net,p,c,base/'forbidden',_analysis_version=R17_LEGACY_VERSION)
            export_task(net,p,c,base/'run')
            manifest_path=base/'run/dual/manifest.json';manifest=json.loads(manifest_path.read_text())
            manifest['analysis_version']=R17_LEGACY_VERSION;manifest_path.write_bytes(canonical(manifest)+b'\n')
            with self.assertRaisesRegex(ValueError,'analysis_version_mismatch'):query(base/'run/dual',operation_id='first')
            with self.assertRaises(ValueError):verify_task(base/'run')
            manifest['analysis_version']='unknown';manifest_path.write_bytes(canonical(manifest)+b'\n')
            with self.assertRaisesRegex(ValueError,'unsupported_analysis_version'):query(base/'run/dual',operation_id='first')

if __name__=='__main__':unittest.main()
