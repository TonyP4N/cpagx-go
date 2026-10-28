"""Version binding, parser budgets and logical-record fail-closed checks."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from cpag_core.capacity import ENGINEERING, resolve_capacity_profile, parser_limits
from cpag_core.dual_source_rules import validate_profile
from cpag_core.parsers import parse_process
from round17_profile import profile


class CapacityProfileTests(unittest.TestCase):
    def test_optional_version_does_not_expand_old_defaults(self):
        old=profile(); new=deepcopy(old); new['capacity_profile']=ENGINEERING
        a=resolve_capacity_profile(old); b=resolve_capacity_profile(new)
        self.assertEqual((a.network_file_bytes,a.network_total_bytes,a.process_bytes,a.process_records,a.operations),(16*1024**2,16*1024**2,2*1024**2,1000,100))
        self.assertEqual((b.network_file_bytes,b.network_total_bytes,b.process_bytes,b.process_records,b.operations),(64*1024**2,128*1024**2,8*1024**2,10000,10000))
        with self.assertRaises(FrozenInstanceError): b.operations=10001
        validate_profile(new)
        for value in ('',None,True,{},'future-version'):
            bad=deepcopy(new); bad['capacity_profile']=value
            with self.assertRaises(ValueError): validate_profile(bad)
        new['replay']={}
        with self.assertRaises(ValueError): validate_profile(new)

    def test_shared_storage_budget_is_explicit_and_preserves_physical_target(self):
        from cpag_core.capacity import SHARED, SHARED_FORMAT, shared_storage_budget
        cfg=profile(); cfg.update(capacity_profile=SHARED,storage_format=SHARED_FORMAT)
        validate_profile(cfg)
        budget=resolve_capacity_profile(cfg)
        self.assertEqual((budget.candidates,budget.snapshots,budget.revisions),(500000,65000,90000))
        self.assertEqual((budget.network_file_bytes,budget.network_total_bytes,budget.process_records,budget.output_bytes),
                         (64*1024**2,128*1024**2,10000,1024**3))
        storage=shared_storage_budget(cfg)
        self.assertEqual((storage.physical_bytes,storage.query_bytes,storage.cache_bytes),(1024**3,8*1024**2,16*1024**2))
        for field in ('capacity_profile','storage_format','analysis_mode'):
            invalid=deepcopy(cfg);invalid.pop(field)
            with self.assertRaises(ValueError):validate_profile(invalid)
        for change in ({'capacity_profile':ENGINEERING},{'storage_format':'unknown'}, {'replay':{}}):
            invalid=deepcopy(cfg);invalid.update(change)
            with self.assertRaises(ValueError):validate_profile(invalid)

    def test_parser_options_are_explicit_and_bounded(self):
        cfg=profile(); old=parser_limits(cfg); cfg['capacity_profile']=ENGINEERING; new=parser_limits(cfg)
        self.assertEqual(old['stream_limits'].max_segments,2048)
        self.assertEqual(new['stream_limits'].max_segments,100000)
        self.assertEqual(new['packet_limits'].max_bytes,64*1024**2)
        self.assertEqual(new['capture_limits'].max_total_bytes,128*1024**2)
        self.assertEqual(new['process_limits'].max_columns,16)
        self.assertEqual(new['stream_limits'].max_processing_seconds,1800)

    def test_csv_record_limit_fails_without_returning_partial_events(self):
        cfg=profile(); cfg['capacity_profile']=ENGINEERING
        options=parser_limits(cfg)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.csv'
            def parse(count,limits):
                path.write_text('time,pump\n'+''.join(f'2026-01-01T00:00:00Z,{i%2}\n' for i in range(count)))
                return parse_process(path,cfg['process'],synthetic=True,limits=limits,extended=True)
            actual=parse(10000,options['process_limits'])
            self.assertEqual(len(actual['events']),10000)
            for count,limits in ((10001,options['process_limits']),(1001,parser_limits(profile())['process_limits'])):
                bad=parse(count,limits)
                self.assertEqual(bad['quality']['status'],'unsupported')
                self.assertEqual(bad['events'],[])
                self.assertIn('process_record_limit',bad['quality']['reasons'])


if __name__=='__main__': unittest.main()
