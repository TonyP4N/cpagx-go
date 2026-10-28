"""Explicit capacity reaches single-source parsing, verification and evidence."""
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from cpag_core.capacity import ENGINEERING,resolve_capacity_profile
from cpag_core.evaluation_artifacts import adapt_artifact
from cpag_core import single_source_export as source
from dual_source_fixtures import make_case
from round17_profile import profile


class SingleSourceCapacityTests(unittest.TestCase):
    def test_explicit_1001_record_export_keeps_all_and_legacy_rejects_without_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,process,config_path=make_case(root/'inputs');config=profile()
            start=datetime(2026,1,1,tzinfo=timezone.utc)
            process.write_text('time,pump\n'+''.join(f'{(start+timedelta(milliseconds=i*10)).isoformat()},0\n' for i in range(1001)))
            config_path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError,'process_record_limit'):
                source.export_task('process',process,config_path,root/'legacy')
            self.assertFalse((root/'legacy').exists())
            config['capacity_profile']=ENGINEERING;config_path.write_text(json.dumps(config))
            source.export_task('process',process,config_path,root/'expanded')
            source.verify_task(root/'expanded')
            actual=json.loads((root/'expanded/analysis.json').read_text())
            self.assertEqual(len(actual['process']),1001)
            self.assertEqual(actual['execution_limits']['process_records'],10000)
            self.assertEqual(actual['capacity_profile'],ENGINEERING)
            self.assertEqual(actual['candidates'],[])

    def test_small_observation_projection_and_query_statistics_stay_equal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);network,process,config_path=make_case(root/'inputs');config=profile()
            for mode,path in [('network',network),('process',process)]:
                results=[]
                for name,version in [('old',None),('new',ENGINEERING)]:
                    current=dict(config)
                    if version:current['capacity_profile']=version
                    config_path.write_text(json.dumps(current));out=root/(mode+'-'+name)
                    source.export_task(mode,path,config_path,out)
                    adapted=adapt_artifact(out,batch='registered',sample_sha256='a'*64,projection=mode)
                    view=source.query_task(out,**({'operation_id':'first'} if mode=='network' else {'change_id':'first'}))
                    results.append((adapted['predictions']['events'],len(view['verified_original_evidence'])))
                self.assertEqual(results[0],results[1])

    def test_per_file_aggregate_process_and_configuration_byte_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);budget=resolve_capacity_profile(dict(profile(),capacity_profile=ENGINEERING))
            paths=[root/'a.pcap',root/'b.pcap']
            for path in paths:
                with path.open('wb') as stream:stream.truncate(budget.network_file_bytes)
            self.assertEqual(source._paths('network',paths,budget),paths)
            with self.assertRaises(ValueError):source._paths('network',paths,resolve_capacity_profile(profile()))
            with paths[0].open('ab') as stream:stream.write(b'x')
            with self.assertRaisesRegex(ValueError,'file_size_limit'):source._paths('network',paths,budget)
            csv_path=root/'data.csv'
            with csv_path.open('wb') as stream:stream.truncate(budget.process_bytes)
            source._paths('process',csv_path,budget)
            with csv_path.open('ab') as stream:stream.write(b'x')
            with self.assertRaisesRegex(ValueError,'input_size_limit'):source._paths('process',csv_path,budget)
            config=profile();config['clocks']['network']['basis']='x'*70000;path=root/'profile.json'
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError,'profile_size_limit'):source._read_profile(path)
            config['capacity_profile']=ENGINEERING;path.write_text(json.dumps(config))
            _,actual=source._read_profile(path)
            self.assertEqual(actual.profile_bytes,8*1024**2)
            self.assertEqual(source._output_limit(actual),1024**3)
            self.assertEqual(source._output_limit(resolve_capacity_profile(profile())),16*1024**2)


if __name__=='__main__':unittest.main()
