import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_core_summary import phase_summary,tmp_samples,redact,summarize


class CorePublicSummaryTests(unittest.TestCase):
    def test_failed_standalone_packet_preserves_observed_native_metrics_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            native={'status':'failed','wall_seconds':10,'cpu_seconds':9,'process_rss_high_water_bytes':123,
                'cgroup':{'peak_memory_bytes':222,'cpu_stat':{'usage_usec':111}}}
            (Path(directory)/'verify-result.json').write_text(json.dumps(native))
            value=phase_summary(directory,{'phase':'verify','status':'failed','whole_phase_seconds':11})
            self.assertEqual(value['status'],'failed');self.assertEqual(value['native_status'],'failed')
            self.assertEqual(value['native_result_source'],'standalone_packet');self.assertTrue(value['native_result_sha256'])
            self.assertEqual(value['native_process_cpu_seconds'],9);self.assertEqual(value['process_rss_high_water_bytes'],123)
            self.assertEqual(value['kernel_cgroup_peak_memory_bytes'],222)

    def test_unfinished_native_measurements_are_null_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            value=phase_summary(directory,{'phase':'verify','status':'failed','whole_phase_seconds':3})
            for field in ('native_module_wall_seconds','native_process_cpu_seconds','process_rss_high_water_bytes','kernel_cgroup_peak_memory_bytes'):
                self.assertIsNone(value[field])
            self.assertIsNone(value['temporary_samples']['sampled_tmpfs_peak_bytes'])
            path=Path(directory)/'sample.jsonl';path.write_text(json.dumps({'tmpfs_sample':{'tmp_used_bytes':0}})+'\n')
            self.assertEqual(tmp_samples(path)['sampled_tmpfs_peak_bytes'],0)

    def test_public_copies_remove_personal_paths_and_reject_capabilities(self):
        value=redact({'message':'/Users/example/Documents/work/file /private/tmp/cpag-r19-core-case/a'},Path('/Users/example/Documents/work'))
        self.assertNotIn('/Users/',value['message']);self.assertIn('$WORKSPACE',value['message'])
        self.assertIn('$CORE_SCRATCH',value['message'])
        with self.assertRaises(ValueError):redact({'approval':{'mac':'do not publish'}},Path('/workspace'))

    def test_missing_cells_are_not_called_passed(self):
        value=summarize({'image_id':'sha256:fixed','runtime_commit':'commit','runtime_file_count':83,'all_equal':True},[],workspace='/workspace')
        self.assertEqual(value['status'],'incomplete_or_failed');self.assertEqual(len(value['cells']),6)
        self.assertTrue(all(row['status']=='not_recorded' and row['measurements'] is None for row in value['cells']))


if __name__=='__main__':unittest.main()
