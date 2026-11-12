import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'services/analysis/src'), str(ROOT/'scripts/validation')]
from dual_source_fixtures import make_case
from cpag_core.contracts import validate
from cpag_core.dual_source_export import (backup_task, export_task, query_task,
                                          restore_task, verify_task)
from cpag_core.pipeline import canonical, file_hash, fingerprint

GOLD = json.loads((ROOT/'fixtures/dual-source/expectations.json').read_text())['cases']


class DualSourceExportTests(unittest.TestCase):
    def test_preregistered_scenarios_project_all_relations_without_new_claims(self):
        for name, gold in GOLD.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                paths = make_case(base/'inputs', name)
                manifest = export_task(*paths, base/'export')
                self.assertEqual(verify_task(base/'export'), manifest)
                result = json.loads((base/'export/analysis.json').read_text())
                graph = json.loads((base/'export/graph.json').read_text())
                events = json.loads((base/'export/events.json').read_text())
                validate('GraphArtifact', graph)
                self.assertEqual(len(graph['nodes']), len(result['network'])+len(result['process'])+gold['changes'])
                self.assertEqual(len(graph['edges']), gold['candidates'])
                self.assertEqual(len(graph['claims']), gold['candidates'])
                self.assertEqual(len(events), len(graph['nodes']))
                self.assertEqual({n['event_id'] for n in graph['nodes']}, {e['event_id'] for e in events})
                self.assertEqual([e['id'] for e in graph['edges']], [c['candidate_id'] for c in result['candidates']])
                self.assertEqual(graph['claims'], [c['claim'] for c in result['candidates']])
                for edge, candidate in zip(graph['edges'], result['candidates']):
                    self.assertEqual(edge['source'], candidate['operation_id'])
                    self.assertEqual(edge['target'], candidate['change_id'])
                    self.assertEqual(edge['rule_version'], candidate['rule_version'])
                    self.assertEqual(edge['config_version'], candidate['config_version'])
                    self.assertEqual(edge['config_fingerprint'], result['config_fingerprint'])
                    self.assertEqual(edge['candidate_state'], candidate['state'])
                    view = query_task(base/'export', operation_id=edge['source'])
                    self.assertTrue(view['verified_original_evidence'])
                if result['changes']:
                    view = query_task(base/'export', change_id=result['changes'][0]['event_id'])
                    self.assertTrue(view['verified_original_evidence'])

    def test_pcapng_and_unknown_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            paths = make_case(base/'inputs', capture_format='pcapng')
            export_task(*paths, base/'export')
            with self.assertRaises(KeyError):
                query_task(base/'export', operation_id='absent')
            with self.assertRaises(KeyError):
                query_task(base/'export', change_id='absent')

    def test_all_retained_and_standard_files_are_required(self):
        names = ('dual/sources/network.pcap', 'dual/sources/process.csv',
                 'dual/sources/profile.json', 'dual/analysis.json', 'dual/manifest.json',
                 'dataset.json', 'events.json', 'graph.json', 'quality.json',
                 'analysis.json', 'run_manifest.json')
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                export_task(*make_case(base/'inputs'), base/'export')
                target = base/'export'/name
                original = target.read_bytes()
                target.write_bytes(original+b' ')
                with self.assertRaises(ValueError):
                    verify_task(base/'export')
                target.unlink()
                with self.assertRaises(ValueError):
                    verify_task(base/'export')

    def test_rehashed_graph_and_analysis_still_fail_reprojection(self):
        for name in ('graph.json', 'analysis.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                export_task(*make_case(base/'inputs'), base/'export')
                target = base/'export'/name
                value = json.loads(target.read_text())
                if name == 'graph.json':
                    value['edges'][0]['candidate_state'] = 'supported_candidate_but_untrue'
                else:
                    value['operations'][0]['response']['state'] = 'error'
                target.write_bytes(canonical(value)+b'\n')
                manifest_path = base/'export/run_manifest.json'
                manifest = json.loads(manifest_path.read_text())
                for entry in manifest['artifacts']:
                    if entry['path'] == name:
                        entry['sha256'] = file_hash(target)
                        entry['size_bytes'] = target.stat().st_size
                if name == 'graph.json':
                    manifest['result_hashes']['graph'] = fingerprint(value)
                manifest_path.write_bytes(canonical(manifest)+b'\n')
                with self.assertRaisesRegex(ValueError, 'projection_mismatch'):
                    verify_task(base/'export')

    def test_portable_directory_backup_restore_and_corruption_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            export_task(*make_case(base/'inputs'), base/'export')
            backup_task(base/'export', base/'bundle')
            restore_task(base/'bundle', base/'restored')
            self.assertEqual((base/'export/run_manifest.json').read_bytes(),
                             (base/'restored/run_manifest.json').read_bytes())
            self.assertTrue(query_task(base/'restored', operation_id='first')['verified_original_evidence'])
            with self.assertRaisesRegex(ValueError, 'restore_target_already_exists'):
                restore_task(base/'bundle', base/'restored')
            (base/'bundle/dual/sources/process.csv').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                restore_task(base/'bundle', base/'second')
            self.assertFalse((base/'second').exists())
            shutil.copytree(base/'export', base/'incomplete')
            (base/'incomplete/dual/manifest.json').unlink()
            with self.assertRaises(ValueError):
                restore_task(base/'incomplete', base/'third')
            self.assertFalse((base/'third').exists())

    def test_claim_identity_and_published_wrapper_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            paths = make_case(base/'inputs')
            output = base/'export'
            manifest = export_task(*paths, output, run_id='queued-dual-job', attempt_id=2)
            self.assertEqual((manifest['run_id'],manifest['attempt_id']), ('queued-dual-job',2))
            wrapper = {'config_fingerprint':manifest['config_fingerprint'],
                       'inputs':dict(zip(('network','process','profile'),(file_hash(path) for path in paths))),
                       'artifacts':[{'path':name,'sha256':file_hash(output/name),'size':(output/name).stat().st_size}
                                    for name in sorted(p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file())]}
            (output/'manifest.json').write_bytes(canonical(wrapper)+b'\n')
            self.assertEqual(verify_task(output), manifest)
            anchor=output/(file_hash(output/'manifest.json')+'.json')
            anchor.write_bytes((output/'manifest.json').read_bytes())
            self.assertEqual(verify_task(output), manifest)
            anchor.unlink()
            wrapper['artifacts'][0]['sha256'] = '0'*64
            (output/'manifest.json').write_bytes(canonical(wrapper)+b'\n')
            with self.assertRaisesRegex(ValueError, 'publication_integrity_mismatch'):
                verify_task(output)

    def test_invalid_attempt_identity_does_not_reserve_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);paths=make_case(base/'inputs')
            with self.assertRaisesRegex(ValueError,'invalid_attempt_id'):
                export_task(*paths,base/'export',run_id='job',attempt_id=0)
            self.assertFalse((base/'export').exists())


if __name__ == '__main__':
    unittest.main()
