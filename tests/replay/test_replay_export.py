import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import export_task,verify_task,query_task,snapshot_task
from cpag_core.pipeline import canonical,file_hash,fingerprint


class ReplayExportTests(unittest.TestCase):
    def test_three_runs_cli_history_and_independent_pending_expected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,profile,_=fixture(base/'input')
            hashes=[]
            for i in range(3):
                out=base/f'run-{i}';export_task(net,process,profile,out,run_id=f'run-{i}',attempt_id=i+1)
                hashes.append({name:file_hash(out/name) for name in ('snapshots.jsonl','revisions.jsonl','arrivals.jsonl','analysis.json','events.json','graph.json','metrics.json')})
                snapshots=[json.loads(line) for line in (out/'snapshots.jsonl').read_text().splitlines()]
                pending=next(row for row in snapshots if row['arrival_seq']==3)
                self.assertEqual(pending['analysis']['operations'][0]['replay']['status'],'pending_response')
                self.assertEqual(len(pending['analysis']['network']),1)
                self.assertEqual(pending['analysis']['candidates'],[])
                view=query_task(out,pending['snapshot_number'],operation_id='first')
                for item in view['verified_original_evidence']:
                    ref=item['source_ref']
                    self.assertNotEqual(ref['source_slot'],'network-1')
                    if ref['source_slot']=='process':self.assertLessEqual(ref['record_number'],2)
                normal=next(row for row in snapshots if row['arrival_seq']==6)
                self.assertEqual(len(normal['analysis']['candidates']),1)
                self.assertEqual(normal['analysis']['candidates'][0]['state'],'supported_candidate')
                self.assertEqual(len(query_task(out,normal['snapshot_number'],operation_id='first')['verified_original_evidence']),4)
                self.assertTrue(json.loads((out/'analysis.json').read_text())['operations'][0]['replay']['closed'])
                self.assertEqual(snapshot_task(out,pending['snapshot_number']),pending)
            self.assertEqual(hashes[0],hashes[1]);self.assertEqual(hashes[1],hashes[2])
            args=[sys.executable,'-m','cpag_core.replay_export']
            for path in net:args.extend(['--network',str(path)])
            args.extend(['--process',str(process),'--profile',str(profile),'--output',str(base/'cli')])
            run=subprocess.run(args,cwd=ROOT,env=dict(os.environ,PYTHONPATH=str(ROOT/'services/analysis/src')),capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual(hashes[0],{name:file_hash(base/'cli'/name) for name in hashes[0]})

    def test_retained_prefix_query_is_unchanged_when_future_response_and_csv_change(self):
        outputs=[]
        with tempfile.TemporaryDirectory() as tmp:
            for variant in (0,1):
                base=Path(tmp)/str(variant);net,process,profile,_=fixture(base/'input')
                if variant:
                    raw=bytearray(net[1].read_bytes());raw[-2]=5;net[1].write_bytes(raw)
                    process.write_text(process.read_text().replace(',1\n',',2\n'))
                out=base/'run';export_task(net,process,profile,out)
                outputs.append((snapshot_task(out,3),query_task(out,3,operation_id='first')))
                self.assertEqual(len(outputs[-1][1]['verified_original_evidence']),1)
            self.assertEqual(outputs[0],outputs[1])

    def test_expired_response_keeps_history_and_originals_without_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,profile,_=fixture(base/'input',case='response_expired')
            export_task(net,process,profile,base/'run')
            snapshots=[json.loads(s) for s in (base/'run/snapshots.jsonl').read_text().splitlines()]
            final=snapshots[-1];analysis=final['analysis']
            self.assertEqual(analysis['candidates'],[]);self.assertEqual(final['graph']['edges'],[])
            self.assertEqual(analysis['operations'][0]['response']['state'],'success')
            self.assertIn('response_clock_validity_outside',analysis['operations'][0]['unknown_reasons'])
            self.assertEqual(len(query_task(base/'run',final['snapshot_number'],operation_id='first')['verified_original_evidence']),2)
            self.assertEqual(len(query_task(base/'run',final['snapshot_number'],change_id='first')['verified_original_evidence']),2)

    def test_restore_copy_and_historical_tamper_rejected_even_rehashed(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);net,process,profile,_=fixture(base/'input');export_task(net,process,profile,base/'run')
            shutil.copytree(base/'run',base/'restored');verify_task(base/'restored')
            self.assertEqual(query_task(base/'run',3,operation_id='first'),query_task(base/'restored',3,operation_id='first'))
            path=base/'restored/snapshots.jsonl';rows=[json.loads(s) for s in path.read_text().splitlines()]
            rows[3]['analysis']['operations'][0]['response']['state']='success'
            path.write_bytes(b''.join(canonical(row)+b'\n' for row in rows))
            manifest=base/'restored/run_manifest.json';doc=json.loads(manifest.read_text())
            for row in doc['artifacts']:
                if row['path']=='snapshots.jsonl':row.update(sha256=file_hash(path),size_bytes=path.stat().st_size)
            manifest.write_bytes(canonical(doc)+b'\n')
            with self.assertRaisesRegex(ValueError,'replay_semantic_mismatch'):verify_task(base/'restored')

    def test_explicit_source_end_and_output_limits_fail_without_publication(self):
        for case in ('missing_eof','output_limit'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp);net,process,profile,config=fixture(base/'input')
                if case=='missing_eof':config['replay']['sequence']=[s for s in config['replay']['sequence'] if s.get('kind')!='source_eof']
                else:config['replay']['max_output_bytes']=1024
                profile.write_text(json.dumps(config))
                with self.assertRaises(ValueError):export_task(net,process,profile,base/'run')
                self.assertFalse((base/'run').exists())


if __name__=='__main__':unittest.main()
