"""Formal compact Python artifact path; Worker/Go/reference performance are separate gates."""
import copy
import json
import io
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'services/analysis/src'),str(ROOT/'scripts/validation')]
from round18_profile import fixture
from cpag_core.replay_export import export_task,verify_task,snapshot_task,query_task,list_revisions,artifact_files_for_inputs,iter_verified_snapshots
from cpag_core.pipeline import canonical,file_hash
from cpag_core.replay_history import VERSION
from cpag_core.replay_spool_cli import action
from cpag_core.dual_source_rules import validate_profile


class SpoolExportTests(unittest.TestCase):
    def build(self,root,*,spool=True,capacity=False,future=False):
        n,p,c,config=fixture(root/'inputs')
        if future:
            raw=bytearray(n[1].read_bytes());raw[-2]=5;n[1].write_bytes(raw)
            p.write_text(p.read_text().replace(',1\n',',2\n'))
        if spool:config['replay']['history_format']=VERSION
        if capacity:config['capacity_profile']='engineering-capacity-1'
        c.write_text(json.dumps(config))
        manifest=export_task(n,p,c,root/'out',run_id='formal-test',attempt_id=2)
        return n,p,c,config,manifest

    def test_new_inventory_and_full_json_business_equivalence_with_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,_,_,_,old=self.build(root/'old',spool=False)
            _,_,_,_,new=self.build(root/'new')
            self.assertEqual(new['semantic_config_fingerprint'],old['semantic_config_fingerprint'])
            old_rows=list(iter_verified_snapshots(root/'old/out'))
            new_rows=list(iter_verified_snapshots(root/'new/out'))
            self.assertEqual(new_rows,json.loads(canonical(old_rows)))
            self.assertEqual(list_revisions(root/'new/out'),list_revisions(root/'old/out'))
            expected=artifact_files_for_inputs(2,history_format=VERSION)
            self.assertEqual({p.relative_to(root/'new/out').as_posix() for p in (root/'new/out').rglob('*') if p.is_file()},expected)
            self.assertFalse((root/'new/out/snapshots.jsonl').exists())
            self.assertEqual(query_task(root/'new/out',3,operation_id='first'),query_task(root/'old/out',3,operation_id='first'))
            for name in ('analysis.json','events.json','graph.json','quality.json','metrics.json','arrivals.jsonl'):
                self.assertEqual((root/'new/out'/name).read_bytes(),(root/'old/out'/name).read_bytes())

    def test_cli_verified_identity_bounded_queries_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,_,_,_,manifest=self.build(root)
            restored=root/'restored';shutil.copytree(root/'out',restored)
            self.assertEqual(verify_task(restored),manifest)
            args=[sys.executable,'-m','cpag_core.replay_spool_cli','--root',str(restored)]
            import os
            env=dict(os.environ,PYTHONPATH=str(ROOT/'services/analysis/src'))
            for command in (['--action','verify'],['--action','metadata'],['--action','snapshot','--snapshot','3'],
                            ['--action','revisions','--limit','2'],['--action','graph','--snapshot','3'],
                            ['--action','evidence','--snapshot','3','--operation','first'],
                            ['--action','evidence','--snapshot','3','--trigger']):
                result=subprocess.run(args+command,capture_output=True,env=env)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                value=json.loads(result.stdout)
                if command==['--action','verify']:
                    self.assertEqual(value['verification'],'source_replayed_storage_and_business_fields_verified')
                    self.assertEqual(value['manifest'],manifest)
                if '--operation' in command:self.assertEqual(len(value['verified_original_evidence']),1)
            bad=subprocess.run(args+['--action','evidence','--snapshot','3','--trigger','--operation','first'],capture_output=True,env=env)
            self.assertNotEqual(bad.returncode,0)
            self.assertEqual(bad.stdout,b'')
            from cpag_core.replay_spool_cli import main
            stdout,stderr=io.StringIO(),io.StringIO()
            with patch('cpag_core.replay_spool_cli.LIMIT',1),patch.object(sys,'argv',['bridge','--root',str(restored),'--action','snapshot','--snapshot','3']),redirect_stdout(stdout),redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as rejected:main()
            self.assertEqual(rejected.exception.code,2)
            self.assertEqual(stdout.getvalue(),'')
            self.assertIn('output_limit',stderr.getvalue())

    def test_cli_evidence_pages_preserve_selection_and_verify_only_page_originals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.build(root)
            full=action(root/'out','evidence',snapshot=6,operation='first')
            self.assertEqual(full['evidence_page']['total'],4)
            self.assertEqual(len(full['selection']['changes']),1)
            rows=[]
            for offset in range(4):
                page=action(root/'out','evidence',snapshot=6,operation='first',ref_offset=offset,ref_limit=1)
                self.assertEqual(page['selection'],full['selection'])
                self.assertEqual(page['snapshot_id'],full['snapshot_id'])
                self.assertEqual(page['quality'],full['quality'])
                self.assertEqual(page['evidence_page']['returned'],1)
                rows+=page['verified_original_evidence']
                allowed={(row['source_ref']['source_slot'],row['source_ref']['frame_number']) for row in page['verified_original_evidence']}
                for event in page['verified_network_fields']:
                    for pieces in event['fields'].values():
                        for piece in pieces:self.assertIn((piece['field']['source_ref']['source_slot'],piece['field']['source_ref']['frame_number']),allowed)
            self.assertEqual(rows,full['verified_original_evidence'])
            empty=action(root/'out','evidence',snapshot=6,operation='first',ref_offset=999,ref_limit=1)
            self.assertEqual(empty['verified_original_evidence'],[])
            self.assertFalse(empty['evidence_page']['has_more'])
            for offset,limit in ((-1,1),(0,0),(0,101)):
                with self.assertRaises(ValueError):action(root/'out','evidence',snapshot=6,operation='first',ref_offset=offset,ref_limit=limit)

    def test_prefix_is_unchanged_when_future_bytes_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.build(root/'a');self.build(root/'b',future=True)
            for number in range(4):self.assertEqual(snapshot_task(root/'a/out',number),snapshot_task(root/'b/out',number))
            self.assertEqual(query_task(root/'a/out',3,operation_id='first'),query_task(root/'b/out',3,operation_id='first'))

    def test_capacity_requires_explicit_new_history_and_old_budget_stays_clamped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);_,_,c,config,_=self.build(root)
            from cpag_core.replay_core import ReplayCore
            with self.assertRaisesRegex(ValueError,'sink_required'):ReplayCore(config)
            larger=copy.deepcopy(config);larger['replay']['max_snapshots']=45000
            with self.assertRaisesRegex(ValueError,'budget_exceeds'):
                validate_profile(larger)
            larger['capacity_profile']='engineering-capacity-1';validate_profile(larger)
            del larger['replay']['history_format']
            with self.assertRaises(ValueError):validate_profile(larger)
            _,_,_,cfg,manifest=self.build(root/'engineering',capacity=True)
            self.assertEqual(manifest['capacity_profile'],'engineering-capacity-1')
            self.assertEqual(verify_task(root/'engineering/out'),manifest)

    def test_declared_total_output_budget_reserves_control_metadata_and_rejects_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            n,p,c,config=fixture(root/'inputs')
            config['replay']['history_format']=VERSION
            config['replay']['max_output_bytes']=256*1024
            c.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError,'insufficient_history_storage_budget'):
                export_task(n,p,c,root/'rejected',run_id='budget',attempt_id=1)
            self.assertFalse((root/'rejected').exists())
            _,_,_,cfg,manifest=self.build(root/'valid')
            history=json.loads((root/'valid/out/history/manifest.json').read_text())
            retained=sum(path.stat().st_size for path in (root/'valid/out/sources').iterdir())
            # One bounded 64KiB history manifest and one bounded 64KiB outer
            # run manifest are reserved before the indexed database can grow.
            self.assertEqual(history['limits']['max_bytes'],cfg['replay']['max_output_bytes']-retained-2*65536)
            self.assertEqual(history['limits']['max_working_bytes'],3*history['limits']['max_bytes'])
            self.assertLessEqual(sum(path.stat().st_size for path in (root/'valid/out').rglob('*') if path.is_file()),cfg['replay']['max_output_bytes'])
            import sqlite3
            failure=sqlite3.OperationalError('injected storage full');failure.sqlite_errorname='SQLITE_FULL'
            config['replay']['max_output_bytes']=16*1024*1024;c.write_text(json.dumps(config))
            with patch('cpag_core.replay_spool_export._sink',side_effect=failure):
                with self.assertRaisesRegex(ValueError,'history_sqlite_write_failed:SQLITE_FULL'):
                    export_task(n,p,c,root/'sqlite-failed',run_id='budget',attempt_id=1)
            self.assertFalse((root/'sqlite-failed').exists())

    def test_tamper_missing_old_attempt_and_self_rehashed_business_rejected(self):
        for mode in ('source','history','missing','attempt','business'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.build(root);out=root/'out'
                if mode=='source':(out/'sources/process.csv').write_text('changed')
                if mode=='history':
                    with (out/'history/history.sqlite3').open('ab') as f:f.write(b'x')
                if mode=='missing':(out/'history/manifest.json').unlink()
                if mode in ('attempt','business'):
                    manifest=json.loads((out/'run_manifest.json').read_text())
                    if mode=='attempt':manifest['attempt_id']=3
                    else:
                        path=out/'analysis.json';value=json.loads(path.read_text());value['operations'][0]['response']['state']='invented';path.write_bytes(canonical(value)+b'\n')
                        for entry in manifest['artifacts']:
                            if entry['path']=='analysis.json':entry.update(sha256=file_hash(path),size_bytes=path.stat().st_size)
                    (out/'run_manifest.json').write_bytes(canonical(manifest)+b'\n')
                with self.assertRaises((ValueError,FileNotFoundError)):
                    verify_task(out)


if __name__=='__main__':unittest.main()
