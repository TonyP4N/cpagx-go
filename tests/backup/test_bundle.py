import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('backup_bundle',REPO/'scripts/backup/bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)
from cpag_core.pipeline import run,canonical,fingerprint


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'shared';self.root.mkdir()
        payload={}
        for role,src in [('network','tests/fixtures/synthetic/network.normalized.jsonl'),('process','tests/fixtures/synthetic/process.csv'),('profile','profiles/synthetic-demo.json')]:
            target=self.root/(role+Path(src).suffix);shutil.copyfile(REPO/src,target)
            payload[role]={'path':target.name,'sha256':bundle.sha(target)}
        out=self.root/'jobs/test/attempt-1'
        core=run(*(self.root/payload[k]['path'] for k in ('network','process','profile')),out,synthetic=True)
        payload['config_fingerprint']=core['config_fingerprint']
        self.row={'id':'test','state':'succeeded','payload':payload,'artifact_path':'jobs/test/attempt-1/manifest.json'}
        self.out=out;self.refresh()

    def refresh(self):
        core=json.loads((self.out/'run_manifest.json').read_text())
        for a in core['artifacts']:
            p=self.out/a['path'];a.update(sha256=bundle.sha(p),size_bytes=p.stat().st_size)
        core['result_hashes']={'events':fingerprint(json.loads((self.out/'events.json').read_text())),
                               'graph':fingerprint(json.loads((self.out/'graph.json').read_text()))}
        (self.out/'run_manifest.json').write_bytes(canonical(core)+b'\n')
        wrapper={'inputs':{k:self.row['payload'][k]['sha256'] for k in ('network','process','profile')},
                 'config_fingerprint':core['config_fingerprint'],'artifacts':[]}
        for name in ('dataset.json','events.json','graph.json','quality.json','run_manifest.json')+ (('packet_observations.json',) if (self.out/'packet_observations.json').exists() else ()):
            p=self.out/name;wrapper['artifacts'].append({'path':name,'sha256':bundle.sha(p),'size':p.stat().st_size})
        manifest=self.out/'manifest.json';manifest.write_text(json.dumps(wrapper))
        self.row['artifact_sha256']=bundle.sha(manifest)

    def test_original_records_graph_and_orphans(self):
        (self.root/'retained-orphan.log').write_text('diagnostic')
        result=bundle.audit([self.row],self.root)
        self.assertTrue(result['valid'],result)
        self.assertEqual(result['unreferenced_files'],['retained-orphan.log'])
        self.assertTrue((self.root/'retained-orphan.log').exists())

    def test_missing_and_tampered_files(self):
        p=self.out/'events.json';original=p.read_bytes();p.unlink()
        self.assertFalse(bundle.audit([self.row],self.root)['valid'])
        p.write_bytes(original+b' ')
        self.assertFalse(bundle.audit([self.row],self.root)['valid'])

    def test_rehashed_invalid_record_reference_rejected(self):
        p=self.out/'events.json';events=json.loads(p.read_text());events[0]['source_ref']['record_number']=999
        p.write_text(json.dumps(events));self.refresh()
        result=bundle.audit([self.row],self.root)
        self.assertFalse(result['valid']);self.assertIn('logical record',result['errors'][0]['reason'])

    def test_rehashed_graph_reference_rejected(self):
        p=self.out/'graph.json';graph=json.loads(p.read_text());graph['nodes'][0]['evidence_refs'][0]['raw_time']='wrong'
        p.write_text(json.dumps(graph));self.refresh()
        result=bundle.audit([self.row],self.root)
        self.assertFalse(result['valid']);self.assertIn('evidence differs',result['errors'][0]['reason'])

    def test_nonterminal_and_path_escape(self):
        row=copy.deepcopy(self.row);row['state']='running'
        self.assertFalse(bundle.audit([row],self.root)['valid'])
        row=copy.deepcopy(self.row);row['payload']['network']['path']='../escape'
        self.assertFalse(bundle.audit([row],self.root)['valid'])
        (self.root/'symlink').symlink_to(self.out/'events.json')
        with self.assertRaisesRegex(ValueError,'symlink'):bundle.inventory(self.root)

    def test_restore_tampering_reports_before_database_mutation(self):
        source=Path(self.tmp.name)/'bundle';source.mkdir();shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'synthetic fake dump, never executed')
        manifest={'format_version':2,'synthetic_validation_only':True,'rows':[self.row],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        (source/'files/network.jsonl').write_text('TAMPERED')
        dest=Path(self.tmp.name)/'restore'
        with patch.object(bundle.subprocess,'run') as call:
            with self.assertRaisesRegex(ValueError,'integrity'):bundle.restore('unused',source,dest)
            call.assert_not_called()
        report=json.loads((Path(str(dest)+'-audit.json')).read_text())
        self.assertFalse(report['valid']);self.assertEqual(report['phase'],'bundle_integrity')
        self.assertFalse(dest.exists())

    def test_restore_inventory_difference_is_failure_with_report(self):
        source=Path(self.tmp.name)/'bundle';source.mkdir();shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'fake dump, pg call mocked')
        manifest={'format_version':2,'synthetic_validation_only':True,'rows':[self.row],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        dest=Path(self.tmp.name)/'restore'
        original_copy=shutil.copytree
        def mutated_copy(src,target,*args,**kwargs):
            result=original_copy(src,target,*args,**kwargs)
            (Path(target)/'unexpected-file').write_text('simulated restore-time write')
            return result
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[self.row]),patch.object(bundle,'attempts_now',return_value=[]),\
             patch.object(bundle.shutil,'copytree',side_effect=mutated_copy):
            with self.assertRaisesRegex(ValueError,'inventory differs'):
                bundle.restore('unused',source,dest)
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid'])
        self.assertTrue((dest/'unexpected-file').exists())

    def make_packet(self):
        import sys
        sys.path.insert(0,str(REPO/'tests/packets'))
        from test_packet_envelope import pcap
        from test_packet_protocol import GET,REPLY,frame
        from cpag_core.packet_job import run as packet_run
        capture=self.root/'synthetic.pcap'
        capture.write_bytes(pcap(list(enumerate([frame(GET[20:],120),frame(GET[:20]),frame(GET[:20]),frame(REPLY,reverse=True)],1))))
        profile=self.root/'packet-profile.json';profile.write_text(json.dumps({'synthetic':True,'adapter':'synthetic-packet-1'}))
        payload=self.row['payload'];payload['kind']='packet'
        for role,path in [('network',capture),('profile',profile)]:payload[role]={'path':path.name,'sha256':bundle.sha(path)}
        shutil.rmtree(self.out)
        manifest=packet_run(capture,self.root/payload['process']['path'],profile,self.out,synthetic=True)
        payload['config_fingerprint']=manifest['config_fingerprint'];self.refresh()
        return capture

    def test_packet_full_refs_and_original_field_query(self):
        from cpag_core.packet_job import query_evidence
        capture=self.make_packet()
        result=bundle.audit([self.row],self.root)
        self.assertTrue(result['valid'],result)
        events=json.loads((self.out/'events.json').read_text())
        query=query_evidence(self.out,capture,events[0]['event_id'],'cip.path')
        self.assertEqual(len(query['node']['evidence_refs']),3)
        self.assertTrue(query['verified_fields']['cip.path'])

    def test_packet_rehashed_field_forgery_and_missing_capture(self):
        capture=self.make_packet()
        p=self.out/'packet_observations.json';side=json.loads(p.read_text())
        side['observations'][0]['fields']['cip.path']['hex']='ffffffffffff'
        p.write_text(json.dumps(side));self.refresh()
        report=bundle.audit([self.row],self.root)
        self.assertFalse(report['valid']);self.assertIn('original capture',report['errors'][0]['reason'])
        capture.unlink();report=bundle.audit([self.row],self.root)
        self.assertFalse(report['valid']);self.assertIn('missing file',report['errors'][0]['reason'])

    def test_attempt_snapshot_identity_publication_and_history_gaps(self):
        row={**self.row,'attempt':2,'worker':'worker-new','attempt_token':'synthetic-new'}
        history=[{'job_id':row['id'],'attempt':1,'worker':'worker-old','attempt_token':'synthetic-old','publication_state':'unpublished'},
                 {'job_id':row['id'],'attempt':2,'worker':'worker-new','attempt_token':'synthetic-new','publication_state':'published',
                  'artifact_path':row['artifact_path'],'artifact_sha256':row['artifact_sha256']}]
        self.assertTrue(bundle.audit_attempts([row],history)['valid'])
        self.assertFalse(bundle.audit_attempts([row],history[1:])['valid'])
        history[1]['attempt_token']='forged'
        result=bundle.audit_attempts([row],history)
        self.assertFalse(result['valid'])
        self.assertNotIn('synthetic-new',json.dumps(result));self.assertNotIn('forged',json.dumps(result))

    def mock_bundle(self):
        source=Path(self.tmp.name)/'bundle';source.mkdir();shutil.copytree(self.root,source/'files')
        (source/'database.dump').write_bytes(b'fake dump for injected database calls only')
        manifest={'format_version':2,'synthetic_validation_only':True,'rows':[self.row],'attempts':[],
                  'database_sha256':bundle.sha(source/'database.dump'),'files':bundle.inventory(source/'files')}
        (source/'bundle.json').write_text(json.dumps(manifest))
        return source,Path(self.tmp.name)/'restored'

    def test_missing_or_unreadable_tree_never_reports_valid(self):
        missing=self.root/'missing'
        report=bundle.audit([],missing)
        self.assertFalse(report['valid']);self.assertFalse(report['inventory_complete'])
        with self.assertRaises(ValueError):bundle.inventory(missing)
        with patch.object(bundle.os,'scandir',side_effect=PermissionError('injected denied subtree')):
            report=bundle.audit([],self.root)
        self.assertFalse(report['valid']);self.assertIn('denied',report['errors'][0]['reason'])

    def test_malformed_job_does_not_abort_later_valid_job_audit(self):
        report=bundle.audit([{'id':'malformed','state':'failed','payload':'not-object'},None,self.row],self.root)
        self.assertFalse(report['valid'])
        self.assertEqual([r['valid'] for r in report['jobs']],[False,False,True])
        self.assertIn(self.row['artifact_path'],report['referenced_files'])
        for state in ('failed','cancelled'):
            self.assertFalse(bundle.audit([{'id':'missing','state':state,'payload':{}}],self.root)['valid'])

    def test_malformed_history_does_not_abort_later_entries(self):
        row={**self.row,'attempt':1,'worker':'worker','attempt_token':'synthetic'}
        valid={'job_id':row['id'],'attempt':1,'worker':'worker','attempt_token':'synthetic','publication_state':'published',
               'artifact_path':row['artifact_path'],'artifact_sha256':row['artifact_sha256']}
        report=bundle.audit_attempts([None,row],[None,{'job_id':'missing'},valid])
        self.assertFalse(report['valid']);self.assertEqual(report['verified_attempt_count'],1)

    def test_restore_copy_capacity_and_truncation_fail_without_valid_marker(self):
        import errno
        source,dest=self.mock_bundle()
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle.shutil,'copytree',side_effect=OSError(errno.ENOSPC,'injected no space')):
            with self.assertRaises(OSError):bundle.restore('unused',source,dest)
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid']);self.assertEqual(report['phase'],'restore_files')
        Path(str(dest)+'-audit.json').unlink()
        original_copy=shutil.copytree
        def truncated_copy(src,target,*args,**kwargs):
            original_copy(src,target,*args,**kwargs)
            if Path(target).resolve()==dest.resolve():(Path(target)/self.row['artifact_path']).write_bytes(b'')
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[self.row]),patch.object(bundle,'attempts_now',return_value=[]),\
             patch.object(bundle.shutil,'copytree',side_effect=truncated_copy):
            with self.assertRaisesRegex(ValueError,'restored references invalid'):bundle.restore('unused',source,dest)
        self.assertFalse(json.loads(Path(str(dest)+'-audit.json').read_text())['valid'])

    def test_report_capacity_failure_leaves_reserved_invalid_report(self):
        import errno
        source,dest=self.mock_bundle()
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle.shutil,'copytree',side_effect=OSError(errno.ENOSPC,'injected copy full')),\
             patch.object(bundle,'write_report',side_effect=OSError(errno.ENOSPC,'injected report full')):
            with self.assertRaises(OSError):bundle.restore('unused',source,dest)
        report=json.loads(Path(str(dest)+'-audit.json').read_text())
        self.assertFalse(report['valid']);self.assertEqual(report['status'],'in_progress')

    def test_database_metadata_change_detected_and_repeat_cannot_flip_report(self):
        source,dest=self.mock_bundle();changed={**self.row,'state':'failed'}
        with patch.object(bundle.subprocess,'run'),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[changed]):
            with self.assertRaisesRegex(ValueError,'metadata differs'):bundle.restore('unused',source,dest)
        report_path=Path(str(dest)+'-audit.json');before=report_path.read_bytes()
        with patch.object(bundle.subprocess,'run') as call:
            with self.assertRaisesRegex(ValueError,'must be new'):bundle.restore('unused',source,dest)
            call.assert_not_called()
        self.assertEqual(report_path.read_bytes(),before)
        self.assertFalse(json.loads(before)['valid'])

    def test_concurrent_restore_cannot_overwrite_success_report(self):
        import threading
        source,dest=self.mock_bundle();entered=threading.Event();release=threading.Event();outcomes={}
        def createdb(*args,**kwargs):entered.set();self.assertTrue(release.wait(timeout=5))
        def first():
            try:outcomes['first']=bundle.restore('unused',source,dest)['valid']
            except Exception as error:outcomes['first']=type(error).__name__
        with patch.object(bundle.subprocess,'run',side_effect=createdb),patch.object(bundle,'pg'),\
             patch.object(bundle,'rows_now',return_value=[self.row]),patch.object(bundle,'attempts_now',return_value=[]):
            thread=threading.Thread(target=first);thread.start();self.assertTrue(entered.wait(timeout=5))
            try:
                with self.assertRaisesRegex(ValueError,'must be new'):bundle.restore('unused',source,dest)
            finally:release.set();thread.join(timeout=5)
            self.assertFalse(thread.is_alive());self.assertTrue(outcomes['first'],outcomes)
        report_path=Path(str(dest)+'-audit.json');before=report_path.read_bytes()
        self.assertTrue(json.loads(before)['valid'])
        with self.assertRaisesRegex(ValueError,'must be new'):bundle.restore('unused',source,dest)
        self.assertEqual(report_path.read_bytes(),before)

    def backup_connection(self):
        import io
        from unittest.mock import Mock
        connection=Mock();connection.stdin=io.StringIO()
        connection.stdout=io.StringIO('SNAPSHOT:mock\nROWS:'+json.dumps([self.row])+'\nATTEMPTS:[]\n')
        connection.poll.return_value=0
        return connection

    def test_source_change_before_copy_inventory_cannot_publish_inconsistent_bundle(self):
        original=bundle.inventory;calls=0
        def changed_inventory(root):
            nonlocal calls
            if Path(root).resolve()==self.root.resolve():
                calls+=1
                if calls==2:
                    p=self.root/self.row['payload']['network']['path'];p.write_bytes(p.read_bytes()+b' ')
            return original(root)
        destination=Path(self.tmp.name)/'snapshot-bundle'
        with patch.object(bundle.subprocess,'Popen',return_value=self.backup_connection()),\
             patch.object(bundle,'inventory',side_effect=changed_inventory),patch.object(bundle,'pg') as dump:
            with self.assertRaisesRegex(ValueError,'copied reference audit failed'):
                bundle.backup('mocked','m4_validation',self.root,destination)
            dump.assert_not_called()
        self.assertFalse((destination/'bundle.json').exists())
        report=json.loads((destination/'backup-failure.json').read_text())
        self.assertFalse(report['valid']);self.assertEqual(report['phase'],'copied_reference_audit')

    def test_dump_time_source_change_and_backup_capacity_cannot_publish(self):
        import errno
        destination=Path(self.tmp.name)/'snapshot-bundle'
        def changed_dump(*args,**kwargs):
            kwargs['stdout'].write(b'mocked dump')
            p=self.root/self.row['payload']['network']['path'];p.write_bytes(p.read_bytes()+b' ')
        with patch.object(bundle.subprocess,'Popen',return_value=self.backup_connection()),patch.object(bundle,'pg',side_effect=changed_dump):
            with self.assertRaisesRegex(ValueError,'during database dump'):
                bundle.backup('mocked','m4_validation',self.root,destination)
        self.assertFalse((destination/'bundle.json').exists())
        self.assertEqual(json.loads((destination/'backup-failure.json').read_text())['phase'],'final_integrity')
        # Restore source bytes before the independent injected capacity case.
        p=self.root/self.row['payload']['network']['path'];p.write_bytes(p.read_bytes()[:-1])
        destination2=Path(self.tmp.name)/'capacity-bundle'
        with patch.object(bundle.subprocess,'Popen',return_value=self.backup_connection()),\
             patch.object(bundle.shutil,'copytree',side_effect=OSError(errno.ENOSPC,'injected no space')):
            with self.assertRaises(OSError):bundle.backup('mocked','m4_validation',self.root,destination2)
        self.assertFalse((destination2/'bundle.json').exists())
        self.assertFalse(json.loads((destination2/'backup-failure.json').read_text())['valid'])

    def test_not_started_proof_is_bound_to_gated_execution_and_stays_revoked(self):
        row={**self.row,'state':'cancelled','attempt':1,'worker':'worker','attempt_token':'synthetic'}
        identity={'id':row['id'],'attempt':1,'worker':'worker','token':'synthetic','location':'docker:synthetic:scope'}
        attempt={'job_id':row['id'],'attempt':1,'worker':'worker','attempt_token':'synthetic','location':identity['location'],
                 'container_id':'','executor_kind':'isolated-v2','start_revoked_at':'2026-10-26T00:00:00Z',
                 'exited_at':'2026-10-26T00:00:00Z','publication_state':'fenced',
                 'exit_receipt':{**identity,'scope':'not-started','start_revoked':True}}
        self.assertTrue(bundle.audit_attempts([row],[attempt])['valid'])
        for key,value in [('executor_kind','legacy'),('start_revoked_at',None),('container_id','unexpected'),('location','docker:other'),('publication_state','published')]:
            changed=copy.deepcopy(attempt);changed[key]=value
            self.assertFalse(bundle.audit_attempts([row],[changed])['valid'],key)
        for key,value in [('start_revoked',False),('location','docker:other'),('token','wrong'),('scope','unknown')]:
            changed=copy.deepcopy(attempt);changed['exit_receipt'][key]=value
            self.assertFalse(bundle.audit_attempts([row],[changed])['valid'],key)
        # Host cleanup may later prove the pre-start orphan removed. It does not
        # clear start_revoked_at or grant this attempt permission to publish.
        cleanup=copy.deepcopy(attempt);cleanup['container_id']='synthetic-container'
        cleanup['exit_receipt']={**identity,'scope':'container','container_id':'synthetic-container','removed':True,'exited':True,
            'inspected_id':'synthetic-container','running':False,'pid':0,
            'labels':{'cpag.job':row['id'],'cpag.attempt':'1','cpag.worker':'worker'}}
        self.assertTrue(bundle.audit_attempts([row],[cleanup])['valid'])
        # An unregistered legacy orphan may receive a bound removal-only proof;
        # it remains revoked and cannot be mistaken for gated not-started proof.
        cleanup['executor_kind']='legacy'
        self.assertTrue(bundle.audit_attempts([row],[cleanup])['valid'])
        cleanup['exit_receipt']['labels']['cpag.job']='other'
        self.assertFalse(bundle.audit_attempts([row],[cleanup])['valid'])
