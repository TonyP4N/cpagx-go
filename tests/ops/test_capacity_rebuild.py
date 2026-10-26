import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cpag_worker.capacity_rebuild import CapacityRebuilder, RebuildRefused

class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        base=Path(self.temp.name);self.root=base/'shared';self.control=base/'control';self.root.mkdir();self.control.mkdir()
        (self.root/'inputs').mkdir();self.base=self.control/'jobs'/'job'/'attempt-1.worker';self.base.mkdir(parents=True)
        (self.base/'exit.json').write_text('{}');output=self.root/'jobs'/'job'/'attempt-1';output.mkdir(parents=True);(output/'result').write_text('synthetic')
        self.status={'id':'job','state':'cancelled','attempt':1,'lease_valid':False,'payload':{},'attempt_history':[{'attempt':1,'exited_at':'2026-10-26','executor':'isolated-v2','publication_state':'fenced'}]}
        self.tool=CapacityRebuilder(self.root,self.control,status_reader=lambda _:self.status,discovery_reader=lambda:[])
    def ledger(self,value): (self.control/'capacity.json').write_text(json.dumps(value))
    def test_missing_and_corrupt_rebuild_backup(self):
        for initial in (None,b'{broken'):
            if self.tool.path.exists():self.tool.path.unlink()
            if initial is not None:self.tool.path.write_bytes(initial)
            plan=self.tool.preview();self.assertTrue(plan['applicable']);result=self.tool.apply(plan,plan['plan_id']);self.assertTrue(result['applied'])
            backup=Path(result['backup']);self.assertTrue((backup/'manifest.json').exists())
            self.assertEqual((backup/'capacity.original').read_bytes() if initial else None,initial)
            self.assertEqual(json.loads(self.tool.path.read_text()),plan['proposed_ledger'])
    def test_terminal_release_and_active_never_release(self):
        self.ledger({'root':str(self.root.resolve()),'reservations':{'job:1':123456789,'__existing__':0}})
        closed=self.tool.preview();self.assertLess(closed['proposed_ledger']['reservations']['job:1'],123456789)
        self.status['state']='running';self.status['attempt_history'][0]['exited_at']=None
        active=self.tool.preview();self.assertGreaterEqual(active['proposed_ledger']['reservations']['job:1'],123456789)
        with self.assertRaises(RebuildRefused):self.tool.apply(closed,closed['plan_id'])
    def test_missing_ledger_active_and_api_unknown_block(self):
        self.status['state']='running';self.status['attempt_history'][0]['exited_at']=None
        plan=self.tool.preview();self.assertFalse(plan['applicable'])
        with self.assertRaises(RebuildRefused):self.tool.apply(plan,plan['plan_id'])
        with patch.object(self.tool,'status_reader',side_effect=OSError('offline')):
            plan=self.tool.preview();self.assertFalse(plan['applicable'])
    def test_owner_and_capacity_lock_contention(self):
        for path in (self.base/'owner.lock',self.control/'capacity.lock'):
            with path.open('a+') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(RebuildRefused):self.tool.preview()
    def test_stale_files_and_confirmation(self):
        plan=self.tool.preview()
        with self.assertRaises(RebuildRefused):self.tool.apply(plan,'yes')
        (self.base/'failure.json').write_text('new evidence')
        with self.assertRaises(RebuildRefused):self.tool.apply(plan,plan['plan_id'])
        self.assertFalse(self.tool.path.exists())
    def test_symlinks_and_foreign_ledger_rejected(self):
        bad=self.base/'bad';bad.symlink_to('/etc/hosts')
        with self.assertRaises(RebuildRefused):self.tool.preview()
        bad.unlink();self.ledger({'root':'/other-root','reservations':{}})
        with self.assertRaises(RebuildRefused):self.tool.preview()
    def test_unknown_attempt_reservation_not_freed(self):
        self.ledger({'root':str(self.root.resolve()),'reservations':{'other:3':99999999}})
        plan=self.tool.preview();self.assertIn('other:3',plan['unknown_attempts']);self.assertGreaterEqual(plan['proposed_ledger']['reservations']['other:3'],99999999)
        with self.assertRaises(RebuildRefused):self.tool.apply(plan,plan['plan_id'])


class DiscoveryRegressions(unittest.TestCase):
    setUp=CapacityTests.setUp
    ledger=CapacityTests.ledger
    def test_database_only_active_attempt_is_not_omitted(self):
        import shutil
        shutil.rmtree(self.control/'jobs');shutil.rmtree(self.root/'jobs')
        self.status['state']='running';self.status['attempt_history'][0]['exited_at']=None
        self.ledger({'root':str(self.root.resolve()),'reservations':{'__existing__':99999999}})
        with patch.object(self.tool,'_discover',create=True,return_value=[{'id':'job','attempt':1,'location':'docker:test','container_id':'a'*64,'executor':'isolated-v2'}]):
            plan=self.tool.preview()
        self.assertIn('job:1',plan['proposed_ledger']['reservations'])
        self.assertGreaterEqual(plan['proposed_ledger']['reservations']['__existing__'],99999999)
    def test_scan_walk_errors_are_not_silently_ignored(self):
        original=__import__('os').walk
        def failing_walk(top,**options):
            if 'onerror' in options:options['onerror'](PermissionError('unreadable subtree'))
            yield from original(top,**options)
        with patch('cpag_worker.capacity_rebuild.os.walk',side_effect=failing_walk):
            with self.assertRaises(PermissionError):self.tool.preview()
    def test_executor_compatible_identifier(self):
        from cpag_worker.capacity_rebuild import JOB,KEY
        identifier='a.'+'x'*126
        self.assertIsNotNone(JOB.fullmatch(identifier));self.assertIsNotNone(KEY.fullmatch(identifier+':1'))

    def test_safe_non_inputs_source_reference(self):
        import hashlib
        target=self.root/'samples';target.mkdir();payload={}
        for role in ('network','process','profile'):
            value=role.encode();path=target/role;path.write_bytes(value);payload[role]={'path':'samples/'+role,'sha256':hashlib.sha256(value).hexdigest()}
        self.status.update(state='running',payload=payload);self.status['attempt_history'][0]['exited_at']=None
        self.ledger({'root':str(self.root.resolve()),'reservations':{'job:1':99999999}})
        self.assertTrue(self.tool.preview()['applicable'])

if __name__=='__main__':unittest.main()
