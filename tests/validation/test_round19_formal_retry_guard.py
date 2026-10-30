"""A formal measurement may not hide first-attempt failure behind retries."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_formal_service_acceptance import Harness


class FormalRetryGuardTests(unittest.TestCase):
    def test_first_observed_retry_is_cancelled_immediately_and_fails_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=Harness(SimpleNamespace(mode='s100',image='sha256:'+'a'*64,output=Path(directory)))
            harness.state={'run_ids':[]};harness.flush=Mock();harness.worker=SimpleNamespace(poll=lambda:None)
            harness.client=SimpleNamespace(expect=Mock(side_effect=[{'run':{'id':'fixed-run'}},{'run':{'state':'running','attempt':2,'attempt_history':[{'attempt':1,'publication_state':'fenced'}]}},{'run':{'state':'cancelling'}},{'run':{'state':'cancelled','attempt':2,'attempt_history':[{'attempt':1,'publication_state':'fenced'},{'attempt':2,'exited_at':'now','publication_state':'fenced'}]}}]))
            with self.assertRaisesRegex(RuntimeError,'first_attempt_failed_or_expired'):
                harness.submit_wait({'dataset_id':'dataset'},'s100-only')
            calls=harness.client.expect.call_args_list
            self.assertEqual(calls[2].args[:2],('POST','/api/v3/runs/fixed-run/cancel'))
            self.assertEqual(calls[-1].args[:2],('GET','/api/v3/runs/fixed-run'))
            row=harness.report['runs'][0]
            self.assertTrue(row['first_attempt_retried']);self.assertTrue(row['extra_attempt_cancel_requested'])
            self.assertEqual(row['attempt'],2)
            self.assertEqual(harness.report['status'],'failed')
            self.assertTrue(row['extra_attempt_cleanup']['terminal_observed'])
            self.assertEqual(row['extra_attempt_cleanup']['last_state'],'cancelled')
            self.assertEqual(row['attempt_history'],[{'attempt':1,'publication_state':'fenced'}])

    def test_unobserved_cancellation_stays_explicitly_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=Harness(SimpleNamespace(mode='s100',image='sha256:'+'a'*64,output=Path(directory)))
            harness.state={'run_ids':[]};harness.flush=Mock();harness.worker=SimpleNamespace(poll=lambda:None)
            harness.client=SimpleNamespace(expect=Mock(side_effect=[{'run':{'id':'fixed-run'}},{'run':{'state':'running','attempt':2,'attempt_history':[{'attempt':1,'publication_state':'fenced'}]}},{'run':{'state':'cancelling'}},TimeoutError('bounded status unavailable')]))
            with self.assertRaisesRegex(RuntimeError,'first_attempt_failed_or_expired'):
                harness.submit_wait({'dataset_id':'dataset'},'s100-only')
            row=harness.report['runs'][0];cleanup=row['extra_attempt_cleanup']
            self.assertTrue(row['extra_attempt_cancel_requested'])
            self.assertFalse(cleanup['terminal_observed'])
            self.assertEqual(cleanup['status'],'cancellation_observation_unavailable')
            self.assertIn('verify_extra_attempt_exit',cleanup['required_action'])
            self.assertEqual(harness.report['status'],'failed')


if __name__=='__main__':unittest.main()
