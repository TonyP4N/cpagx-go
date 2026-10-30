"""The old backup engine explicitly refuses unproven shared restore formats."""
import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('shared_refusal_bundle', ROOT / 'scripts/backup/bundle.py')
bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)


class SharedBackupRefusalTests(unittest.TestCase):
    def test_dag6_markers_refuse_even_before_succeeded_publication(self):
        for marker in ({'storage_format': 'shared-observation-dag-6'},
                       {'resource_profile': 'engineering-core-capacity-3'},
                       {'capacity_profile': 'engineering-core-capacity-3'},
                       {'history_format': 'shared-observation-dag-6'},
                       {'storage_budget_version': 'shared-storage-budget-2'}):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'unsupported_shared_backup_restore'):
                bundle.audit_dual({'payload': marker, 'state': 'failed'}, Path('/unused'), None)
        with self.assertRaisesRegex(ValueError, 'unsupported_shared_backup_restore'):
            bundle.reject_unproven_shared_backup({}, {'replay': {'history_format': 'shared-observation-dag-6'}})

    def test_old_payload_remains_accepted_by_guard(self):
        self.assertIsNone(bundle.reject_unproven_shared_backup({'resource_profile': 'engineering-capacity-1'}))
        self.assertIsNone(bundle.reject_unproven_shared_backup({'history_format': 'replay-history-checkpoint-delta-2'}))


if __name__ == '__main__': unittest.main()
