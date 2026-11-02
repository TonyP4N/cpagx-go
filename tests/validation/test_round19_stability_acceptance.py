"""Short stability guards; no PostgreSQL, Docker or S100 execution."""
from copy import deepcopy
from pathlib import Path
import sys
import plistlib
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'scripts/validation'), str(REPO / 'services/analysis/src')]
import round19_stability_acceptance as stability
from round19_core_small import inputs
from cpag_core import shared_export as core


class StabilityAcceptanceTests(unittest.TestCase):
    def test_complete_small_roots_equal_across_independent_run_and_attempt_contexts(self):
        for mode, case in [('offline', 'success'), ('replay', 'normal')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                networks, process, profile, _ = inputs(root / 'inputs', case, mode)
                first = core.export_task(networks, process, profile, root / 'one', run_id='independent-one', attempt_id=1, mode=mode)
                second = core.export_task(networks, process, profile, root / 'two', run_id='independent-two', attempt_id=2, mode=mode)
                a, b = stability.business_signature(first), stability.business_signature(second)
                self.assertNotEqual(a['original_identity'], b['original_identity'])
                self.assertEqual(a['sha256'], b['sha256'])
                self.assertEqual(a['value'], b['value'])
                self.assertEqual(len(a['value']['complete_business_roots']), 11 if mode == 'offline' else 16)
                self.assertEqual(stability.POLICY['business_fields_removed_or_normalized'], [])
                altered = deepcopy(second)
                root_descriptor = next(row for row in altered['logical_artifacts'] if row['name'] == 'quality.json')
                root_descriptor['digest'] = 'a' * 64
                self.assertNotEqual(stability.business_signature(altered)['sha256'], a['sha256'])
                if mode == 'replay':
                    telemetry = deepcopy(second)
                    next(row for row in telemetry['logical_artifacts'] if row['name'] == 'runtime_metrics.json')['digest'] = 'b' * 64
                    self.assertEqual(stability.business_signature(telemetry)['sha256'], a['sha256'])
                    self.assertNotEqual(stability.business_signature(telemetry)['retained_telemetry_descriptors'], a['retained_telemetry_descriptors'])
                duplicate = deepcopy(first)
                duplicate['logical_artifacts'].append(deepcopy(duplicate['logical_artifacts'][0]))
                with self.assertRaisesRegex(ValueError, 'inventory_changed'):
                    stability.business_signature(duplicate)

    def test_three_groups_are_exactly_six_serial_first_attempt_cells(self):
        state = {'status': 'ready', 'groups': []}
        calls = []
        def execute(group, mode):
            calls.append((group, mode))
            return {'status': 'passed', 'attempt': 1, 'signature': {'sha256': mode, 'value': {'all_business': mode}}}
        stability.run_groups(state, [1, 2, 3], execute, lambda: None)
        self.assertEqual(calls, [(group, mode) for group in (1, 2, 3) for mode in ('offline', 'replay')])
        self.assertEqual(state['status'], 'passed')
        with self.assertRaisesRegex(ValueError, 'cannot_resume'):
            stability.run_groups(state, [3], execute, lambda: None)

    def test_failure_clock_invalidity_retry_or_business_change_stops_before_next_cell(self):
        for kind in ('failure', 'invalid_environment', 'retry', 'business_change'):
            with self.subTest(kind=kind):
                state = {'status': 'ready', 'groups': []}
                calls = []
                def execute(group, mode):
                    calls.append((group, mode))
                    if (group, mode) == (2, 'offline'):
                        if kind == 'failure':
                            raise RuntimeError('bounded_failure')
                        if kind == 'invalid_environment':
                            raise stability.formal.InvalidEnvironment('clock_gap')
                        if kind == 'retry':
                            return {'status': 'passed', 'attempt': 2, 'signature': {'sha256': mode, 'value': mode}}
                        return {'status': 'passed', 'attempt': 1, 'signature': {'sha256': 'changed', 'value': mode}}
                    return {'status': 'passed', 'attempt': 1, 'signature': {'sha256': mode, 'value': mode}}
                with self.assertRaises((RuntimeError, ValueError)):
                    stability.run_groups(state, [1, 2, 3], execute, lambda: None)
                self.assertEqual(calls[-1], (2, 'offline'))
                self.assertEqual(len(calls), 3)
                self.assertEqual(state['status'], 'invalid_environment' if kind == 'invalid_environment' else 'failed')
                with self.assertRaisesRegex(ValueError, 'cannot_resume'):
                    stability.run_groups(state, [2], execute, lambda: None)

    def test_out_of_order_group_never_starts_and_frozen_binary_mismatch_refused(self):
        state = {'status': 'ready', 'groups': []}
        with self.assertRaisesRegex(ValueError, 'once_in_order'):
            stability.run_groups(state, [2], lambda *_: self.fail('out-of-order cell started'), lambda: None)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'build').mkdir()
            (root / 'build/cpagx-v3').write_bytes(b'changed-build')
            args = stability.SimpleNamespace(output=root, image='image', fixture=root)
            lock = {'version': {'fixed': 'version'}, 'binary_sha256': {'cpagx-v3': 'a' * 64}}
            with patch.object(stability, 'version_lock', return_value=lock['version']):
                with self.assertRaisesRegex(ValueError, 'binary_changed'):
                    stability.check_freeze(args, lock)

    def test_registered_offline_range_and_explicit_replay_counts(self):
        frozen = {'offline_expected': {'network': 200, 'process': 100, 'operations': 100, 'changes': 99,
                                      'candidate_lower_bound': 2594, 'candidate_upper_bound': 2596}}
        counts = {'network': 200, 'process': 100, 'operations': 100, 'changes': 99,
                  'candidates': 2594, 'snapshots': 0, 'revisions': 0}
        stability.expected_counts({'mode': 'offline', 'counts': counts}, frozen)
        with self.assertRaisesRegex(ValueError, 'offline_registered'):
            stability.expected_counts({'mode': 'offline', 'counts': dict(counts, candidates=2593)}, frozen)
        stability.expected_counts({'mode': 'replay', 'counts': dict(counts, candidates=2596, snapshots=310, revisions=306)}, frozen)
        with self.assertRaisesRegex(ValueError, 'replay_counts'):
            stability.expected_counts({'mode': 'replay', 'counts': dict(counts, snapshots=310, revisions=306)}, frozen)

    def test_power_requires_both_AC_and_observable_open_lid_without_permanent_changes(self):
        with patch.object(stability.platform, 'system', return_value='Darwin'):
            for ac, external, lid in [("Now drawing from 'Battery Power'", True, '"AppleClamshellState" = No'),
                            ("Now drawing from 'AC Power'", False, '"AppleClamshellState" = No'),
                            ("Now drawing from 'AC Power'", True, '"AppleClamshellState" = Yes'),
                            ("Now drawing from 'AC Power'", True, '')]:
                smart = plistlib.dumps([{'ExternalConnected': external, 'IsCharging': False, 'Amperage': -840, 'Serial': 'never-retain-me'}])
                with self.subTest(ac=ac, external=external, lid=lid), patch.object(stability.subprocess, 'check_output', side_effect=[ac, smart, lid]):
                    with self.assertRaises(stability.formal.InvalidEnvironment):
                        stability.power_state()
            smart = plistlib.dumps([{'ExternalConnected': True, 'IsCharging': False, 'Amperage': -840, 'Serial': 'never-retain-me'}])
            with patch.object(stability.subprocess, 'check_output', side_effect=["Now drawing from 'AC Power'", smart, '"AppleClamshellState" = No']):
                observed = stability.power_state()
                self.assertEqual(observed['status'], 'AC_power_open_lid_observed')
                self.assertIs(observed['IsCharging'], False)
                self.assertEqual(observed['Amperage'], -840)
                self.assertNotIn('Serial', observed)

    def test_global_serial_slot_denies_second_runner_and_releases_after_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / 'global.lock'
            with stability.serial_slot(lock):
                with self.assertRaisesRegex(ValueError, 'global_serial_slot'):
                    with stability.serial_slot(lock):
                        self.fail('second runner acquired exclusive slot')
            with stability.serial_slot(lock):
                pass

    def test_tiny_preflight_power_exception_is_explicit_and_does_not_authorize_long(self):
        error = stability.formal.InvalidEnvironment('power_not_ready')
        error.power_observation = {'ExternalConnected': False, 'IsCharging': False, 'Amperage': -840}
        with patch.object(stability, 'power_state', side_effect=error), patch.object(stability.platform, 'system', return_value='Linux'):
            with stability.awake(long_eligible=False) as observed:
                self.assertEqual(observed['status'], 'tiny_preflight_only_power_not_long_eligible')
                self.assertFalse(observed['ExternalConnected'])
            with self.assertRaises(stability.formal.InvalidEnvironment):
                with stability.awake(long_eligible=True):
                    self.fail('long measurement proceeded without power')


if __name__ == '__main__':
    unittest.main()
