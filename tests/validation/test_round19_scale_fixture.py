"""Raw density fixture controls independent of analysis output and labels."""
import csv
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/validation'), str(ROOT / 'services/analysis/src')]
from round19_scale_fixture import generate
from round19_capacity import read_case
from cpag_core.dual_source_rules import validate_profile


class ScaleFixtureTests(unittest.TestCase):
    def test_all_scales_preserve_raw_request_response_and_csv_density(self):
        with tempfile.TemporaryDirectory() as directory:
            for scale, count in [('S', 100), ('M', 1000), ('L', 10000)]:
                with self.subTest(scale=scale):
                    root = Path(directory) / scale; report = generate(root, scale)
                    data = (root / 'network.pcap').read_bytes(); position = 24; frames = []
                    while position < len(data):
                        _, _, captured, original = struct.unpack_from('<IIII', data, position)
                        self.assertEqual(captured, original)
                        frames.append(data[position + 16:position + 16 + captured]); position += 16 + captured
                    self.assertEqual(position, len(data)); self.assertEqual(len(frames), 2 * count)
                    # CIP service literal starts after Ethernet/IP/TCP + ENIP/CPF.
                    self.assertEqual(sum(frame[94] == 0x10 for frame in frames), count)
                    self.assertEqual(sum(frame[94] == 0x90 for frame in frames), count)
                    with (root / 'process.csv').open(newline='') as stream:
                        self.assertEqual(sum(1 for _ in csv.reader(stream)) - 1, count)
                    config = json.loads((root / 'replay-profile.json').read_text())
                    validate_profile(config)
                    sequence = config['replay']['sequence']
                    self.assertEqual(len(sequence), 3 * count + 4)
                    for slot, expected in [('network-0', 2 * count), ('process', count + 1)]:
                        records = [row['record_number'] for row in sequence if row.get('source_slot') == slot and 'record_number' in row]
                        self.assertEqual(records, list(range(1, expected + 1)))
                    self.assertEqual(read_case(root / 'dual_source-1.json')['input_logical_records'], count)
                    self.assertEqual(report['arrival_steps'], 3 * count + 4)
                    self.assertFalse(config['replay']['realtime'])

    def test_existing_fixture_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'; generate(root, 'S')
            original = (root / 'network.pcap').read_bytes()
            with self.assertRaises(FileExistsError): generate(root, 'S')
            self.assertEqual((root / 'network.pcap').read_bytes(), original)



class CapacityDensityFixtureTests(unittest.TestCase):
    def test_explicit_version_preserves_raw_and_emits_bound_formal_matrix(self):
        from round19_scale_fixture import CAPACITY_VERSION, RAW_SHA256, read_preflight, density_budget_math
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            for scale,count in (('S',100),('M',1000),('L',10000)):
                with self.subTest(scale=scale):
                    root=Path(directory)/scale;report=generate(root,scale,version=CAPACITY_VERSION)
                    self.assertEqual(report['schema_version'],CAPACITY_VERSION)
                    for name,sha in RAW_SHA256[scale].items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),sha)
                    matrix=json.loads((root/'matrix.json').read_text())
                    self.assertEqual(len(matrix['rows']),6)
                    for row in matrix['rows']:
                        case=root/row['case_manifest'];details=read_preflight(case)
                        self.assertEqual(read_case(case)['input_logical_records'],count)
                        self.assertEqual(details['config_fingerprint'],json.loads((root/'preflight.json').read_text())['modes'][row['mode']]['config_fingerprint'])
                        profile=json.loads((root/details['profile']).read_text())
                        validate_profile(profile)
                        self.assertEqual(profile['capacity_profile'],'engineering-capacity-1')
                        self.assertEqual(profile['window_seconds'],5)
                        self.assertEqual(profile['max_sample_gap_seconds'],3)
                        if row['mode']=='dual_source_replay':
                            self.assertEqual(profile['replay']['history_format'],'replay-history-checkpoint-delta-2')
                            self.assertEqual(len(profile['replay']['sequence']),3*count+4)
                            self.assertEqual(profile['replay']['buffer_seconds'],300)
                            self.assertEqual(profile['replay']['allowed_lateness_seconds'],2)
                        if scale=='S':self.assertEqual(details['status'],'admissible_for_formal_attempt')
                        else:
                            self.assertEqual(details['status'],'blocked_budget_design')
                            self.assertIn('flat_output_lower_bound_exceeds_budget',[issue['code'] for issue in details['issues']])
                        if scale=='L':self.assertIn('candidate_lower_bound_exceeds_budget',[issue['code'] for issue in details['issues']])
                    if scale=='L':
                        replay=read_preflight(root/'dual_source_replay-1.json')
                        self.assertIn('snapshot_coverage_not_proven',[issue['code'] for issue in replay['issues']])
                    self.assertEqual(density_budget_math(scale)['changes'],count-1)

    def test_shared_capacity_matrix_preserves_density_without_claiming_physical_fit(self):
        from round19_scale_fixture import SHARED_VERSION, RAW_SHA256, read_preflight
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            for scale,count in (('S',100),('M',1000),('L',10000)):
                root=Path(directory)/scale;generate(root,scale,version=SHARED_VERSION)
                for name,digest in RAW_SHA256[scale].items():
                    self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest)
                matrix=json.loads((root/'matrix.json').read_text())
                self.assertEqual(matrix['operator_resource_profile'],'engineering-capacity-2')
                self.assertEqual(len(matrix['rows']),6)
                for mode in ('dual_source','dual_source_replay'):
                    result=read_preflight(root/(mode+'-1.json'))
                    self.assertEqual(result['status'],'admissible_for_formal_attempt')
                    self.assertEqual(result['physical_fit'],'unverified_until_complete_formal_run')
                    self.assertEqual(result['capacity_profile'],'engineering-capacity-2')
                    self.assertEqual(result['storage_budget']['physical_bytes'],1024**3)
                    self.assertEqual(result['density_math']['operations'],count)
                    cfg=json.loads((root/result['profile']).read_text());validate_profile(cfg)
                    self.assertEqual(cfg['storage_format'],'shared-observation-dag-5')
                    self.assertEqual(cfg['window_seconds'],5)
                    if mode=='dual_source_replay':
                        self.assertEqual(len(cfg['replay']['sequence']),3*count+4)
                        self.assertEqual(cfg['replay']['buffer_seconds'],300)
                        self.assertEqual(cfg['replay']['max_snapshots'],65000)
                # No fallback to the old admission mode after marker deletion.
                (root/'preflight.json').unlink()
                with self.assertRaisesRegex(ValueError,'preflight_missing'):
                    read_preflight(root/'dual_source-1.json')

    def test_legacy_default_profiles_and_raw_remain_byte_identical(self):
        from round19_scale_fixture import read_preflight
        import hashlib
        expected={
            'S':('7ca402c94d4f68b4f5a8d9b269b32df4857ccb9622dc2e70332a1e5cd655deb3'),
            'M':('9e6bdc2aec84b433cd7b02509b2dab947a6b71560c0bc50d9b1e9b709a01693a'),
            'L':('d22a215bf5080948f4943b34c639f7a902f5de9d7b8366019288d0998f06ef7b')}
        with tempfile.TemporaryDirectory() as directory:
            for scale in expected:
                root=Path(directory)/scale;generate(root,scale)
                self.assertEqual(hashlib.sha256((root/'replay-profile.json').read_bytes()).hexdigest(),expected[scale])
                self.assertEqual(hashlib.sha256((root/'offline-profile.json').read_bytes()).hexdigest(),'ea1b146bbdbf947aa8a07ed9a58fabad75d33b1cebbd5ed0ad1cd8c796291281')
                self.assertIsNone(read_preflight(root/'dual_source-1.json'))
                with self.assertRaisesRegex(ValueError,'missing'):read_preflight(root/'dual_source-1.json',require_new=True)

    def test_independent_interval_arithmetic_and_required_flat_bytes(self):
        from round19_scale_fixture import density_budget_math
        expected={'S':(2594,2596,70576,125879300,75527580,304,308,612),
                  'M':(31751,31813,1008000,1795907870,1077544722,3004,3008,6012),
                  'L':(317500,318125,10080000,17959075000,10775445000,30004,30008,60012)}
        for scale,row in expected.items():
            actual=density_budget_math(scale)
            self.assertEqual(tuple(actual[key] for key in ('candidate_count_lower_bound','candidate_count_upper_bound',
                'candidate_counter_product_sum','offline_flat_output_lower_bound_bytes','replay_flat_output_lower_bound_bytes',
                'arrival_steps','snapshot_lower_bound','snapshot_upper_bound')),row)
        # Independently enumerate the source table at S (not the indexed helper).
        e=[];u=[]
        for i in range(100):
            request=10_000_000+50_000*i;counts={0:0,1:0}
            for j in range(1,100):
                left=9_000_000+80_000*(j-1);right=9_000_000+80_000*j
                if left<request+5_000_000 and right>=request:counts[j%2]+=1
            e.append(counts[1]);u.append(counts[0])
        self.assertEqual(sum(e),2594)
        self.assertEqual(sum(a*b for a,b in zip(e,u)),70576)
        # A source reference contributes at least177 bytes; the count excludes
        # every surrounding container plus most required candidate fields.
        ref={'column':'pump','file_sha256':'a'*64,'frame_number':None,'raw_time':'2026-01-01T00:00:09.000000Z','record_number':1}
        self.assertEqual(len(json.dumps(ref,sort_keys=True,separators=(',',':'))),177)
        self.assertGreater(expected['M'][4],1024**3)

    def test_changed_preflight_source_profile_schedule_and_case_are_refused(self):
        from round19_scale_fixture import CAPACITY_VERSION,read_preflight
        for mutation in ('math','clear_issues','profile','schedule','raw','case_input','case_profile','missing'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)/'M';generate(root,'M',version=CAPACITY_VERSION)
                case=root/'dual_source_replay-1.json'
                if mutation in ('math','clear_issues'):
                    p=root/'preflight.json';value=json.loads(p.read_text())
                    if mutation=='math':value['density_math']['candidate_count_lower_bound']=0
                    else:value['modes']['dual_source_replay'].update(status='admissible_for_formal_attempt',issues=[])
                    p.write_text(json.dumps(value))
                if mutation in ('profile','schedule'):
                    p=root/'replay-profile.json';value=json.loads(p.read_text())
                    if mutation=='profile':value['window_seconds']=1
                    else:value['replay']['sequence'].pop()
                    p.write_text(json.dumps(value))
                if mutation=='raw':
                    p=root/'process.csv';p.write_text(p.read_text().replace(',1\n',',0\n'))
                if mutation in ('case_input','case_profile'):
                    value=json.loads(case.read_text());value['networks' if mutation=='case_input' else 'profile']=['other.pcap'] if mutation=='case_input' else 'offline-profile.json';case.write_text(json.dumps(value))
                if mutation=='missing':(root/'preflight.json').unlink()
                with self.assertRaises(ValueError):read_preflight(case)

    def test_generator_digest_is_declared_provenance_not_current_code_requirement(self):
        from round19_scale_fixture import CAPACITY_VERSION,read_preflight
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'S';generate(root,'S',version=CAPACITY_VERSION)
            p=root/'preflight.json';value=json.loads(p.read_text());value['generator_sha256']='a'*64;p.write_text(json.dumps(value))
            self.assertEqual(read_preflight(root/'dual_source-1.json')['generator_sha256'],'a'*64)
            value['generator_sha256']='unsupported';p.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'digest_invalid'):read_preflight(root/'dual_source-1.json')

    def test_unknown_generator_version_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'invalid'
            with self.assertRaisesRegex(ValueError,'unsupported_density'):generate(root,'S',version='unknown')
            self.assertFalse(root.exists())


if __name__ == '__main__': unittest.main()
