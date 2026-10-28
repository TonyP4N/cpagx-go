"""Admission and pagination defects must fail before being called accepted."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_core_guards import admit_fixture,check_counts,EvidencePages
from round19_scale_fixture import generate,COMPACT_STANDARD_VERSION,COMPACT_CACHED_VERSION,COMPACT_VERSION,density_budget_math
from round19_core_matrix import copy_handoff,file_inventory


class CoreMatrixGuardTests(unittest.TestCase):
    def test_complete_handoff_and_new_query_logs_preserve_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'scratch';source.mkdir();(source/'artifact').mkdir()
            (source/'artifact/original').write_bytes(b'original\r\nbytes');(source/'report.json').write_text('{}')
            target=root/'controlled';before=file_inventory(source)
            self.assertEqual(copy_handoff(source,target),before)
            (target/'after-query.log').write_bytes(b'new evidence')
            (target/'report.json').write_text('{"state":"query_complete"}')
            copy_handoff(target,source,new_files_only=True)
            self.assertEqual((source/'artifact/original').read_bytes(),b'original\r\nbytes')
            self.assertEqual((source/'after-query.log').read_bytes(),b'new evidence')
            self.assertEqual((source/'report.json').read_text(),'{}')
            (target/'artifact/original').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'preserved_file_changed'):
                copy_handoff(target,source,new_files_only=True)

    def test_handoff_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'scratch';source.mkdir();(source/'data').write_text('source')
            (source/'link').symlink_to(source/'data')
            with self.assertRaisesRegex(ValueError,'symlink'):copy_handoff(source,root/'controlled')

    def test_generator6_requires_explicit_cache_strategy_and_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'fixture';generate(root,'S',version=COMPACT_CACHED_VERSION)
            with self.assertRaisesRegex(ValueError,'generator5_or_6'):
                admit_fixture(root,root/'replay-profile.json','S','replay')
            accepted=admit_fixture(root,root/'replay-profile.json','S','replay',fixture_version=COMPACT_CACHED_VERSION)
            self.assertEqual(accepted['judgement_strategy'],'prepared-prefix-cache-1')
            path=root/'replay-profile.json';value=json.loads(path.read_text());value['replay'].pop('judgement_strategy');path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'profile_or_schedule_changed'):
                admit_fixture(root,path,'S','replay',fixture_version=COMPACT_CACHED_VERSION)

    def test_exact_generator5_admission_and_changed_profile_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'fixture';generate(root,'S',version=COMPACT_STANDARD_VERSION)
            accepted=admit_fixture(root,root/'replay-profile.json','S','replay')
            self.assertEqual(accepted['fixture_version'],COMPACT_STANDARD_VERSION)
            path=root/'replay-profile.json';value=json.loads(path.read_text())
            value['replay']['allowed_lateness_seconds']=3;path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'profile_or_schedule_changed'):
                admit_fixture(root,path,'S','replay')

    def test_old_profile_and_wrong_selected_mode_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'fixture';generate(root,'S',version=COMPACT_VERSION)
            with self.assertRaisesRegex(ValueError,'generator5'):
                admit_fixture(root,root/'offline-profile.json','S','offline')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'fixture';generate(root,'S',version=COMPACT_STANDARD_VERSION)
            with self.assertRaisesRegex(ValueError,'profile_identity'):
                admit_fixture(root,root/'offline-profile.json','S','replay')

    def test_counts_use_independent_geometry_and_reject_boolean(self):
        value=density_budget_math('S');counts={'operations':100,'network':200,'process':100,'changes':99,'candidates':value['candidate_count_lower_bound']}
        check_counts(counts,'S')
        for key,replacement in [('candidates',0),('operations',True),('changes',100),('network',199)]:
            bad=dict(counts);bad[key]=replacement
            with self.assertRaises(ValueError):check_counts(bad,'S')

    def test_pages_require_complete_contiguous_unique_references(self):
        rows=[{'source_ref':{'record_number':i}} for i in range(3)]
        first={'offset':0,'limit':2,'returned':2,'total':3,'has_more':True}
        last={'offset':2,'limit':2,'returned':1,'total':3,'has_more':False}
        pages=EvidencePages();self.assertFalse(pages.add(first,rows[:2]));self.assertTrue(pages.add(last,rows[2:]));self.assertEqual(pages.offset,3)
        for replacement in ({'has_more':False},{'offset':1},{'returned':True},{'total':1}):
            bad=copy.deepcopy(first);bad.update(replacement)
            with self.assertRaises(ValueError):EvidencePages().add(bad,rows[:2])
        pages=EvidencePages();pages.add(first,rows[:2])
        with self.assertRaisesRegex(ValueError,'repeated'):pages.add(last,rows[:1])
        pages=EvidencePages();pages.add(first,rows[:2]);bad=dict(last,total=4,has_more=True)
        with self.assertRaisesRegex(ValueError,'total_changed'):pages.add(bad,rows[2:])


if __name__=='__main__':unittest.main()
