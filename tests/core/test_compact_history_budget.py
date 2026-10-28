"""Logical extents are authenticated counts, never a memory/output allocation."""
from pathlib import Path
import tempfile
import unittest
from cpag_core.capacity import shared_storage_budget,resolve_capacity_profile
from cpag_core.shared_artifact_store_compact import FORMAT,SharedArtifactWriter,SharedArtifactReader
from cpag_core.shared_artifact_store_compressed import SharedArtifactWriter as OldWriter,CONTENT_FORMAT

CONTEXT={'run_id':'extent','attempt_id':1,'input_fingerprint':'a'*64,'config_fingerprint':'b'*64}

class CompactExtentTests(unittest.TestCase):
    def test_budget_version_is_explicit_and_keeps_physical_and_read_limits(self):
        config={'analysis_mode':'bounded-real-capable-v1','capacity_profile':'engineering-core-capacity-3','storage_format':FORMAT}
        old=shared_storage_budget(config)
        new=shared_storage_budget(dict(config,storage_budget_version='shared-storage-budget-2'))
        self.assertEqual(old.max_logical_root_bytes,512*1024**3)
        self.assertEqual(new.max_logical_root_bytes,4*1024**5)
        self.assertEqual((old.physical_bytes,old.query_bytes,old.query_items),(new.physical_bytes,new.query_bytes,new.query_items))
        with self.assertRaises(ValueError):resolve_capacity_profile(dict(config,storage_budget_version='unknown'))
        with self.assertRaises(ValueError):resolve_capacity_profile({'storage_budget_version':'shared-storage-budget-2'})

    def test_shared_large_extent_verifies_but_cannot_be_expanded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'new'
            writer=SharedArtifactWriter(root,context=CONTEXT,version=FORMAT,max_logical_root_bytes=4*1024**5)
            scalar=writer.intern('x'*1048576)
            billion=writer.sequence(None,[scalar['digest']]*1000)
            trillion=writer.sequence('huge',[billion['digest']]*1000)
            self.assertGreater(trillion['logical_bytes'],512*1024**3)
            sealed=writer.seal()
            self.assertLess((root/'shared.sqlite3').stat().st_size,8*1024**2)
            reader=SharedArtifactReader(root,expected_manifest_sha256=sealed['manifest_sha256'],expected_context=CONTEXT)
            try:
                self.assertEqual(reader.descriptor('huge')['logical_bytes'],trillion['logical_bytes'])
                with self.assertRaises(ValueError):reader.get('huge')
                self.assertEqual(reader.get('huge',path=[999,999]),'x'*1048576)
            finally:reader.close()
            with self.assertRaises(ValueError):OldWriter(Path(directory)/'old',context=CONTEXT,version=CONTENT_FORMAT,max_logical_root_bytes=4*1024**5)


class FlatMemoTests(unittest.TestCase):
    def test_complete_values_not_identity_and_signed_zero(self):
        from cpag_core.shared_artifact_store_compact import LogicalHasher
        with tempfile.TemporaryDirectory() as directory:
            writer=SharedArtifactWriter(Path(directory)/'store',context=CONTEXT,version=FORMAT)
            value={'field':'x','value':0.0}
            first=writer.intern(value)
            value['value']=-0.0
            second=writer.intern(value)
            self.assertNotEqual(first['digest'],second['digest'])
            self.assertEqual(second['digest'],LogicalHasher().digest(value)['digest'])
            value['field']='y'
            third=writer.intern(value)
            self.assertNotEqual(second['digest'],third['digest'])
            self.assertEqual(third['digest'],LogicalHasher().digest(value)['digest'])
            for number in range(4500):writer.intern({'frame':number,'source':'a'*64})
            self.assertLessEqual(len(writer._flat_values),writer.limits['cache_entries'])
            self.assertLessEqual(writer._flat_value_bytes,writer.limits['cache_bytes'])
            writer.close()

if __name__=='__main__':unittest.main()
