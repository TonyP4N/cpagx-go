"""Only vanished known temporary files may make a live sample incomplete."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))
from round19_core_matrix import sample_physical,physical,file_inventory


class LiveSamplerTests(unittest.TestCase):
    def fixture(self,root):
        journal=root/'result/artifact/shared/shared.sqlite3-journal';journal.parent.mkdir(parents=True);journal.write_bytes(b'journal')
        source=root/'input/process.csv';source.parent.mkdir();source.write_bytes(b'original\n')
        return journal,source
    def test_vanished_journal_is_recorded_without_zero_filling_the_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal,source=self.fixture(root);original=Path.lstat
            def removed(path,*args,**kwargs):
                if path==journal and journal.exists():journal.unlink();raise FileNotFoundError(str(path))
                return original(path,*args,**kwargs)
            with patch.object(Path,'lstat',removed):result=sample_physical(root)
            self.assertTrue(result['sample_incomplete']);self.assertEqual(result['vanished'],['result/artifact/shared/shared.sqlite3-journal'])
            self.assertEqual(result['file_bytes'],source.stat().st_size)
    def test_fixed_source_disappearance_is_never_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal,source=self.fixture(root);original=Path.lstat
            def removed(path,*args,**kwargs):
                if path==source and source.exists():source.unlink();raise FileNotFoundError(str(path))
                return original(path,*args,**kwargs)
            with patch.object(Path,'lstat',removed),self.assertRaises(FileNotFoundError):sample_physical(root)
    def test_fixed_artifact_disappearance_is_never_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal,source=self.fixture(root)
            artifact=journal.with_name('shared.sqlite3');artifact.write_bytes(b'fixed');original=Path.lstat
            def removed(path,*args,**kwargs):
                if path==artifact:raise FileNotFoundError(str(path))
                return original(path,*args,**kwargs)
            with patch.object(Path,'lstat',removed),self.assertRaises(FileNotFoundError):sample_physical(root)
    def test_even_journal_disappearance_is_strict_at_terminal_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal,source=self.fixture(root);original=Path.is_file
            def removed(path):
                answer=original(path)
                if path==journal and answer:journal.unlink()
                return answer
            with patch.object(Path,'is_file',removed),self.assertRaises(FileNotFoundError):physical(root)
            journal.write_bytes(b'journal')
            with patch.object(Path,'is_file',removed),self.assertRaises(FileNotFoundError):file_inventory(root)
    def test_permission_error_and_final_inventory_disappearance_still_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal,source=self.fixture(root);original=Path.lstat
            def denied(path,*args,**kwargs):
                if path==journal:raise PermissionError('permission denied')
                return original(path,*args,**kwargs)
            with patch.object(Path,'lstat',denied),self.assertRaises(PermissionError):sample_physical(root)
            old=Path.is_file
            def final_removed(path):
                answer=old(path)
                if path==source and answer:source.unlink()
                return answer
            with patch.object(Path,'is_file',final_removed),self.assertRaises(FileNotFoundError):physical(root)
            source.write_bytes(b'original\n')
            with patch.object(Path,'is_file',final_removed),self.assertRaises(FileNotFoundError):file_inventory(root)


if __name__=='__main__':unittest.main()
