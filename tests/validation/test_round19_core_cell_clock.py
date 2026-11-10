"""A dependency import delay must remain charged to the cold-process clock."""
import builtins
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/validation'))


class CoreColdClockTests(unittest.TestCase):
    def test_kernel_cgroup_peak_is_distinct_and_missing_not_inferred(self):
        spec=importlib.util.spec_from_file_location('controlled_core_cell_cgroup',ROOT/'scripts/validation/round19_core_cell.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.assertFalse(module.cgroup_snapshot(root)['available'])
            for name,value in {'memory.peak':'1234','memory.current':'1200','memory.max':'8589934592','cpu.stat':'usage_usec 100\nuser_usec 90\nsystem_usec 10\n'}.items():
                (root/name).write_text(value)
            result=module.cgroup_snapshot(root)
            self.assertTrue(result['available']);self.assertEqual(result['peak_memory_bytes'],1234)
            self.assertEqual(result['current_memory_bytes'],1200);self.assertEqual(result['cpu_stat']['usage_usec'],100)
            (root/'memory.max').write_text('max')
            self.assertFalse(module.cgroup_snapshot(root)['available'])

    def test_import_and_parse_work_is_charged_from_module_entry(self):
        clock={'now':1.0};real_import=builtins.__import__;received={}
        def importing(name,*args,**kwargs):
            if name=='argparse':clock['now']+=5.0
            return real_import(name,*args,**kwargs)
        def export(*args,**kwargs):
            received.update(kwargs);clock['now']+=1.0
            raise ValueError('intentional_no_artifact_test_stop')
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'__init__.py';source.write_text('# inert test core\n')
            core=types.SimpleNamespace(__file__=str(source),export_task=export)
            package=types.ModuleType('cpag_core');package.shared_export=core
            spec=importlib.util.spec_from_file_location('controlled_core_cell_clock',ROOT/'scripts/validation/round19_core_cell.py')
            module=importlib.util.module_from_spec(spec);buffer=io.BytesIO()
            arguments=['cell','--action','export','--mode','offline','--seconds','20','--run-id','clock-test']
            with patch('time.monotonic',lambda:clock['now']),patch('builtins.__import__',side_effect=importing),patch.dict(sys.modules,{'cpag_core':package}),patch.object(sys,'argv',arguments),patch.object(sys,'stdout',types.SimpleNamespace(buffer=buffer)),patch.object(sys,'stderr',io.StringIO()):
                spec.loader.exec_module(module)
                self.assertEqual(module.main(),1)
            value=json.loads(buffer.getvalue())
            self.assertEqual(received['deadline'],21.0)
            self.assertEqual(value['wall_seconds'],6.0)
            self.assertEqual(value['query_measurement_version'],'core-query-module-clock-2')
            self.assertEqual(value['reason'],'intentional_no_artifact_test_stop')


if __name__=='__main__':unittest.main()
