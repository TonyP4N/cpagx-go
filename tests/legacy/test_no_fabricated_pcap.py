"""Dependency-free behavior tests of actual legacy methods, extracted with AST.

These deliberately do not certify imports, packet decoding, or service integration.
"""
import ast
from datetime import datetime
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
V2 = ROOT / 'services/python-cpag-generator/api/v2'


def method(filename, name):
    tree = ast.parse((V2 / filename).read_text())
    node = next(n for cls in tree.body if isinstance(cls, ast.ClassDef)
                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    ns = {'pd': types.SimpleNamespace(DataFrame=list), 'datetime': datetime,
          'os': os, 'struct': struct, 'NEO4J_AVAILABLE': False}
    # Postponed annotations avoid importing the optional scientific/service stack.
    source = 'from __future__ import annotations\n' + ast.unparse(node)
    exec(compile(source, str(V2 / filename), 'exec'), ns)
    return ns[name]


class LegacySafetyTests(unittest.TestCase):
    def setUp(self):
        self.standard = method('unified_cpag_processor.py', '_parse_classic_pcap')

    def test_standard_rejects_even_syntactically_valid_placeholder_trigger(self):
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(bytes(24) + (struct.pack('<IIII', 1, 0, 1, 1) + b'x') * 100)
            capture.flush()
            with self.assertRaisesRegex(NotImplementedError, 'UNSUPPORTED_CLASSIC_PCAP'):
                self.standard(object(), capture.name, 120000, 8000)

    def test_optimized_classic_delegates_to_explicit_unsupported(self):
        enhanced = method('pcap_processor_optimized.py', '_parse_pcap_enhanced')
        base = types.SimpleNamespace(_parse_classic_pcap=types.MethodType(self.standard, object()))
        with self.assertRaisesRegex(NotImplementedError, 'UNSUPPORTED_CLASSIC_PCAP'):
            processor = types.SimpleNamespace(base_processor=base)
            processor._parse_pcap_enhanced = types.MethodType(enhanced, processor)
            dispatch = method('pcap_processor_optimized.py', 'process_pcap_optimized')
            dispatch(processor, 'unused.pcap', 'pcap')

    def test_failed_parser_becomes_failed_public_result_without_graph(self):
        process = method('unified_cpag_processor.py', 'process_file')
        for optimized in (True, False):
            with self.subTest(optimized=optimized), tempfile.TemporaryDirectory() as out:
                fake = types.SimpleNamespace(detect_file_type=lambda _: 'pcap')
                def reject(*args, **kwargs):
                    return self.standard(fake, args[0], 120000, 8000)
                fake._process_pcap_file = reject
                result = process(fake, 'input.pcap', out,
                                 custom_params={'use_optimized_pcap': optimized})
                self.assertEqual(result['status'], 'failed')
                self.assertIn('UNSUPPORTED_CLASSIC_PCAP', result['error'])
                self.assertNotIn('units', result)
                self.assertNotIn('graph_data', result)
                self.assertEqual(os.listdir(out), [])

    def test_pcapng_io_and_header_errors_surface(self):
        parse = method('unified_cpag_processor.py', '_parse_pcapng_enip_requests')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'PCAPNG_PARSE_FAILED'):
                parse(object(), str(Path(directory) / 'missing'))
            empty = Path(directory) / 'empty.pcapng'
            empty.touch()
            with self.assertRaisesRegex(RuntimeError, 'File too small'):
                parse(object(), str(empty))

    def test_task_checks_failed_result_before_success_handling(self):
        # The existing Celery wrapper must retain its failure guard.
        tree = ast.parse((V2 / 'tasks.py').read_text())
        task = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'generate_cpag')
        guards = [n for n in ast.walk(task) if isinstance(n, ast.If)
                  and "processing_result.get('status') == 'failed'" == ast.unparse(n.test)]
        self.assertEqual(len(guards), 1)
        self.assertIsInstance(guards[0].body[0], ast.Raise)


if __name__ == '__main__':
    unittest.main()
