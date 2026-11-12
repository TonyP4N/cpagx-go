import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]

class VerifierIdentityTests(unittest.TestCase):
    def test_source_identity_matches_actual_bundle_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();core=root/'services/analysis/src/cpag_core';core.mkdir(parents=True)
            schemas=root/'schemas';schemas.mkdir();(core/'example.py').write_text('value=1\n');(schemas/'example.json').write_text('{}')
            shutil.copyfile(ROOT/'deployments/resident/verifier_identity.py',root/'verifier_identity.py')
            shutil.copyfile(ROOT/'deployments/r21/k3s/source-verifier.py',root/'source-verifier.py')
            spec=importlib.util.spec_from_file_location('verifier_identity',root/'verifier_identity.py');identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
            value=identity.source_identity(root);self.assertTrue(value.startswith('source-sha256:'));self.assertEqual(value,identity.source_identity(root))
            trusted=root/'trusted.identity';trusted.write_text(value)
            spec=importlib.util.spec_from_file_location('test_compose_verifier',root/'source-verifier.py');verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
            with patch.dict(sys.modules,{'verifier_identity':identity}),patch.dict(os.environ,{'CPAG_VERIFY_BACKEND':'compose-file-sidecar-v1','CPAG_VERIFIER_IDENTITY_FILE':str(trusted)}):
                self.assertEqual(verifier.verify_compose_identity(),value)
                (core/'example.py').write_text('value=2\n')
                self.assertNotEqual(value,identity.source_identity(root))
                with self.assertRaises(ValueError):verifier.verify_compose_identity()
            with patch.dict(os.environ,{},clear=True):self.assertIsNone(verifier.verify_compose_identity())
