import json,os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'services/worker'))
from cpag_worker.service import read_config
class ServiceConfig(unittest.TestCase):
 def test_private_worker_credentials_only(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'worker.json';base={'api_url':'http://127.0.0.1:8094','shared_root':d+'/shared','control_root':d+'/control','worker_token':'w'*32,'coordinator_token':'c'*32}
   path.write_text(json.dumps(base));path.chmod(0o600);self.assertEqual(read_config(path)['recovery_seconds'],5)
   for patch in ({'database_url':'secret'},{'api_url':'http://127.0.0.1:8094@evil.example'},{'coordinator_token':'w'*32},{'poll_seconds':0},{'shared_root':'relative'},{'control_root':d+'/shared/control'}):
    path.write_text(json.dumps({**base,**patch}))
    with self.assertRaises(ValueError):read_config(path)
   path.write_text(json.dumps(base));path.chmod(0o644)
   with self.assertRaises(ValueError):read_config(path)
if __name__=='__main__':unittest.main()
