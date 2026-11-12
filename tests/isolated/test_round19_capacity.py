"""Independent reservation arithmetic: every ordered original must be budgeted."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'services/worker'))
from cpag_worker.isolated import DockerExecutor

class ReservationTests(unittest.TestCase):
    def case(self, root, count, budget=10000000):
        shared=root/'shared';shared.mkdir();control=root/'control'
        refs=[]
        for i in range(count):
            p=shared/('network%d.pcap'%i);p.write_bytes(bytes([i])*((i+1)*100))
            refs.append({'path':p.name,'sha256':str(i)*64})
        for name in ('process','profile'):(shared/name).write_bytes(b'x'*10)
        payload={'kind':'dual-source-replay','network':refs[0],
                 'process':{'path':'process'},'profile':{'path':'profile'}}
        if count>1:payload['networks']=refs
        claim={'id':'test','attempt':1,'payload':payload}
        worker=DockerExecutor(None,None,shared,control,'test',output_bytes=100,host_budget_bytes=budget,min_free_bytes=0)
        return worker,claim,control
    def test_all_sources_counted_once_and_repeat_is_idempotent(self):
        for count in (1,2,4):
            with self.subTest(count=count),tempfile.TemporaryDirectory() as tmp:
                worker,claim,control=self.case(Path(tmp),count)
                worker.capacity(claim);worker.capacity(claim)
                ledger=json.loads((control/'capacity.json').read_text())
                self.assertEqual(ledger['reservations']['test:1'],sum(100*(i+1) for i in range(count))+20+200+2097152)
    def test_missing_later_original_refuses_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            worker,claim,control=self.case(Path(tmp),2)
            (worker.root/'network1.pcap').unlink()
            with self.assertRaises(FileNotFoundError):worker.capacity(claim)
            self.assertFalse((control/'capacity.json').exists())
    def test_budget_includes_later_original_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Actual originals 320, retained copy 320, output 200, overhead2097152.
            worker,claim,control=self.case(Path(tmp),2,budget=2097152+320+200+200)
            with self.assertRaises(OSError):worker.capacity(claim)
            self.assertFalse((control/'capacity.json').exists())

if __name__=='__main__':unittest.main()
