"""All independent arrival oracles also apply to the opt-in digest strategy."""
import test_arrived_inputs as base
from test_arrived_inputs import REQUEST, REPLY, frame, pcap, pcapng, PROFILE, visible
from cpag_core.replay_inputs import ReplayInputs
from cpag_core.pipeline import canonical


class IncrementalArrivalInputTests(base.ArrivalInputTests):
    def inputs(self,network,process=None):
        if process is None:process=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n','.csv')
        result=ReplayInputs(network,process,PROFILE,synthetic=True,digest_strategy='incremental-prefix-digest-2')
        self.addCleanup(result.close);return result

    def test_each_prefix_duplicate_conflict_and_filtered_snapshot_matches_old(self):
        first,_=pcap([frame(REQUEST[:20]),frame(REQUEST[20:],120)])
        second,_=pcapng([frame(REPLY,reverse=True)])
        networks=[self.source(first),self.source(second)]
        process=self.source(b'time,level\n2026-01-01T00:00:00Z,0\n2026-01-01T00:00:01Z,1\n','.csv')
        old=ReplayInputs(networks,process,PROFILE,synthetic=True);self.addCleanup(old.close)
        new=self.inputs(networks,process)
        self.assertEqual(old.digest,new.digest)
        self.assertEqual(old.digest_strategy,'canonical-prefix-1')
        for slot,number in [('network-0',1),('process',1),('process',2),('network-0',2),('network-1',1),('process',3)]:
            self.assertEqual(self.advance(old,slot,number),self.advance(new,slot,number))
            self.assertEqual(old.digest,new.digest)
            self.assertEqual(canonical(visible(old)),canonical(visible(new)))
            before=new.digest
            for item in (old,new):
                self.assertEqual(self.advance(item,slot,number)['status'],'duplicate')
                self.assertEqual(self.advance(item,slot,number,record_sha256='0'*64)['status'],'conflicting_reference')
            self.assertEqual(new.digest,before);self.assertEqual(old.digest,before)
        allowed=[new.seen[('network-0',1)]['source_ref'],new.seen[('process',2)]['source_ref']]
        a=old.snapshot(allowed_record_refs=allowed);b=new.snapshot(allowed_record_refs=allowed)
        self.assertEqual(canonical({k:v for k,v in a.items() if k!='frames'}),canonical({k:v for k,v in b.items() if k!='frames'}))

    def test_unknown_strategy_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsupported_arrival_digest_strategy'):
            ReplayInputs('unused','unused',PROFILE,synthetic=True,digest_strategy='invented')
