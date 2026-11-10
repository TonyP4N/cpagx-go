"""Every independent replay oracle also exercises the optional prepared cache."""
import json
from unittest.mock import patch
import test_compact_semantic_regression as reference

OriginalScenario=reference.scenario

class CachedJudgementSemantics(reference.CompactSemanticRegression):
    def setUp(self):
        def cached(*args,**kwargs):
            networks,process,path,config=OriginalScenario(*args,**kwargs)
            config['replay']['judgement_strategy']='prepared-prefix-cache-1'
            path.write_text(json.dumps(config))
            return networks,process,path,config
        replacement=patch.object(reference,'scenario',cached)
        replacement.start();self.addCleanup(replacement.stop)
