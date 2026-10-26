"""One-command synthetic dual-source example, including raw evidence query."""
import argparse
import json
from pathlib import Path
import sys
from dual_source_fixtures import make_case, ROOT
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_core.dual_source import run_dual, query


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    network,process,profile=make_case(args.output/'inputs')
    result=run_dual(network,process,profile,args.output/'run')
    evidence=query(args.output/'run',operation_id='first')
    (args.output/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'synthetic':True,'operation':result['operations'][0],
                      'candidate_state':result['candidates'][0]['state'],'claim_status':result['candidates'][0]['claim']['status'],
                      'evidence_file':str(args.output/'evidence.json')},indent=2))

if __name__=='__main__':main()
