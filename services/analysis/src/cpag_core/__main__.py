import argparse
import json
import sys
from .pipeline import run

def main():
    parser=argparse.ArgumentParser(description='M1 synthetic offline analysis; no alignment or inference')
    parser.add_argument('--network',required=True)
    parser.add_argument('--process',required=True)
    parser.add_argument('--profile',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--synthetic',required=True,action='store_true',help='explicitly acknowledge synthetic inputs')
    args=parser.parse_args()
    try:
        manifest=run(args.network,args.process,args.profile,args.output,synthetic=args.synthetic)
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr)
        return 1
    print(json.dumps({'run_id':manifest['run_id'],'output':args.output,'result_hashes':manifest['result_hashes']},sort_keys=True))
    return 0

if __name__=='__main__':
    sys.exit(main())
