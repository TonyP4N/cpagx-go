import argparse
import json
import sys
from .pipeline import run

def main():
    parser=argparse.ArgumentParser(description='Independent offline core; explicit dual-source mode available')
    parser.add_argument('--network',required=True,action='append')
    parser.add_argument('--process',required=True)
    parser.add_argument('--profile',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--synthetic',action='store_true',help='explicitly acknowledge synthetic inputs')
    parser.add_argument('--dual-source',action='store_true',help='use the bounded dual-source core and retained profile source mode')
    args=parser.parse_args()
    try:
        if args.dual_source:
            from .dual_source_export import export_task
            from .dual_source import strict_json
            from pathlib import Path
            if args.synthetic and strict_json(Path(args.profile).read_text())['synthetic'] is not True:
                raise ValueError('synthetic_flag_profile_mismatch')
            manifest=export_task(args.network,args.process,args.profile,args.output)
        else:
            if not args.synthetic:raise ValueError('legacy_core_requires_synthetic_acknowledgement')
            if len(args.network)!=1:raise ValueError('multiple_captures_require_dual_source_mode')
            manifest=run(args.network[0],args.process,args.profile,args.output,synthetic=args.synthetic)
    except (ValueError,OSError,KeyError,TypeError) as error:
        print(str(error),file=sys.stderr)
        return 1
    print(json.dumps({'run_id':manifest['run_id'],'output':args.output,'result_hashes':manifest['result_hashes']},sort_keys=True))
    return 0

if __name__=='__main__':
    sys.exit(main())
