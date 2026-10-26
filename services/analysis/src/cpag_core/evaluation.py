"""Opt-in synthetic evaluation only. Never imports a predictor or generates gold."""
import argparse
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from .contracts import validate, _validate
from .pipeline import canonical, fingerprint


def instant(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('explicit timezone required')
    return parsed.timestamp()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(name + ': finite nonnegative value required')
    return value


def check_schema(name, value):
    from .contracts import SCHEMAS
    _validate(json.loads((SCHEMAS / (name + '.schema.json')).read_text()), value, name)


def validate_splits(split):
    check_schema('EvaluationSplit', split)
    windows = split['rule_windows_seconds']
    if not windows:
        raise ValueError('rule windows must be declared, use explicit zero for no window')
    largest = max(number(w, 'rule window') for w in windows.values())
    gap = number(split['isolation_seconds'], 'isolation')
    if gap < largest:
        raise ValueError('isolation smaller than maximum rule window')
    seen = set(); blocks = []
    for block in split['blocks']:
        if not block['sample_sha256']:
            raise ValueError('empty sample identity')
        start, end = instant(block['start']), instant(block['end'])
        if end <= start:
            raise ValueError('invalid split interval')
        for sample in block['sample_sha256']:
            if sample in seen:
                raise ValueError('duplicate sample across blocks')
            seen.add(sample)
        blocks.append((block, start, end))
    if {b['partition'] for b, _, _ in blocks} != {'calibration', 'holdout'}:
        raise ValueError('both calibration and holdout required')
    for i, (a, sa, ea) in enumerate(blocks):
        for b, sb, eb in blocks[i+1:]:
            if a['batch'] != b['batch']:
                continue
            separation = max(sa, sb) - min(ea, eb)
            if separation < 0:
                raise ValueError('overlapping split blocks')
            if a['partition'] != b['partition'] and separation < gap:
                raise ValueError('insufficient boundary isolation')
    return blocks


def contains(blocks, batch, at, normal=False):
    return any(b['partition']=='holdout' and b['batch']==batch and start <= at < end
               and (not normal or b['normal']) for b,start,end in blocks)


def evaluate(predictions, annotations, split, registration):
    check_schema('EvaluationPredictions', predictions)
    check_schema('EvaluationAnnotations', annotations)
    check_schema('EvaluationRegistration', registration)
    blocks = validate_splits(split)
    if registration['split_sha256'] != digest(split):
        raise ValueError('split changed after registration')
    if registration['input_fingerprint'] != predictions['input_fingerprint'] or registration['config_fingerprint'] != predictions['config_fingerprint']:
        raise ValueError('prediction identity differs from frozen registration')
    if instant(registration['registered_at']) >= instant(registration['holdout_opened_at']):
        raise ValueError('registration must precede holdout opening')
    if annotations['origin'] != 'independent' or not all(annotations[k].strip() for k in ('review_ref','source_ref','annotation_version')):
        raise ValueError('independent reviewed annotations required')
    tolerance = number(registration['tolerance_seconds'], 'tolerance')
    for value in registration['thresholds'].values():
        number(value, 'threshold')
    if max(len(predictions['events']),len(annotations['events'])) > 500:
        raise ValueError('synthetic evaluator limit: 500 events per side')
    for dataset in (predictions, annotations):
        ids=set()
        for event in dataset['events']:
            if event['id'] in ids:
                raise ValueError('duplicate event identity')
            ids.add(event['id'])
            if not any(b['partition']=='holdout' and b['batch']==event['batch'] and start<=instant(event['time'])<end and event['sample_sha256'] in b['sample_sha256'] for b,start,end in blocks):
                raise ValueError('event outside holdout')
    for event in annotations['events']:
        if contains(blocks,event['batch'],instant(event['time']),True):
            raise ValueError('positive gold inside declared normal interval')
    disputes=[]
    for item in annotations['disputed_intervals']:
        start,end=instant(item['start']),instant(item['end'])
        if end<=start or not any(b['partition']=='holdout' and b['batch']==item['batch'] and s<=start and end<=e for b,s,e in blocks):
            raise ValueError('dispute outside holdout')
        disputes.append((item['batch'],start,end))
    def disputed(event):
        return any(batch==event['batch'] and start<=instant(event['time'])<end for batch,start,end in disputes)
    pred=[p for p in predictions['events'] if not disputed(p)]
    gold=[g for g in annotations['events'] if not disputed(g)]
    # Maximum cardinality, one-to-one matching; do not double count detections.
    edges=[[j for j,g in enumerate(gold) if p['batch']==g['batch'] and p['kind']==g['kind'] and p['asset']==g['asset'] and abs(instant(p['time'])-instant(g['time']))<=tolerance] for p in pred]
    assigned={}
    def augment(i, seen):
        for j in edges[i]:
            if j in seen: continue
            seen.add(j)
            if j not in assigned or augment(assigned[j], seen):
                assigned[j]=i
                return True
        return False
    for i in range(len(pred)): augment(i,set())
    matched=set(assigned.values()); tp=len(assigned); fp=len(pred)-tp; fn=len(gold)-tp
    # Merge dispute ranges before subtracting from verified normal duration.
    seconds=0
    for b,start,end in blocks:
        if b['partition']!='holdout' or not b['normal']: continue
        intervals=sorted((max(start,s),min(end,e)) for batch,s,e in disputes if batch==b['batch'] and s<end and e>start)
        cursor=start
        for s,e in intervals:
            seconds+=max(0,s-cursor);cursor=max(cursor,e)
        seconds+=max(0,end-cursor)
    hours=seconds/3600
    normal_fp=sum(i not in matched and contains(blocks,p['batch'],instant(p['time']),True) for i,p in enumerate(pred))
    synthetic=all(x['synthetic'] for x in (predictions,annotations,split,registration))
    metrics={'tp':tp,'fp':fp,'fn':fn,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,'normal_hours':hours if hours else None,'false_alarms_per_normal_hour':normal_fp/hours if hours else None}
    if not synthetic: metrics={k:None for k in metrics}
    record={'schema_version':'1.0.0','synthetic':synthetic,'evaluation_id':'evaluation-'+digest([predictions,annotations,split,registration]),'run_id':predictions['run_id'],'data_split':digest(split),'label_source':annotations['source_ref'],'annotation_version':annotations['annotation_version'],'matching_strategy':'maximum-cardinality one-to-one, explicit type/asset/batch and time tolerance','metrics':metrics,'error_analysis':['Synthetic calculation only; real industrial evaluation not performed.','Unlabelled relations excluded; no path gold or path accuracy.'],'independent_labels':True}
    validate('EvaluationRecord',record)
    return {'record':record,'status':'synthetic_software_test' if synthetic else 'not_evaluated','input_fingerprint':predictions['input_fingerprint'],'config_fingerprint':predictions['config_fingerprint'],'annotation_sha256':digest(annotations),'registration_sha256':digest(registration),'excluded_disputed_predictions':sum(disputed(p) for p in predictions['events']),'unlabelled_relations':len(predictions['unlabelled_relations']),'path_accuracy':None,'provenance_note':'Independence and opening times are declared provenance, not a cryptographic custody proof.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('predictions','annotations','split','registration'): parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:
        values=[json.loads(Path(getattr(args,n)).read_text()) for n in ('predictions','annotations','split','registration')]
        result=evaluate(*values)
    except (ValueError,OSError,KeyError,TypeError,RecursionError):
        print(json.dumps({'status':'rejected','reason':'invalid evaluation contract or inconsistent provenance'}))
        return 2
    print(json.dumps(result,sort_keys=True,allow_nan=False))
    return 0

if __name__=='__main__': raise SystemExit(main())
