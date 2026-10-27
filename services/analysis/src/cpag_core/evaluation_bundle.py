"""Versioned, independent evaluation sidecar. Never changes analysis artifacts.

Local CLI files are a trust boundary, not tamper-proof custody. Registration
records observed creation time as well as declared provenance; a trusted clock
and external review remain necessary. Labels never enter an analysis call.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

from .dual_source import strict_json
from .evaluation import check_schema, digest, instant, validate_splits
from .evaluation_artifacts import adapt_artifact, query_prediction
from .pipeline import canonical
from .evaluation_details import MATCHING_VERSION, DETAILS_VERSION

VERSION='evaluation-bundle-1'
FILES={'registration.json','split.json','adapted.json','annotations.json','references.json','result.json','freeze.json'}
CUSTODY='local_clock_and_files_not_external_independence_proof'
REFERENCE_STATUS='declared_independent_reference_not_original_bytes_verified'
FREEZE_FIELDS={'version','observed_frozen_at','registration_sha256','split_sha256','adapted_sha256',
    'binding_sha256','matching','details_version','custody'}
BINDING_FIELDS={'version','freeze_sha256','artifact_binding_sha256','annotations_sha256',
    'references_sha256','observed_opened_at','reference_status'}


def exact_fields(value,fields,reason):
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError(reason)


def valid_digest(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def validate_freeze(frozen,registration):
    exact_fields(frozen,FREEZE_FIELDS,'frozen_contract_invalid')
    if (frozen['version']!=VERSION or frozen['matching']!=MATCHING_VERSION
            or frozen['details_version']!=DETAILS_VERSION or frozen['custody']!=CUSTODY):
        raise ValueError('unsupported_evaluation_version_or_custody')
    if any(not valid_digest(frozen[name]) for name in FREEZE_FIELDS if name.endswith('_sha256')):
        raise ValueError('frozen_digest_invalid')
    observed=instant(frozen['observed_frozen_at']);registered=instant(registration['registered_at'])
    opening=instant(registration['holdout_opened_at'])
    if registered>observed:raise ValueError('registration_cannot_follow_observed_freeze')
    if not registered<=observed<opening:raise ValueError('system_freeze_must_precede_declared_opening')


def validate_references(annotations,references):
    check_schema('EvaluationAnnotations',annotations)
    if not isinstance(references,dict) or set(references)!={e['id'] for e in annotations['events']}:
        raise ValueError('every_gold_requires_independent_reference')
    for value in references.values():
        exact_fields(value,{'source_ref','record','sha256'},'independent_reference_invalid')
        if not all(isinstance(v,str) and v.strip() and len(v)<=65536 for v in value.values()):
            raise ValueError('independent_reference_invalid')
        if not valid_digest(value['sha256']):raise ValueError('reference_hash_invalid')


def validate_bundle_binding(binding):
    exact_fields(binding,BINDING_FIELDS,'evaluation_binding_contract_invalid')
    if binding['version']!=VERSION or binding['reference_status']!=REFERENCE_STATUS:
        raise ValueError('evaluation_binding_version_or_reference_status_invalid')
    if any(not valid_digest(binding[name]) for name in BINDING_FIELDS if name.endswith('_sha256')):
        raise ValueError('evaluation_binding_digest_invalid')
    instant(binding['observed_opened_at'])


def read(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>8*1024*1024:
        raise ValueError('ordinary_bounded_json_required')
    return strict_json(path.read_text())


def write(path,value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value)+b'\n')


def publish(destination,values):
    destination=Path(destination).absolute()
    if destination.exists():raise ValueError('new_output_directory_required')
    destination.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix='.evaluation-',dir=destination.parent))
    reserved=False
    try:
        for name,value in values.items():write(stage/name,value)
        # Do not overwrite a previously published bundle on duplicate submission.
        destination.mkdir(mode=0o700)
        reserved=True
        for item in stage.iterdir():item.rename(destination/item.name)
        stage.rmdir()
    except BaseException:
        shutil.rmtree(stage,ignore_errors=True)
        if reserved:shutil.rmtree(destination,ignore_errors=True)
        raise


def freeze(artifact,split,registration,output,*,batch,sample_sha256,projection='dual'):
    check_schema('EvaluationRegistration',registration);validate_splits(split)
    if registration['split_sha256']!=digest(split):raise ValueError('split_not_registered')
    if instant(registration['registered_at'])>=instant(registration['holdout_opened_at']):
        raise ValueError('registration_not_before_opening')
    if instant(datetime.now(timezone.utc).isoformat())>=instant(registration['holdout_opened_at']):
        raise ValueError('system_freeze_must_precede_declared_opening')
    adapted=adapt_artifact(artifact,batch=batch,sample_sha256=sample_sha256,projection=projection)
    pred=adapted['predictions']
    for key in ('input_fingerprint','config_fingerprint'):
        if pred[key]!=registration[key]:raise ValueError('registration_identity_mismatch')
    if not any(b['partition']=='holdout' and b['batch']==batch and sample_sha256 in b['sample_sha256'] for b in split['blocks']):
        raise ValueError('sample_not_in_registered_holdout')
    # Artifact verification may be expensive. The frozen observation is taken
    # after those inputs are fixed, never from the beginning of the operation.
    observed=datetime.now(timezone.utc).isoformat()
    frozen={'version':VERSION,'observed_frozen_at':observed,'registration_sha256':digest(registration),
        'split_sha256':digest(split),'adapted_sha256':digest(adapted),'binding_sha256':digest(adapted['binding']),
        'matching':MATCHING_VERSION,'details_version':DETAILS_VERSION,
        'custody':CUSTODY}
    validate_freeze(frozen,registration)
    publish(output,{'registration.json':registration,'split.json':split,'adapted.json':adapted,'freeze.json':frozen})
    completed=instant(datetime.now(timezone.utc).isoformat())
    if completed<instant(observed) or completed>=instant(registration['holdout_opened_at']):
        shutil.rmtree(Path(output).absolute())
        raise ValueError('completed_freeze_must_precede_declared_opening')
    return frozen


def frozen_inputs(root,artifact):
    root=Path(root)
    values={n:read(root/(n+'.json')) for n in ('registration','split','adapted','freeze')}
    f=values['freeze']
    registration=values['registration'];check_schema('EvaluationRegistration',registration)
    validate_splits(values['split']);validate_freeze(f,registration)
    if registration['split_sha256']!=digest(values['split']):raise ValueError('split_not_registered')
    for name in ('registration','split','adapted'):
        if f[name+'_sha256']!=digest(values[name]):raise ValueError('frozen_input_changed')
    if f['binding_sha256']!=digest(values['adapted']['binding']):raise ValueError('frozen_binding_changed')
    b=values['adapted']['binding']
    for key in ('input_fingerprint','config_fingerprint'):
        if values['adapted']['predictions'][key]!=registration[key]:raise ValueError('registration_identity_mismatch')
    if not any(block['partition']=='holdout' and block['batch']==b['batch'] and b['sample_sha256'] in block['sample_sha256'] for block in values['split']['blocks']):
        raise ValueError('sample_not_in_registered_holdout')
    actual=adapt_artifact(artifact,batch=b['batch'],sample_sha256=b['sample_sha256'],projection=b['projection'],expected_binding=b)
    if actual!=values['adapted']:raise ValueError('frozen_projection_changed')
    return values


def evaluate_bundle(frozen,artifact,annotations,references,output):
    from .evaluation_details import evaluate_detailed
    values=frozen_inputs(frozen,artifact)
    opened=datetime.now(timezone.utc).isoformat()
    if instant(opened)<instant(values['registration']['holdout_opened_at']):raise ValueError('holdout_not_open')
    if instant(opened)<=instant(values['freeze']['observed_frozen_at']):raise ValueError('invalid_system_opening_order')
    validate_references(annotations,references)
    result=evaluate_detailed(values['adapted']['predictions'],annotations,values['split'],values['registration'])
    result['bundle_binding']={'version':VERSION,'freeze_sha256':digest(values['freeze']),
        'artifact_binding_sha256':digest(values['adapted']['binding']),'annotations_sha256':digest(annotations),
        'references_sha256':digest(references),'observed_opened_at':opened,
        'reference_status':REFERENCE_STATUS}
    payload={n+'.json':v for n,v in values.items()}
    payload.update({'annotations.json':annotations,'references.json':references,'result.json':result})
    manifest={'version':VERSION,'files':{n:digest(v) for n,v in payload.items()}}
    publish(output,{**payload,'manifest.json':manifest})
    return result


def verify_bundle(root,artifact):
    root=Path(root);manifest=read(root/'manifest.json')
    exact_fields(manifest,{'version','files'},'evaluation_manifest_contract_invalid')
    if manifest.get('version')!=VERSION or set(manifest.get('files',{}))!=FILES or {p.name for p in root.iterdir()}!=FILES|{'manifest.json'}:
        raise ValueError('evaluation_inventory_invalid')
    if any(not valid_digest(value) for value in manifest['files'].values()):raise ValueError('evaluation_manifest_digest_invalid')
    values={n:read(root/n) for n in FILES}
    for name,value in values.items():
        if digest(value)!=manifest['files'][name]:raise ValueError('evaluation_file_changed')
    frozen_inputs(root,artifact)
    validate_references(values['annotations.json'],values['references.json'])
    from .evaluation_details import evaluate_detailed
    expected=evaluate_detailed(values['adapted.json']['predictions'],values['annotations.json'],values['split.json'],values['registration.json'])
    result=values['result.json'];binding=result.get('bundle_binding',{})
    validate_bundle_binding(binding)
    if {k:v for k,v in result.items() if k!='bundle_binding'}!=expected:raise ValueError('evaluation_result_changed')
    for name,key in [('annotations','annotations_sha256'),('references','references_sha256'),('freeze','freeze_sha256')]:
        if binding.get(key)!=digest(values[name+'.json']):raise ValueError('evaluation_binding_changed')
    if binding.get('artifact_binding_sha256')!=digest(values['adapted.json']['binding']):raise ValueError('artifact_binding_changed')
    if not instant(values['freeze.json']['observed_frozen_at'])<instant(binding['observed_opened_at']) or instant(binding['observed_opened_at'])<instant(values['registration.json']['holdout_opened_at']):
        raise ValueError('evaluation_opening_order_invalid')
    return result


def query_error(root,artifact,identity,*,reference=False):
    verify_bundle(root,artifact)
    if reference:
        refs=read(Path(root)/'references.json')
        if identity not in refs:raise ValueError('reference_not_found')
        return {'annotation_id':identity,'reference':refs[identity], 'status':'independent_declared_reference_not_original_bytes_verified'}
    return query_prediction(artifact,read(Path(root)/'adapted.json'),identity)


def verify_document(document,artifact,*,identity=None,reference=False):
    if not isinstance(document,dict) or set(document)!=FILES|{'manifest.json'}:
        raise ValueError('evaluation_document_inventory_invalid')
    with tempfile.TemporaryDirectory(prefix='cpag-evaluation-review-') as work:
        root=Path(work)
        for name,value in document.items():write(root/name,value)
        result=verify_bundle(root,artifact)
        response={'document':document,'result':result,'document_sha256':digest(document)}
        if identity is not None:response['evidence']=query_error(root,artifact,identity,reference=reference)
        return response


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    f=sub.add_parser('freeze')
    for key in ('artifact','split','registration','output','batch','sample-sha256'):f.add_argument('--'+key,required=True)
    f.add_argument('--projection',choices=('network','process','dual'),default='dual')
    e=sub.add_parser('evaluate')
    for key in ('frozen','artifact','annotations','references','output'):e.add_argument('--'+key,required=True)
    v=sub.add_parser('verify');v.add_argument('--bundle',required=True);v.add_argument('--artifact',required=True)
    q=sub.add_parser('query');q.add_argument('--bundle',required=True);q.add_argument('--artifact',required=True);q.add_argument('--id',required=True);q.add_argument('--reference',action='store_true')
    d=sub.add_parser('verify-document');d.add_argument('--artifact',required=True);d.add_argument('--id');d.add_argument('--reference',action='store_true')
    a=p.parse_args()
    try:
        if a.command=='verify-document':
            data=sys.stdin.buffer.read(8*1024*1024+1)
            if len(data)>8*1024*1024:raise ValueError('evaluation_document_limit')
            result=verify_document(strict_json(data.decode('utf-8')),a.artifact,identity=a.id,reference=a.reference)
        elif a.command=='freeze':result=freeze(a.artifact,read(a.split),read(a.registration),a.output,batch=a.batch,sample_sha256=a.sample_sha256,projection=a.projection)
        elif a.command=='evaluate':result=evaluate_bundle(a.frozen,a.artifact,read(a.annotations),read(a.references),a.output)
        elif a.command=='verify':result=verify_bundle(a.bundle,a.artifact)
        else:result=query_error(a.bundle,a.artifact,a.id,reference=a.reference)
        print(json.dumps(result,sort_keys=True,allow_nan=False));return 0
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'rejected','reason':str(exc)}));return 2

if __name__=='__main__':raise SystemExit(main())
