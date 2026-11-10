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
from . import evaluation_details as details_api
from .reference_inventory import build_inventory, verify_inventory, query_original, STATUS as ORIGINAL_STATUS
from .reference_inventory import (LOCATOR_VERSION,LOCATED_STATUS,validate_located_reference,
                                  verify_locators,query_csv_original)

VERSION='evaluation-bundle-1'
V2_VERSION='evaluation-bundle-2'
V3_VERSION='evaluation-bundle-3'
LEGACY_DOCUMENT_BYTES=8*1024*1024
V2_DOCUMENT_BYTES=128*1024*1024
FILES={'registration.json','split.json','adapted.json','annotations.json','references.json','result.json','freeze.json'}
CUSTODY='local_clock_and_files_not_external_independence_proof'
REFERENCE_STATUS='declared_independent_reference_not_original_bytes_verified'
FREEZE_FIELDS={'version','observed_frozen_at','registration_sha256','split_sha256','adapted_sha256',
    'binding_sha256','matching','details_version','custody'}
BINDING_FIELDS={'version','freeze_sha256','artifact_binding_sha256','annotations_sha256',
    'references_sha256','observed_opened_at','reference_status'}


def document_limit(version):
    if version==VERSION:return LEGACY_DOCUMENT_BYTES
    if version in (V2_VERSION,V3_VERSION):return V2_DOCUMENT_BYTES
    raise ValueError('unsupported_evaluation_bundle_version')


def files_for_version(version):
    document_limit(version)
    return FILES|{'reference_inventory.json'} if version in (V2_VERSION,V3_VERSION) else FILES


def matching_pair(matching,detail=None):
    return details_api.validate_matching_version(matching,detail)


def enforce_document_limit(document):
    if not isinstance(document,dict):raise ValueError('evaluation_document_inventory_invalid')
    manifest=document.get('manifest.json')
    if not isinstance(manifest,dict):raise ValueError('evaluation_document_inventory_invalid')
    version=manifest.get('version')
    if len(canonical(document))>document_limit(version):raise ValueError('evaluation_document_limit')
    return version


def exact_fields(value,fields,reason):
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError(reason)


def valid_digest(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def checked_time(value):
    if not isinstance(value,str):raise ValueError('evaluation_timestamp_invalid')
    return instant(value)


def validate_freeze(frozen,registration):
    if not isinstance(frozen,dict):raise ValueError('frozen_contract_invalid')
    version=frozen.get('version');document_limit(version)
    fields=FREEZE_FIELDS|{'reference_inventory_sha256'} if version in (V2_VERSION,V3_VERSION) else FREEZE_FIELDS
    if version==V3_VERSION:fields=fields|{'reference_locator_version'}
    exact_fields(frozen,fields,'frozen_contract_invalid')
    matching_pair(frozen['matching'],frozen['details_version'])
    if ((version==VERSION and (frozen['matching']!=MATCHING_VERSION or frozen['details_version']!=DETAILS_VERSION))
            or frozen['custody']!=CUSTODY):
        raise ValueError('unsupported_evaluation_version_or_custody')
    if version==V3_VERSION and frozen['reference_locator_version']!=LOCATOR_VERSION:
        raise ValueError('unsupported_reference_locator_version')
    if any(not valid_digest(frozen[name]) for name in fields if name.endswith('_sha256')):
        raise ValueError('frozen_digest_invalid')
    observed=checked_time(frozen['observed_frozen_at']);registered=checked_time(registration['registered_at'])
    opening=checked_time(registration['holdout_opened_at'])
    if registered>observed:raise ValueError('registration_cannot_follow_observed_freeze')
    if not registered<=observed<opening:raise ValueError('system_freeze_must_precede_declared_opening')


def validate_references(annotations,references,version=VERSION):
    check_schema('EvaluationAnnotations',annotations)
    if not isinstance(references,dict) or set(references)!={e['id'] for e in annotations['events']}:
        raise ValueError('every_gold_requires_independent_reference')
    for value in references.values():
        if version==V3_VERSION:
            validate_located_reference(value)
            continue
        exact_fields(value,{'source_ref','record','sha256'},'independent_reference_invalid')
        if not all(isinstance(v,str) and v.strip() and len(v)<=65536 for v in value.values()):
            raise ValueError('independent_reference_invalid')
        if not valid_digest(value['sha256']):raise ValueError('reference_hash_invalid')


def validate_bundle_binding(binding,version=VERSION):
    fields=BINDING_FIELDS|{'reference_inventory_sha256'} if version in (V2_VERSION,V3_VERSION) else BINDING_FIELDS
    if version==V3_VERSION:fields=fields|{'reference_locator_version'}
    exact_fields(binding,fields,'evaluation_binding_contract_invalid')
    status=LOCATED_STATUS if version==V3_VERSION else ORIGINAL_STATUS if version==V2_VERSION else REFERENCE_STATUS
    if binding['version']!=version or binding['reference_status']!=status:
        raise ValueError('evaluation_binding_version_or_reference_status_invalid')
    if version==V3_VERSION and binding['reference_locator_version']!=LOCATOR_VERSION:
        raise ValueError('unsupported_reference_locator_version')
    if any(not valid_digest(binding[name]) for name in fields if name.endswith('_sha256')):
        raise ValueError('evaluation_binding_digest_invalid')
    checked_time(binding['observed_opened_at'])


def read(path,*,limit=LEGACY_DOCUMENT_BYTES):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:
        raise ValueError('ordinary_bounded_json_required')
    return strict_json(path.read_text(encoding='utf-8'))


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


def freeze(artifact,split,registration,output,*,batch,sample_sha256,projection='dual',
           matching_version=MATCHING_VERSION,bundle_version=VERSION,reference_inventory=None):
    document_limit(bundle_version);detail_version=matching_pair(matching_version)
    if bundle_version==VERSION and matching_version!=MATCHING_VERSION:
        raise ValueError('new_matching_requires_explicit_bundle_v2')
    if bundle_version in (V2_VERSION,V3_VERSION):
        verify_inventory(reference_inventory)
    elif reference_inventory is not None:raise ValueError('reference_originals_require_explicit_bundle_v2')
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
    frozen={'version':bundle_version,'observed_frozen_at':observed,'registration_sha256':digest(registration),
        'split_sha256':digest(split),'adapted_sha256':digest(adapted),'binding_sha256':digest(adapted['binding']),
        'matching':matching_version,'details_version':detail_version,
        'custody':CUSTODY}
    if bundle_version in (V2_VERSION,V3_VERSION):frozen['reference_inventory_sha256']=digest(reference_inventory)
    if bundle_version==V3_VERSION:frozen['reference_locator_version']=LOCATOR_VERSION
    validate_freeze(frozen,registration)
    payload={'registration.json':registration,'split.json':split,'adapted.json':adapted,'freeze.json':frozen}
    if bundle_version in (V2_VERSION,V3_VERSION):payload['reference_inventory.json']=reference_inventory
    if bundle_version in (V2_VERSION,V3_VERSION) and len(canonical(payload))>document_limit(bundle_version):raise ValueError('evaluation_document_limit')
    publish(output,payload)
    completed=instant(datetime.now(timezone.utc).isoformat())
    if completed<instant(observed) or completed>=instant(registration['holdout_opened_at']):
        shutil.rmtree(Path(output).absolute())
        raise ValueError('completed_freeze_must_precede_declared_opening')
    return frozen


def frozen_inputs(root,artifact):
    root=Path(root)
    frozen=read(root/'freeze.json');limit=document_limit(frozen.get('version'))
    values={n:read(root/(n+'.json'),limit=limit) for n in ('registration','split','adapted','freeze')}
    if frozen['version'] in (V2_VERSION,V3_VERSION):
        inventory=read(root/'reference_inventory.json',limit=limit);verify_inventory(inventory)
        if digest(inventory)!=frozen.get('reference_inventory_sha256'):raise ValueError('frozen_reference_original_inventory_changed')
        values['reference_inventory']=inventory
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
    version=values['freeze']['version']
    validate_references(annotations,references,version)
    if version in (V2_VERSION,V3_VERSION):verify_inventory(values['reference_inventory'],references)
    if version==V3_VERSION:verify_locators(values['reference_inventory'],references)
    result=evaluate_detailed(values['adapted']['predictions'],annotations,values['split'],values['registration'],matching_version=values['freeze']['matching'])
    result['bundle_binding']={'version':version,'freeze_sha256':digest(values['freeze']),
        'artifact_binding_sha256':digest(values['adapted']['binding']),'annotations_sha256':digest(annotations),
        'references_sha256':digest(references),'observed_opened_at':opened,
        'reference_status':LOCATED_STATUS if version==V3_VERSION else ORIGINAL_STATUS if version==V2_VERSION else REFERENCE_STATUS}
    if version in (V2_VERSION,V3_VERSION):result['bundle_binding']['reference_inventory_sha256']=digest(values['reference_inventory'])
    if version==V3_VERSION:result['bundle_binding']['reference_locator_version']=LOCATOR_VERSION
    payload={n+'.json':v for n,v in values.items()}
    payload.update({'annotations.json':annotations,'references.json':references,'result.json':result})
    manifest={'version':version,'files':{n:digest(v) for n,v in payload.items()}}
    document={**payload,'manifest.json':manifest}
    if version in (V2_VERSION,V3_VERSION):enforce_document_limit(document)
    publish(output,document)
    return result


def verify_bundle(root,artifact):
    root=Path(root);manifest=read(root/'manifest.json')
    exact_fields(manifest,{'version','files'},'evaluation_manifest_contract_invalid')
    version=manifest['version'];files=files_for_version(version);limit=document_limit(version)
    exact_fields(manifest['files'],files,'evaluation_manifest_files_contract_invalid')
    if {p.name for p in root.iterdir()}!=files|{'manifest.json'}:
        raise ValueError('evaluation_inventory_invalid')
    if any(not valid_digest(value) for value in manifest['files'].values()):raise ValueError('evaluation_manifest_digest_invalid')
    values={n:read(root/n,limit=limit) for n in files}
    # Historical directory bundles were bounded per file. Keep that reader
    # contract; transport/database documents retain their separate 8 MiB cap.
    if version in (V2_VERSION,V3_VERSION):enforce_document_limit({**values,'manifest.json':manifest})
    for name,value in values.items():
        if digest(value)!=manifest['files'][name]:raise ValueError('evaluation_file_changed')
    frozen_inputs(root,artifact)
    if values['freeze.json']['version']!=version:raise ValueError('evaluation_bundle_version_mismatch')
    validate_references(values['annotations.json'],values['references.json'],version)
    from .evaluation_details import evaluate_detailed
    if version in (V2_VERSION,V3_VERSION):verify_inventory(values['reference_inventory.json'],values['references.json'])
    if version==V3_VERSION:verify_locators(values['reference_inventory.json'],values['references.json'])
    expected=evaluate_detailed(values['adapted.json']['predictions'],values['annotations.json'],values['split.json'],values['registration.json'],matching_version=values['freeze.json']['matching'])
    result=values['result.json'];binding=result.get('bundle_binding',{})
    validate_bundle_binding(binding,version)
    if version in (V2_VERSION,V3_VERSION) and binding['reference_inventory_sha256']!=digest(values['reference_inventory.json']):
        raise ValueError('evaluation_reference_inventory_binding_changed')
    if {k:v for k,v in result.items() if k!='bundle_binding'}!=expected:raise ValueError('evaluation_result_changed')
    for name,key in [('annotations','annotations_sha256'),('references','references_sha256'),('freeze','freeze_sha256')]:
        if binding.get(key)!=digest(values[name+'.json']):raise ValueError('evaluation_binding_changed')
    if binding.get('artifact_binding_sha256')!=digest(values['adapted.json']['binding']):raise ValueError('artifact_binding_changed')
    if not instant(values['freeze.json']['observed_frozen_at'])<instant(binding['observed_opened_at']) or instant(binding['observed_opened_at'])<instant(values['registration.json']['holdout_opened_at']):
        raise ValueError('evaluation_opening_order_invalid')
    return result


def query_error(root,artifact,identity,*,reference=False):
    verify_bundle(root,artifact)
    version=read(Path(root)/'manifest.json')['version'];limit=document_limit(version)
    if reference:
        refs=read(Path(root)/'references.json',limit=limit)
        if identity not in refs:raise ValueError('reference_not_found')
        if version==V3_VERSION:
            return query_csv_original(read(Path(root)/'reference_inventory.json',limit=V2_DOCUMENT_BYTES),refs,identity)
        if version==V2_VERSION:
            return query_original(read(Path(root)/'reference_inventory.json',limit=V2_DOCUMENT_BYTES),refs,identity)
        return {'annotation_id':identity,'reference':refs[identity], 'status':'independent_declared_reference_not_original_bytes_verified'}
    return query_prediction(artifact,read(Path(root)/'adapted.json',limit=limit),identity)


def verify_document(document,artifact,*,identity=None,reference=False):
    version=enforce_document_limit(document)
    if set(document)!=files_for_version(version)|{'manifest.json'}:
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
    f.add_argument('--bundle-version',choices=(VERSION,V2_VERSION,V3_VERSION),default=VERSION)
    f.add_argument('--matching-version',default=MATCHING_VERSION)
    f.add_argument('--reference-root');f.add_argument('--reference-files')
    e=sub.add_parser('evaluate')
    for key in ('frozen','artifact','annotations','references','output'):e.add_argument('--'+key,required=True)
    v=sub.add_parser('verify');v.add_argument('--bundle',required=True);v.add_argument('--artifact',required=True)
    q=sub.add_parser('query');q.add_argument('--bundle',required=True);q.add_argument('--artifact',required=True);q.add_argument('--id',required=True);q.add_argument('--reference',action='store_true')
    d=sub.add_parser('verify-document');d.add_argument('--artifact',required=True);d.add_argument('--id');d.add_argument('--reference',action='store_true')
    d.add_argument('--service-publication-sha256',help=argparse.SUPPRESS)
    d.add_argument('--service-envelope',action='store_true',help=argparse.SUPPRESS)
    a=p.parse_args()
    try:
        if a.command=='verify-document':
            maximum=2*V2_DOCUMENT_BYTES+1024 if a.service_envelope else V2_DOCUMENT_BYTES
            data=sys.stdin.buffer.read(maximum+1)
            if len(data)>maximum:raise ValueError('evaluation_document_limit')
            document=strict_json(data.decode('utf-8'));prepared=None
            if a.service_envelope:
                if (a.service_publication_sha256 is None
                        or set(document)!={'version','document','prepared_adapted'}
                        or document['version']!='evaluation-service-envelope-1'):
                    raise ValueError('invalid_evaluation_service_envelope')
                prepared=document['prepared_adapted'];document=document['document']
            from .evaluation_context import service_publication
            with service_publication(a.artifact,a.service_publication_sha256,prepared_adapted=prepared):
                result=verify_document(document,a.artifact,identity=a.id,reference=a.reference)
        elif a.command=='freeze':
            inventory=None
            if a.bundle_version in (V2_VERSION,V3_VERSION):
                if not a.reference_root or not a.reference_files:raise ValueError('controlled_reference_inventory_required')
                inventory=build_inventory(a.reference_root,read(a.reference_files))
            elif a.reference_root or a.reference_files:raise ValueError('reference_originals_require_explicit_bundle_v2')
            result=freeze(a.artifact,read(a.split,limit=document_limit(a.bundle_version)),read(a.registration),a.output,
                batch=a.batch,sample_sha256=a.sample_sha256,projection=a.projection,
                matching_version=a.matching_version,bundle_version=a.bundle_version,reference_inventory=inventory)
        elif a.command=='evaluate':
            limit=document_limit(read(Path(a.frozen)/'freeze.json')['version'])
            result=evaluate_bundle(a.frozen,a.artifact,read(a.annotations,limit=limit),read(a.references,limit=limit),a.output)
        elif a.command=='verify':result=verify_bundle(a.bundle,a.artifact)
        else:result=query_error(a.bundle,a.artifact,a.id,reference=a.reference)
        print(json.dumps(result,sort_keys=True,allow_nan=False));return 0
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'rejected','reason':str(exc)}));return 2

if __name__=='__main__':raise SystemExit(main())
