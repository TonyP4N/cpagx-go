"""Independent admission and paging guards for the fixed core-only matrix.

These checks admit an attempt; they never certify generated runtime results.
The generator's exact, independently generated raw bytes/profile/schedule are
recomputed before a cell starts. No gold labels or predictor are consulted.
"""
import hashlib
from pathlib import Path


def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1024**2),b''):value.update(data)
    return value.hexdigest()


def admit_fixture(fixture,profile,scale,mode,*,fixture_version='r19-density-capacity-5'):
    from round19_scale_fixture import RAW_SHA256,read_preflight
    fixture=Path(fixture).resolve();profile=Path(profile).resolve()
    source_mode={'offline':'dual_source','replay':'dual_source_replay'}[mode]
    admission=read_preflight(fixture/(source_mode+'-1.json'),require_new=True)
    if fixture_version not in ('r19-density-capacity-5','r19-density-capacity-6'):
        raise ValueError('unsupported_registered_core_fixture')
    if (admission['fixture_version']!=fixture_version
            or admission['scale']!=scale or admission['mode']!=source_mode
            or admission['status']!='admissible_for_core_attempt'
            or admission['integration_ready'] is not False):
        raise ValueError('registered_core_generator5_or_6_fixture_required')
    if profile!=fixture/admission['profile'] or sha(profile)!=admission['profile_sha256']:
        raise ValueError('frozen_density_profile_identity_mismatch')
    if any(sha(fixture/name)!=digest for name,digest in RAW_SHA256[scale].items()):
        raise ValueError('fixed_density_original_sha_mismatch')
    # The reader recomputes the entire generated configuration and schedule,
    # including 5s association windows, 300s buffer and 2s allowed lateness.
    return admission


def check_counts(counts,scale):
    from round19_scale_fixture import density_budget_math
    expected=density_budget_math(scale)
    for name in ('operations','changes'):
        if type(counts.get(name)) is not int or counts[name]!=expected[name]:
            raise ValueError('hand_fixed_density_count_mismatch:'+name)
    for name,target in (('network',2*expected['operations']),('process',expected['process_records'])):
        if type(counts.get(name)) is not int or counts[name]!=target:
            raise ValueError('hand_fixed_density_count_mismatch:'+name)
    count=counts.get('candidates')
    if type(count) is not int or not expected['candidate_count_lower_bound']<=count<=expected['candidate_count_upper_bound']:
        raise ValueError('independent_density_candidate_bound_mismatch')
    return {'candidate_count_lower_bound':expected['candidate_count_lower_bound'],
        'candidate_count_upper_bound':expected['candidate_count_upper_bound'],
        'scope':'independent count geometry only; not a complete semantic comparison'}


class EvidencePages:
    """Require contiguous, unique, complete pages without trusting has_more."""
    def __init__(self):self.offset=0;self.total=None;self.seen=set();self.finished=False

    def add(self,info,rows):
        if self.finished:raise ValueError('evidence_page_after_completion')
        for key in ('offset','limit','returned','total'):
            if type(info.get(key)) is not int:raise ValueError('evidence_page_integer_required:'+key)
        if (info['offset']!=self.offset or not 1<=info['limit']<=100
                or info['returned']!=len(rows) or not 0<=len(rows)<=info['limit']
                or info['total']<self.offset+len(rows) or type(info.get('has_more')) is not bool):
            raise ValueError('evidence_page_contract_mismatch')
        if self.total is None:self.total=info['total']
        if self.total!=info['total']:raise ValueError('evidence_page_total_changed')
        import json
        for row in rows:
            identity=json.dumps(row['source_ref'],sort_keys=True,separators=(',',':'),ensure_ascii=False)
            if identity in self.seen:raise ValueError('evidence_reference_repeated_across_pages')
            self.seen.add(identity)
        self.offset+=len(rows);expected_more=self.offset<self.total
        if info['has_more']!=expected_more or (expected_more and not rows):
            raise ValueError('evidence_page_premature_or_nonadvancing_end')
        self.finished=not expected_more
        return self.finished
