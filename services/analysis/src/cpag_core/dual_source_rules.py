"""Versioned bounded time, mapping and finite-rule operators; no expression evaluator."""
from datetime import datetime, timezone
import math
import re
from fractions import Fraction
from .contracts import validate
from .pipeline import fingerprint
from .capacity import resolve_capacity_profile

MODE = 'bounded-real-capable-v1'
REAL_LIMITATIONS = ['real_source_unvalidated', 'source_and_authorization_references_not_independently_verified',
                    'no_attack_or_causality_decision', 'response_success_is_not_physical_effect',
                    'endpoint_not_authenticated_actor', 'configured_offsets_not_estimated',
                    'existing_bounded_protocol_subset']


def epoch(value):
    dt=datetime.fromisoformat(value.replace('Z', '+00:00'))
    delta=dt-datetime(1970,1,1,tzinfo=timezone.utc)
    return Fraction(delta.days*86400+delta.seconds)+Fraction(delta.microseconds,1000000)


def validity(item, interval):
    """Whole uncertain interval must lie inside the closed declared UTC validity."""
    if 'valid_from' not in item or 'valid_to' not in item:
        return 'missing' if ('valid_from' in item or 'valid_to' in item) else 'legacy'
    if interval is None:
        return 'unknown'
    low, high = epoch(item['valid_from']), epoch(item['valid_to'])
    if interval[1] < low or interval[0] > high:
        return 'outside'
    return 'applicable' if low <= interval[0] <= interval[1] <= high else 'uncertain'


def validate_profile(config):
    spool=config.get('replay',{}).get('history_format')=='replay-history-checkpoint-delta-2'
    compact=config.get('storage_format')=='shared-observation-dag-6'
    shared=config.get('storage_format') in ('shared-observation-dag-5','shared-observation-dag-6')
    validate('DualCompactProfile' if compact else 'DualSharedProfile' if shared else 'DualSpoolProfile' if spool else 'DualSourceProfile', config)
    budget = resolve_capacity_profile(config)
    if budget.version and 'replay' in config and not (spool or shared):
        raise ValueError('capacity_replay_requires_versioned_history_integration')
    if spool or (shared and 'replay' in config):
        options=config['replay']
        for field,ceiling in (('max_snapshots',budget.snapshots),('max_revisions',budget.revisions),('max_output_bytes',budget.output_bytes),('max_buffer_records',budget.frames+budget.process_records+1 if budget.version else 11000)):
            if options[field]>ceiling:raise ValueError('history_budget_exceeds_capacity_profile:'+field)
        if len(options.get('sequence',[]))>budget.arrival_steps:raise ValueError('arrival_step_limit')
    extended = config.get('analysis_mode') == MODE
    if 'replay' in config and not extended:
        raise ValueError('replay_requires_bounded_analysis_mode')
    if extended:
        def check_precision(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if key in ('valid_from','valid_to','drift_anchor','start','end') and isinstance(item,str) and re.search(r':\d{2}\.\d{7,}',item):raise ValueError('configuration_timestamp_precision_unsupported')
                    check_precision(item)
            elif isinstance(value,list):
                for item in value:check_precision(item)
        check_precision(config)
    if config['synthetic'] is False and not extended:
        raise ValueError('real_input_requires_explicit_analysis_mode')
    r17_fields=('finite_rules' in config or 'source_provenance' in config
        or any(set(clock)-{'offset_seconds','uncertainty_seconds','basis'} for clock in config['clocks'].values())
        or any(set(mapping)&{'version','basis','valid_from','valid_to'} for mapping in config['mappings'])
        or any(key in config['process'] for key in ('timestamp_format','missing_values')))
    if r17_fields and not extended:
        raise ValueError('r17_fields_require_analysis_mode')
    rules = config.get('finite_rules', [])
    if len(rules) > 100:
        raise ValueError('finite_rule_limit')
    identifiers = [r['rule_id'] for r in rules]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError('duplicate_finite_rule_id')
    if config['synthetic'] is False:
        provenance = config.get('source_provenance')
        if not provenance:
            raise ValueError('real_source_provenance_required')
        if epoch(provenance['collection_range']['start']) > epoch(provenance['collection_range']['end']):
            raise ValueError('invalid_source_collection_range')
        for clock in config['clocks'].values():
            if any(key not in clock or clock[key] is None or (isinstance(clock[key],str) and not clock[key].strip()) for key in ('version','basis','valid_from','valid_to','drift_ppm','drift_anchor','drift_basis','precision_seconds','precision_basis')):
                raise ValueError('real_clock_materials_required')
        for mapping in config['mappings']:
            if any(not mapping.get(key) for key in ('version','basis','valid_from','valid_to')):
                raise ValueError('real_mapping_materials_required')
    for item in [*config['clocks'].values(), *config['mappings'], *rules]:
        if ('valid_from' in item) != ('valid_to' in item):
            raise ValueError('incomplete_validity_interval')
        if 'valid_from' in item and epoch(item['valid_from']) > epoch(item['valid_to']):
            raise ValueError('invalid_validity_interval')
    for rule in rules:
        kind = rule['kind']
        if kind != 'state_change' and not {'operator','value'} <= set(rule):
            raise ValueError('finite_rule_operator_and_value_required')
        if kind == 'process_constraint' and not {'other_tag','other_unit','arithmetic'} <= set(rule):
            raise ValueError('constraint_operand_required')
        if kind != 'process_constraint' and any(k in rule for k in ('other_tag','other_unit','arithmetic')):
            raise ValueError('unsupported_rule_parameter')
        if kind == 'state_change' and any(k in rule for k in ('operator','value')):
            raise ValueError('unsupported_state_change_parameter')
        if kind == 'threshold' and type(rule['value']) not in (int,float):
            raise ValueError('threshold_requires_numeric_value')
        if kind == 'process_constraint' and type(rule['value']) not in (int,float):
            raise ValueError('constraint_requires_numeric_value')
    return extended


def outward(value, upper=False):
    result=float(value)
    rounded=Fraction.from_float(result)
    if (upper and rounded<value) or (not upper and rounded>value):
        result=math.nextafter(result,math.inf if upper else -math.inf)
    return result


def clock_time(raw, low, high, clock, legacy, require_materials=False):
    timing = legacy(raw, low, high, clock)
    if not require_materials and not any(k in clock for k in ('version','drift_ppm','precision_seconds','valid_from')):
        return timing
    timing['model'] = {k:v for k,v in clock.items() if k not in ('offset_seconds','uncertainty_seconds','basis')}
    reasons=[]
    if require_materials:
        for name in ('version','drift_ppm','drift_anchor','drift_basis','precision_seconds','precision_basis','valid_from','valid_to'):
            if name not in clock or clock[name] is None or (isinstance(clock[name],str) and not clock[name].strip()):reasons.append('clock_material_missing_'+name)
    if 'drift_ppm' in clock and not all(clock.get(k) for k in ('drift_anchor','drift_basis')):
        reasons.append('drift_basis_missing')
    if 'precision_seconds' in clock and not clock.get('precision_basis'):
        reasons.append('precision_basis_missing')
    status=validity(clock, [low,high] if low is not None else None)
    if status not in ('legacy','applicable'):
        reasons.append('clock_validity_'+status)
    if timing['interval'] is not None and not reasons:
        number=lambda v:Fraction(str(v))
        ppm=number(clock.get('drift_ppm',0))/1000000
        anchor=number(epoch(clock['drift_anchor'])) if 'drift_anchor' in clock else 0
        error=number(clock['uncertainty_seconds'])+number(clock.get('precision_seconds',0))
        # low/high are outward-rounded representations of original source ticks.
        lo,hi=Fraction.from_float(float(low)),Fraction.from_float(float(high))
        timing['interval']=[outward(lo+number(clock['offset_seconds'])+(lo-anchor)*ppm-error),
                            outward(hi+number(clock['offset_seconds'])+(hi-anchor)*ppm+error,True)]
    elif reasons:
        timing.update(status='unknown',interval=None)
    timing['unknown_reasons']=reasons
    return timing


def compare(left, operator, right):
    if operator in ('eq','ne'):
        same = (type(left) in (int,float) and type(right) in (int,float) and left == right) or (type(left) is type(right) and left == right)
        return same if operator == 'eq' else not same
    if type(left) not in (int,float) or type(right) not in (int,float):
        return None
    return {'gt':lambda:left>right, 'ge':lambda:left>=right,
            'lt':lambda:left<right, 'le':lambda:left<=right}[operator]()


def finite_findings(config, groups, group_issues, *, filtered_record_numbers=()):
    """Emit one evidence-backed supported/refuted/unknown finding per applicable input.

    Rules use exact synchronous intervals for other-tag inputs. Ratios are scalar;
    difference/sum require identical units. No interpolation or arbitrary code.
    """
    findings=[]
    for rule in config.get('finite_rules', []):
        rows=groups.get((rule['asset_id'],rule['tag']),[])
        if not rows:
            rows=[None]
        previous=None
        for row in rows:
            selected=[] if row is None else [row]
            unknown=[]; refuted=[]; result=None
            interval=row['time']['interval'] if row else None
            event=row['event'] if row else None
            status=validity(rule,interval)
            if status != 'applicable':unknown.append('rule_validity_'+status)
            if event is None:unknown.append('missing_rule_input')
            elif event['unit'] != rule['unit']:unknown.append('unit_mismatch')
            if group_issues.get((rule['asset_id'],rule['tag'])):
                unknown.extend(group_issues[(rule['asset_id'],rule['tag'])])
            if row and (event['value'] is None or event['quality']['status'] != 'valid'):
                unknown.append('missing_or_invalid_rule_input')
            def companion(tag, unit):
                values=[r for r in groups.get((rule['asset_id'],tag),[]) if interval is not None and r['time']['interval']==interval]
                if len(values)!=1 or group_issues.get((rule['asset_id'],tag)):
                    unknown.append('companion_missing_or_ambiguous');return None
                other=values[0];selected.append(other)
                if other['event']['unit'] != unit:unknown.append('companion_unit_mismatch')
                if other['event']['value'] is None or other['event']['quality']['status'] != 'valid':unknown.append('missing_or_invalid_companion')
                return other['event']['value']
            if row and rule.get('applies_when'):
                condition=rule['applies_when'];v=companion(condition['tag'],condition['unit'])
                if v is not None and not compare(v,'eq',condition['equals']):unknown.append('applicability_not_met')
            if row and not unknown:
                left=event['value']
                if rule['kind']=='state_change':
                    if previous is None:unknown.append('previous_valid_sample_missing')
                    else:
                        selected.append(previous)
                        a,b=previous['event']['source_ref']['record_number'],event['source_ref']['record_number']
                        if a is not None and b is not None and any(min(a,b)<number<max(a,b) for number in filtered_record_numbers):unknown.append('filtered_process_record_gap')
                        elif interval[1]-previous['time']['interval'][0]>config['max_sample_gap_seconds']:unknown.append('sampling_gap')
                        else:result=not compare(left,'eq',previous['event']['value'])
                elif rule['kind']=='process_constraint':
                    right=companion(rule['other_tag'],rule['other_unit'])
                    if not unknown:
                        if type(left) not in (int,float) or type(right) not in (int,float):unknown.append('nonnumeric_constraint_input')
                        elif rule['arithmetic'] in ('sum','difference') and rule['unit'] != rule['other_unit']:unknown.append('constraint_units_incompatible')
                        elif rule['arithmetic']=='ratio' and right==0:unknown.append('division_by_zero')
                        elif rule['arithmetic']=='ratio' and rule['unit'] != rule['other_unit']:unknown.append('constraint_units_incompatible')
                        else:
                            computed={'sum':lambda:left+right,'difference':lambda:left-right,'ratio':lambda:left/right}[rule['arithmetic']]()
                            if not math.isfinite(computed):unknown.append('nonfinite_rule_result')
                            else:result=compare(computed,rule['operator'],rule['value'])
                else:result=compare(left,rule['operator'],rule['value'])
            if result is None and not unknown:unknown.append('incompatible_rule_types')
            if result is False:refuted.append('configured_predicate_false')
            refs=[r['event']['source_ref'] for r in selected]
            finding={'rule_id':rule['rule_id'],'rule_version':rule['version'],'kind':rule['kind'],
                     'parameters':rule,'missing_value_policy':'unknown_no_interpolation','applicability':status,'interval':interval,
                     'state':'unknown' if unknown else 'supported' if result else 'refuted',
                     'support':[] if unknown or not result else ['configured_predicate_true'],
                     'counterevidence':[] if not refuted else [{'reason':refuted[0],'evidence_refs':refs}],
                     'unknown_reasons':sorted(set(unknown)),'evidence_refs':refs,'predicate_result':None if unknown else result}
            finding['finding_id']='rule-'+fingerprint(finding)
            findings.append(finding)
            if len(findings)>10000:raise ValueError('finite_finding_limit')
            previous=row if row and event['value'] is not None and event['quality']['status']=='valid' and interval is not None and status=='applicable' else None
    return findings
