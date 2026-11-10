"""Generated fixture profiles for R17 software checks; no real industrial validation."""
import copy
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
START='2026-01-01T00:00:00Z'
END='2026-01-01T00:01:00Z'


def profile(*, synthetic=True, rules=False):
    config=json.loads((ROOT/'profiles/dual-source-synthetic.json').read_text())
    config.update(synthetic=synthetic,analysis_mode='bounded-real-capable-v1')
    for clock in config['clocks'].values():
        clock.update(version='generated-clock-v1',valid_from=START,valid_to=END,
                     precision_seconds=0,precision_basis='generated exact timestamp reference',
                     drift_ppm=0,drift_anchor=START,drift_basis='generated fixed UTC clock')
    for mapping in config['mappings']:
        mapping.update(version='generated-mapping-v1',basis='generated explicit packet/tag fixture mapping',valid_from=START,valid_to=END)
    config['source_provenance']={'source':'generated R17 fixture exercising source branch; no industrial sample',
        'release':'generated-fixture-v1','authorization_ref':'repository generated software fixture',
        'collection_range':{'start':START,'end':END},'timezone_basis':'generated UTC fixture clock',
        'mapping_evidence_ref':'repository generated packet/tag fixture',
        'rules_evidence_ref':'repository generated finite-rule fixture'}
    if rules:
        common={'version':'generated-rule-v1','asset_id':'synthetic-pump','tag':'pump_state','unit':'synthetic_boolean',
                'basis':'generated rule software reference','valid_from':START,'valid_to':END}
        config['finite_rules']=[dict(common,rule_id='threshold-one',kind='threshold',operator='ge',value=1),
                                dict(common,rule_id='state-change',kind='state_change')]
    return copy.deepcopy(config)
