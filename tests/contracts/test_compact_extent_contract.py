"""Outer manifest extents: hand-stated limits and real runtime validation.

These are schema/runtime boundary checks, never a large capacity measurement.
The expected numbers are independent of the capacity resolver implementation.
"""
import json
import unittest

from cpag_core.contracts import ContractError,SCHEMAS,_validate,validate,validation_session

LEGACY_EXTENT=549755813888
LARGE_EXTENT=4503599627370496


def manifest(version):
    budget={'version':version,'physical_bytes':1073741824,'max_nodes':8000000,
        'max_roots':160000,'max_node_bytes':8388608,'max_dict_items':4096,
        'cache_bytes':16777216,'query_bytes':8388608,'query_items':100,
        'max_logical_root_bytes':LARGE_EXTENT if version=='shared-storage-budget-2' else LEGACY_EXTENT}
    result={'schema_version':'1.0.0','synthetic':True,'run_id':'extent-contract','attempt_id':1,
        'input_fingerprint':'a'*64,'config_fingerprint':'b'*64,'tool_versions':{'core':'test','python':'test'},
        'mode':'replay','artifacts':[],'result_hashes':{'events':'c'*64,'graph':'d'*64},
        'limitations':[],'status':'succeeded','warnings':[],'source_fingerprint':'e'*64,
        'semantic_config_fingerprint':'f'*64,'shared_manifest_sha256':'0'*64,
        'storage_format':'shared-observation-dag-6','result_hash_kind':'merkle-json-dag-1',
        'storage_budget':budget,'network_count':1,'graph_identity_strategy':'merkle-json-dag-1',
        'counts':dict(network=0,process=0,operations=0,changes=0,candidates=0,snapshots=1,revisions=0),
        'history_format':'shared-observation-dag-6','identity_strategy':'merkle-json-dag-1',
        'replay_version':'dual-source-replay-1','prefix_digest_strategy':'incremental-prefix-digest-2',
        'final_snapshot_number':0,'final_snapshot_id':'snapshot-'+'1'*64}
    result['logical_artifacts']=[{'name':name,'digest':'2'*64,'logical_bytes':2,'kind':'array_leaf','items':0}
        for name in ('analysis.json','events.json','graph.json','history/snapshots','history/revisions')]
    return result


class CompactExtentContractTests(unittest.TestCase):
    def test_independent_jsonschema_and_runtime_agree_on_full_manifest_boundaries(self):
        from jsonschema import Draft202012Validator
        schema=json.loads((SCHEMAS/'CompactStoreRunManifest.schema.json').read_text())
        Draft202012Validator.check_schema(schema);independent=Draft202012Validator(schema)
        for version,maximum in (('shared-storage-budget-1',LEGACY_EXTENT),('shared-storage-budget-2',LARGE_EXTENT)):
            for extent,expected in ((2,True),(maximum,True),(maximum+1,False)):
                value=manifest(version);value['logical_artifacts'][3]['logical_bytes']=extent
                with self.subTest(version=version,extent=extent):
                    self.assertEqual(independent.is_valid(value),expected)
                    if expected:validate('CompactStoreRunManifest',value)
                    else:
                        with self.assertRaises(ContractError):validate('CompactStoreRunManifest',value)

    def test_full_outer_manifest_each_version_exact_boundary_and_one_above(self):
        for version,maximum in (('shared-storage-budget-1',LEGACY_EXTENT),('shared-storage-budget-2',LARGE_EXTENT)):
            with self.subTest(version=version):
                value=manifest(version);value['logical_artifacts'][3]['logical_bytes']=maximum
                self.assertIs(validate('CompactStoreRunManifest',value),value)
                value['logical_artifacts'][3]['logical_bytes']=maximum+1
                with self.assertRaisesRegex(ContractError,'logical_bytes: above maximum'):
                    validate('CompactStoreRunManifest',value)

    def test_budget2_accepts_above_legacy_boundary_without_materializing_content(self):
        value=manifest('shared-storage-budget-2')
        value['logical_artifacts'][3]['logical_bytes']=LEGACY_EXTENT+1
        validate('CompactStoreRunManifest',value)

    def test_version_and_declared_extent_budget_cannot_be_crossed(self):
        for version,wrong in (('shared-storage-budget-1',LARGE_EXTENT),('shared-storage-budget-2',LEGACY_EXTENT)):
            with self.subTest(version=version):
                value=manifest(version);value['storage_budget']['max_logical_root_bytes']=wrong
                with self.assertRaises(ContractError):validate('CompactStoreRunManifest',value)

    def test_missing_and_unknown_budget_versions_are_rejected(self):
        for value in (None,'shared-storage-budget-3'):
            document=manifest('shared-storage-budget-1')
            if value is None:document['storage_budget'].pop('version')
            else:document['storage_budget']['version']=value
            with self.subTest(version=value),self.assertRaises(ContractError):validate('CompactStoreRunManifest',document)

    def test_session_does_not_reuse_pass_after_nested_extent_or_version_changes(self):
        value=manifest('shared-storage-budget-2');value['logical_artifacts'][3]['logical_bytes']=LEGACY_EXTENT+1
        with validation_session():
            validate('CompactStoreRunManifest',value)
            value['storage_budget'].update(version='shared-storage-budget-1',max_logical_root_bytes=LEGACY_EXTENT)
            with self.assertRaises(ContractError):validate('CompactStoreRunManifest',value)


class ConditionalSubsetTests(unittest.TestCase):
    def test_allof_checks_every_branch(self):
        schema={'allOf':[{'type':'integer','minimum':1},{'maximum':3}]}
        _validate(schema,2,'number')
        for value in (0,4,'two'):
            with self.subTest(value=value),self.assertRaises(ContractError):_validate(schema,value,'number')

    def test_matching_missing_and_nonmatching_condition_use_the_correct_branch(self):
        schema={'type':'object','if':{'required':['kind'],'properties':{'kind':{'const':'new'}}},
            'then':{'required':['new_value'],'properties':{'new_value':{'const':4}}},
            'else':{'required':['old_value'],'properties':{'old_value':{'const':2}}}}
        for value in ({'kind':'new','new_value':4},{'kind':'old','old_value':2},{'old_value':2}):
            _validate(schema,value,'conditional')
        for value in ({'kind':'new','old_value':2},{'kind':'old','new_value':4},{'new_value':4},
                      {'kind':'new','new_value':5},{'old_value':3}):
            with self.subTest(value=value),self.assertRaises(ContractError):_validate(schema,value,'conditional')

    def test_absent_then_or_else_does_not_make_if_a_rejection_rule(self):
        _validate({'if':{'const':1}},2,'if-only')
        _validate({'if':{'const':1},'then':{'const':1}},2,'no-else')
        _validate({'if':{'const':1},'else':{'const':2}},1,'no-then')

    def test_condition_ref_error_is_not_hidden_as_an_else_match(self):
        with self.assertRaises(OSError):
            _validate({'if':{'$ref':'nonexistent-conditional-test.schema.json'},'else':{}},1,'missing-ref')


if __name__=='__main__':unittest.main()
