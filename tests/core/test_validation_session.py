import unittest
from cpag_core.contracts import _validate, ContractError, validation_session

class SessionTests(unittest.TestCase):
    def test_flat_mutation_rechecked_including_bool_int_equality(self):
        schema={'type':'object','properties':{'x':{'type':'integer'}},'required':['x'],'additionalProperties':False}
        value={'x':0}
        with validation_session():
            _validate(schema,value,'first');_validate(schema,value,'second')
            value['x']=False
            with self.assertRaises(ContractError):_validate(schema,value,'third')
            value['x']=1;_validate(schema,value,'fourth')
            value['y']=None
            with self.assertRaises(ContractError):_validate(schema,value,'fifth')
    def test_nested_mutation_never_cached(self):
        schema={'type':'array','items':{'type':'integer'}};value=[1]
        with validation_session():
            _validate(schema,value,'a');value.append('bad')
            with self.assertRaises(ContractError):_validate(schema,value,'b')
    def test_scopes_do_not_reuse_changed_schema(self):
        schema={'type':'object','properties':{'x':{'type':'integer'}}};value={'x':1}
        with validation_session():_validate(schema,value,'a')
        schema['properties']['x']['type']='string'
        with validation_session():
            with self.assertRaises(ContractError):_validate(schema,value,'b')
