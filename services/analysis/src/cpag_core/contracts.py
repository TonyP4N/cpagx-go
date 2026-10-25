"""Strict validation of the checked-in JSON Schema subset (stdlib runtime)."""
from datetime import datetime
import json
import math
from pathlib import Path
import re

SCHEMAS = Path(__file__).resolve().parents[4] / 'schemas'

class ContractError(ValueError):
    pass

def validate(name, value):
    schema = json.loads((SCHEMAS / (name + '.schema.json')).read_text())
    _validate(schema, value, name)
    return value

def _validate(schema, value, path):
    if '$ref' in schema:
        _validate(json.loads((SCHEMAS / schema['$ref']).read_text()), value, path)
        return
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise ContractError(f'{path}: wrong constant/schema version')
    if 'enum' in schema and value not in schema['enum']:
        raise ContractError(f'{path}: invalid enum')
    types = schema.get('type', [])
    if isinstance(types, str):
        types = [types]
    checks = {'object':lambda x:isinstance(x,dict), 'array':lambda x:isinstance(x,list),
              'string':lambda x:isinstance(x,str), 'null':lambda x:x is None,
              'boolean':lambda x:isinstance(x,bool), 'integer':lambda x:isinstance(x,int) and not isinstance(x,bool),
              'number':lambda x:isinstance(x,(int,float)) and not isinstance(x,bool) and math.isfinite(x)}
    if types and not any(checks[t](value) for t in types):
        raise ContractError(f'{path}: expected {types}')
    if isinstance(value,dict):
        props = schema.get('properties', {})
        for key in schema.get('required', []):
            if key not in value:
                raise ContractError(f'{path}: missing {key}')
        for key,item in value.items():
            if key in props:
                _validate(props[key],item,path+'.'+key)
            elif schema.get('additionalProperties') is False:
                raise ContractError(f'{path}: unknown field {key}')
            elif isinstance(schema.get('additionalProperties'),dict):
                _validate(schema['additionalProperties'],item,path+'.'+key)
    elif isinstance(value,list):
        for i,item in enumerate(value):
            _validate(schema.get('items',{}),item,f'{path}[{i}]')
    elif isinstance(value,str) and schema.get('format') == 'date-time':
        try:
            if not re.search(schema['pattern'],value):
                raise ValueError('timestamp requires explicit zone')
            datetime.fromisoformat(value.replace('Z','+00:00'))
        except ValueError as error:
            raise ContractError(f'{path}: invalid date-time') from error
    elif isinstance(value,str) and 'pattern' in schema and not re.search(schema['pattern'],value):
        raise ContractError(f'{path}: invalid pattern')
    elif isinstance(value,(int,float)):
        if 'minimum' in schema and value < schema['minimum']:
            raise ContractError(f'{path}: below minimum')
        if 'maximum' in schema and value > schema['maximum']:
            raise ContractError(f'{path}: above maximum')
