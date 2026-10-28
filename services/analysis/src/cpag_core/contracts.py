"""Strict validation of the checked-in JSON Schema subset (stdlib runtime)."""
from datetime import datetime
from contextlib import contextmanager
from contextvars import ContextVar
import json
import math
from pathlib import Path
import re

SCHEMAS = Path(__file__).resolve().parents[4] / 'schemas'

_SESSION = ContextVar('cpag_contract_session', default=None)

@contextmanager
def validation_session():
    """Reuse immutable schema/ref checks only within a synchronous operation.

    Flat dictionaries are compared with typed scalar snapshots before reuse, so
    mutation cannot turn a cached success into acceptance of a changed value.
    Nested/mutable values never enter this memo; the bounded cache is discarded.
    """
    token=_SESSION.set({'schemas':{},'flat':{}})
    try:yield
    finally:_SESSION.reset(token)

def _schema(name):
    session=_SESSION.get()
    if session is None:return json.loads((SCHEMAS/name).read_text())
    if name not in session['schemas']:session['schemas'][name]=json.loads((SCHEMAS/name).read_text())
    return session['schemas'][name]

class ContractError(ValueError):
    pass

def validate(name, value):
    schema = _schema(name + '.schema.json')
    _validate(schema, value, name)
    return value

def _validate(schema, value, path):
    session=_SESSION.get();snapshot=None
    if session is not None and isinstance(value,dict) and all(type(v) in (str,int,float,bool,type(None)) for v in value.values()):
        snapshot=tuple((k,type(v),v) for k,v in value.items())
        entry=session['flat'].get((id(schema),id(value)))
        if entry is not None and entry[0] is value and entry[1]==snapshot:return
    _validate_impl(schema,value,path)
    if snapshot is not None and len(session['flat'])<10000:
        session['flat'][(id(schema),id(value))]=(value,snapshot)

def _validate_impl(schema, value, path):
    if '$ref' in schema:
        _validate(_schema(schema['$ref']), value, path)
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
    if isinstance(value,str) and 'maxLength' in schema and len(value)>schema['maxLength']:
        raise ContractError(f'{path}: above maximum string length')
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
        if 'minItems' in schema and len(value)<schema['minItems']:
            raise ContractError(f'{path}: below minimum array length')
        if 'maxItems' in schema and len(value)>schema['maxItems']:
            raise ContractError(f'{path}: above maximum array length')
        if schema.get('uniqueItems') and len({json.dumps(item,sort_keys=True,ensure_ascii=False,separators=(',',':')) for item in value})!=len(value):
            raise ContractError(f'{path}: duplicate array item')
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
