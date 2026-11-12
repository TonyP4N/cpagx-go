"""Bounded portable reference originals, separate from analysis inputs and labels.

Hashes prove retained bytes match the declared original digest. They do not
prove annotation independence or provenance custody. Historical byte-only queries
do not resolve declared record text; only explicit v3 CSV locators resolve records.
The inventory is embedded in evaluation JSON for exact database/backup retention.
"""
import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import re
import stat
from threading import RLock

from .contracts import validate

VERSION = 'evaluation-reference-inventory-1'
FILE_BYTES = 8 * 1024 * 1024
TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 256
STATUS = 'reference_original_bytes_sha256_verified'
LOCATOR_VERSION = 'csv-logical-record-1'
LOCATED_STATUS = 'reference_original_csv_record_verified'
CSV_MAX_COLUMNS = 1024
CSV_MAX_RECORDS = 1000000
_CSV_LIMIT_LOCK = RLock()


def _name(value):
    if (not isinstance(value, str) or not value or len(value) > 1024 or '\\' in value
            or Path(value).is_absolute() or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('reference_inventory_relative_name_required')
    return value


def _sha(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def _read_controlled(root, name):
    """Walk with openat/no-follow; never resolve a caller path outside the root."""
    _name(name)
    root = Path(root).absolute()
    if root.is_symlink():raise ValueError('reference_inventory_symlink_root')
    # The explicitly trusted root may use a platform alias such as macOS /var.
    # Resolve that root once; every untrusted relative component uses no-follow.
    root = root.resolve(strict=True)
    descriptors = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        parts = name.split('/')
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(source)
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > FILE_BYTES:
            raise ValueError('reference_inventory_regular_bounded_unlinked_file_required')
        with os.fdopen(os.dup(source), 'rb') as stream:
            data = stream.read(FILE_BYTES + 1)
        after = os.fstat(source)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(data) > FILE_BYTES or signature(before) != signature(after) or len(data) != after.st_size:
            raise ValueError('reference_original_changed_during_read')
        return data
    except OSError as error:
        raise ValueError('reference_original_missing_or_unsafe') from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def build_inventory(root, files):
    """files maps controlled relative names to independently declared SHA-256."""
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ValueError('reference_inventory_file_count_limit')
    inventory = {'version': VERSION, 'files': {}}
    total = 0
    for name, expected in files.items():
        if not _sha(expected):
            raise ValueError('reference_original_declared_hash_invalid')
        data = _read_controlled(root, name)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError('reference_original_hash_mismatch')
        if actual in inventory['files']:
            raise ValueError('duplicate_reference_original_digest')
        total += len(data)
        if total > TOTAL_BYTES:
            raise ValueError('reference_inventory_total_bytes_limit')
        inventory['files'][actual] = {'name': name, 'size_bytes': len(data),
            'content_base64': base64.b64encode(data).decode('ascii')}
    return inventory


def verify_inventory(inventory, references=None):
    if (not isinstance(inventory, dict) or set(inventory) != {'version', 'files'}
            or inventory['version'] != VERSION or not isinstance(inventory['files'], dict)
            or len(inventory['files']) > MAX_FILES):
        raise ValueError('reference_inventory_contract_invalid')
    expected = {entry['sha256'] for entry in references.values()} if references is not None else set(inventory['files'])
    if set(inventory['files']) != expected:
        raise ValueError('reference_original_inventory_missing_or_unreferenced')
    total = 0
    for expected_sha, entry in inventory['files'].items():
        if (not _sha(expected_sha) or not isinstance(entry, dict)
                or set(entry) != {'name', 'size_bytes', 'content_base64'}):
            raise ValueError('reference_original_entry_invalid')
        _name(entry['name'])
        size = entry['size_bytes']; content = entry['content_base64']
        if (type(size) is not int or not 0 <= size <= FILE_BYTES or not isinstance(content, str)
                or len(content) != 4 * ((size + 2) // 3)):
            raise ValueError('reference_original_encoded_size_invalid')
        total += size
        if total > TOTAL_BYTES:
            raise ValueError('reference_inventory_total_bytes_limit')
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, UnicodeError) as error:
            raise ValueError('reference_original_base64_invalid') from error
        if (len(data) != size or base64.b64encode(data).decode('ascii') != content
                or hashlib.sha256(data).hexdigest() != expected_sha):
            raise ValueError('reference_original_hash_mismatch')
    return inventory


def query_original(inventory, references, identity):
    verify_inventory(inventory, references)
    if identity not in references:
        raise ValueError('reference_not_found')
    declaration = references[identity]
    entry = inventory['files'][declaration['sha256']]
    return {'annotation_id': identity, 'reference': declaration, 'status': STATUS,
            'original': dict(entry, sha256=declaration['sha256']),
            'record_locator_status': 'declared_record_not_independently_resolved',
            'independence_status': 'declared_not_externally_verified'}


def validate_located_reference(reference):
    """A new contract; never interpret a historical free-text record string."""
    validate('EvaluationLocatedReference',reference)
    locator=reference['locator']
    if not reference['source_ref'].strip() or len(reference['source_ref'])>65536:
        raise ValueError('located_reference_source_invalid')
    if locator['file_sha256']!=reference['sha256']:
        raise ValueError('reference_locator_file_identity_mismatch')
    columns=locator['columns']
    if (not 1<=len(columns)<=CSV_MAX_COLUMNS or len(set(columns))!=len(columns)
            or any(not column.strip() or len(column)>4096 or any(c in column for c in '\r\n\x00') for column in columns)):
        raise ValueError('reference_locator_columns_invalid')
    return reference


class _CSVByteLines:
    """Supply UTF-8 physical input to csv, tracking bytes actually consumed.

    The csv reader, not a physical-line index, decides when a logical record
    ends. CRLF and quoted newlines remain untouched in the retained raw slice.
    """
    def __init__(self,data):
        self.stream=io.BytesIO(data);self.offset=0;self.lines=0
    def __iter__(self):return self
    def __next__(self):
        raw=self.stream.readline()
        if not raw:raise StopIteration
        self.offset+=len(raw);self.lines+=1
        if self.lines==1 and raw.startswith(b'\xef\xbb\xbf'):raw=raw[3:]
        return raw.decode('utf-8')


def _fragment(data,start,end,line_start,line_end):
    raw=data[start:end]
    return {'byte_offset':start,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'content_base64':base64.b64encode(raw).decode('ascii'),
            'physical_line_start':line_start,'physical_line_end':line_end}


def _scan_csv(data,requested,necessary,target=None):
    if b'\x00' in data:raise ValueError('reference_csv_nul_invalid')
    lines=_CSVByteLines(data)
    # csv's field limit is process-wide. Serialize our bounded scan and restore
    # the prior value before returning to any legacy analysis/evaluation call.
    with _CSV_LIMIT_LOCK:
        previous=csv.field_size_limit();csv.field_size_limit(max(previous,FILE_BYTES))
        try:
            reader=csv.reader(lines,delimiter=',',quotechar='"',doublequote=True,
                              escapechar=None,skipinitialspace=False,strict=True)
            header=next(reader,None)
            if (not header or len(header)>CSV_MAX_COLUMNS or len(set(header))!=len(header)
                    or any(not name.strip() or len(name)>4096 or any(c in name for c in '\r\n\x00') for name in header)):
                raise ValueError('reference_csv_header_invalid')
            if not necessary<=set(header):raise ValueError('reference_csv_required_column_missing')
            header_end=lines.offset;header_line_end=reader.line_num
            start=header_end;line_start=header_line_end+1;count=0;selected=None
            for row in reader:
                count+=1
                if count>CSV_MAX_RECORDS:raise ValueError('reference_csv_record_limit')
                if len(row)!=len(header):raise ValueError('reference_csv_record_width_invalid')
                end=lines.offset;line_end=reader.line_num
                if target==count:
                    selected={'row':dict(zip(header,row)),
                              'fragment':_fragment(data,start,end,line_start,line_end)}
                start=end;line_start=line_end+1
            if any(number>count for number in requested):raise ValueError('reference_csv_record_out_of_range')
            if target is not None:
                selected.update(header_columns=header,
                    header_fragment=_fragment(data,0,header_end,1,header_line_end),
                    logical_data_record_count=count)
            return selected
        except UnicodeError as error:
            raise ValueError('reference_csv_utf8_invalid') from error
        except csv.Error as error:
            raise ValueError('reference_csv_format_invalid') from error
        finally:csv.field_size_limit(previous)


def verify_locators(inventory,references,*,identity=None):
    """Validate every locator in one complete CSV scan per referenced file.

    Only the requested query's fragment is materialized, not a copy of every
    referenced row/header. No predictions, labels or annotation values are read.
    """
    if not isinstance(references,dict):raise ValueError('located_references_object_required')
    for reference in references.values():validate_located_reference(reference)
    verify_inventory(inventory,references)
    if identity is not None and identity not in references:raise ValueError('reference_not_found')
    groups={}
    for reference in references.values():groups.setdefault(reference['sha256'],[]).append(reference['locator'])
    result=None
    for sha,locators in groups.items():
        entry=inventory['files'][sha]
        if Path(entry['name']).suffix.lower()!='.csv':raise ValueError('reference_csv_format_required')
        data=base64.b64decode(entry['content_base64'],validate=True)
        target=references[identity]['locator'] if identity is not None and references[identity]['sha256']==sha else None
        selected=_scan_csv(data,{locator['record_number'] for locator in locators},
            {column for locator in locators for column in locator['columns']},
            target['record_number'] if target is not None else None)
        if target is not None:
            result={'locator_version':LOCATOR_VERSION,'file_sha256':sha,
                    'record_number':target['record_number'],'columns':target['columns'],
                    'values':{column:selected['row'][column] for column in target['columns']},
                    **{key:value for key,value in selected.items() if key!='row'}}
    return result


def query_csv_original(inventory,references,identity):
    resolved=verify_locators(inventory,references,identity=identity)
    declaration=references[identity];entry=inventory['files'][declaration['sha256']]
    return {'annotation_id':identity,'reference':declaration,'status':LOCATED_STATUS,
            'original_bytes_status':STATUS,'original':dict(entry,sha256=declaration['sha256']),
            'record_locator_status':'csv_logical_record_resolved','resolved_record':resolved,
            'annotation_semantics_status':'not_independently_validated',
            'independence_status':'declared_not_externally_verified'}
