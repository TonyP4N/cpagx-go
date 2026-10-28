"""Bounded portable reference originals, separate from analysis inputs and labels.

Hashes prove retained bytes match the declared original digest. They do not
prove annotation independence, provenance custody or a declared record locator.
The inventory is embedded in evaluation JSON for exact database/backup retention.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import stat

VERSION = 'evaluation-reference-inventory-1'
FILE_BYTES = 8 * 1024 * 1024
TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 256
STATUS = 'reference_original_bytes_sha256_verified'


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
