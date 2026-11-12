"""Per-run immutable source snapshots and O(1) logical record lookup."""
import csv
import hashlib
import io
import json
from pathlib import Path
from .contracts import ContractError


def signature(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class EvidenceIndex:
    def __init__(self, path, expected_digest=None):
        self.path = Path(path)
        self.signature = signature(self.path)
        data = self.path.read_bytes()
        self.digest = hashlib.sha256(data).hexdigest()
        if signature(self.path) != self.signature or (expected_digest and expected_digest != self.digest):
            raise ContractError('evidence file changed')
        self.size_bytes = len(data)
        try:
            self.text = data.decode('utf-8-sig')
        except UnicodeError as exc:
            raise ContractError('evidence input is not valid UTF-8: ' + self.path.name) from exc
        self.records = {}
        if self.path.suffix.lower() == '.csv':
            reader = csv.reader(io.StringIO(self.text, newline=''), strict=True)
            try:
                header = next(reader, [])
                for number, values in enumerate(reader, 1):
                    if len(values) == len(header):
                        self.records[number] = dict(zip(header, values))
            except csv.Error:
                pass  # preceding complete records retain their logical positions
        else:
            for number, line in enumerate(io.StringIO(self.text), 1):
                try:
                    row = json.loads(line)
                    if isinstance(row, dict):
                        self.records[number] = row
                except ValueError:
                    pass  # invalid earlier JSONL rows never prevent later lookup

    def verify(self):
        digest = hashlib.sha256()
        before = signature(self.path)
        with self.path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        if before != self.signature or signature(self.path) != before or digest.hexdigest() != self.digest:
            raise ContractError('evidence file changed')

    def resolve(self, ref):
        if signature(self.path) != self.signature or ref['file_sha256'] != self.digest:
            raise ContractError('evidence file changed')
        number = ref.get('record_number')
        if ref.get('frame_number') is not None or isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise ContractError('evidence requires a valid logical record number; raw frames unsupported')
        if number not in self.records:
            raise ContractError('evidence logical record does not exist')
        row = self.records[number]
        if ref.get('column') is not None and ref['column'] not in row:
            raise ContractError('evidence column does not exist')
        if self.path.suffix.lower() == '.jsonl' and ref.get('raw_time') != row.get('raw_time'):
            raise ContractError('evidence raw time differs')
        return dict(row)
