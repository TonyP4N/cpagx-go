"""Content identity of the bundled file-sidecar verifier, independent of Docker."""
import argparse
import hashlib
import json
from pathlib import Path


def source_identity(root):
    root = Path(root).resolve()
    analysis = list((root/'services/analysis/src/cpag_core').rglob('*.py'))
    schemas = list((root/'schemas').glob('*.json'))
    if not analysis or not schemas:
        raise ValueError('complete verifier analysis and schemas required')
    paths = analysis + schemas + [root/'source-verifier.py', root/'verifier_identity.py']
    manifest = []
    for path in sorted(paths):
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            raise ValueError('regular bundled verifier sources required')
        manifest.append([path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()])
    encoded = json.dumps(manifest, separators=(',', ':'), ensure_ascii=True).encode()
    return 'source-sha256:'+hashlib.sha256(encoded).hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='/opt/cpag')
    print(source_identity(parser.parse_args().root))
