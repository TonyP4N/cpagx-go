import os
import json
from typing import Dict, Optional, List


def result_manifest_path(base_dir: str, task_id: str) -> str:
    return os.path.join(base_dir, task_id, "result_manifest.json")


def write_manifest(base_dir: str, task_id: str, manifest: Dict):
    out_dir = os.path.join(base_dir, task_id)
    os.makedirs(out_dir, exist_ok=True)
    path = result_manifest_path(base_dir, task_id)
    
    # 确保created_at字段包含Z后缀（UTC时间标识）
    if 'created_at' in manifest and manifest['created_at']:
        created_at = str(manifest['created_at'])
        if not created_at.endswith('Z') and not created_at.endswith('+00:00'):
            manifest['created_at'] = created_at + 'Z'
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return path


def read_manifest(base_dir: str, task_id: str) -> Optional[Dict]:
    path = result_manifest_path(base_dir, task_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def list_tasks_from_manifests(base_dir: str) -> List[Dict]:
    results: List[Dict] = []
    if not os.path.exists(base_dir):
        return results
    for name in os.listdir(base_dir):
        task_dir = os.path.join(base_dir, name)
        if not os.path.isdir(task_dir):
            continue
        mf = result_manifest_path(base_dir, name)
        if os.path.exists(mf):
            try:
                with open(mf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        results.append(data)
            except Exception:
                continue
    return results


