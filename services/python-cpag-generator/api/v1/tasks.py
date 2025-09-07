#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Celery tasks for v1 — delegate compute via the shared generators
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from infrastructure.celery_app import celery_app
from core.generators import PCAPCPAGGenerator, CSVCPAGGenerator
from infrastructure.status import write_manifest
from core.config import get_config

# Concurrency control
config = get_config()
MAX_CONCURRENT_TASKS = config.max_concurrent_tasks_v1
import redis
try:
    redis_client = redis.from_url(config.redis_url)
except Exception:
    redis_client = None


@celery_app.task(bind=True)
def generate_cpag(
    self,
    task_id: str,
    file_path: Optional[str],
    csv_path: Optional[str],
    device_map: Dict[str, str],
    rules: List[str],
    output_dir: str,
    file_size: Optional[int] = None,
    file_name: Optional[str] = None,
):
    """v1 generation task: build a single cpag.json in output_dir/task_id"""
    try:
        # Check concurrency limits
        current_active = 0
        if redis_client:
            try:
                current_active = len(redis_client.smembers("v1_active_tasks"))
            except Exception:
                pass
        
        if current_active >= MAX_CONCURRENT_TASKS:
            raise Exception(f"Too many concurrent tasks. Maximum allowed: {MAX_CONCURRENT_TASKS}")
        
        # Add to active task set
        if redis_client:
            try:
                redis_client.sadd("v1_active_tasks", task_id)
                redis_client.expire("v1_active_tasks", 3600)  # 1 hour expiry
            except Exception:
                pass
        
        

        
        out_dir = os.path.join(output_dir, task_id)
        os.makedirs(out_dir, exist_ok=True)

        cpag_graph: Dict[str, Any] = {}
        if file_path:
            pgen = PCAPCPAGGenerator()
            pcap_data = pgen.parse_pcap(file_path)
            cpag_graph = pgen.build_cpag(pcap_data, device_map)
        elif csv_path:
            cgen = CSVCPAGGenerator()
            csv_df = cgen.parse_csv(csv_path)
            cpag_graph = cgen.build_cpag(csv_df, device_map)
        else:
            cpag_graph = {"nodes": [], "edges": [], "metadata": {"generated_at": datetime.utcnow().isoformat()}}

        cpag_json_path = os.path.join(out_dir, 'cpag.json')
        with open(cpag_json_path, 'w', encoding='utf-8') as f:
            json.dump(cpag_graph, f, ensure_ascii=False, indent=2)

        manifest = {
            "task_id": task_id,
            "version": "v1",
            "status": "completed",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "files": ["cpag.json"],
            "file_size": file_size,
            "file_name": file_name,
        }
        write_manifest(output_dir, task_id, manifest)

        return {"status": "completed", "task_id": task_id}
    except Exception as e:
        err_path = os.path.join(output_dir, task_id, 'error.log')
        try:
            with open(err_path, 'w', encoding='utf-8') as f:
                f.write(str(e))
        except Exception:
            pass
        return {"status": "failed", "task_id": task_id, "error": str(e)}
    finally:
        # Remove from active task set
        if redis_client:
            try:
                redis_client.srem("v1_active_tasks", task_id)
            except Exception:
                pass


