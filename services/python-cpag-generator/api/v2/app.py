#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Generator v2.0 - Enhanced FastAPI Application
Support for ENIP/CIP protocol parsing, Neo4j integration and enhanced visualization
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Dict, List, Optional, Any
import uuid
import asyncio
from datetime import datetime
import os
import tempfile
import json
import subprocess
import sys
from pathlib import Path
import glob
from infrastructure.files import (
    ensure_output_dir,
    save_upload_validated,
    cleanup_temp_files,
    assign_compatible_file_param,
)
from infrastructure.status import read_manifest, list_tasks_from_manifests


app = FastAPI(title="CPAG Generator v2.0", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Output directory
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs/v2"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

from core.models import CPAGResponse, TaskInfo
VERSION = "v2"

# Concurrency control
from core.config import get_config
config = get_config()
import redis
try:
    redis_client = redis.from_url(config.redis_url)
except Exception:
    redis_client = None

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cpag-generator-v2", "version": VERSION, "port": int(os.getenv("PORT", 8002))}

@app.post("/cpag/generate", response_model=CPAGResponse)
async def generate_cpag(
    file: Optional[UploadFile] = File(None),
    pcap_file: Optional[UploadFile] = File(None),
    csv_file: Optional[UploadFile] = File(None),
    device_map: str = Form("{}"),
    rules: str = Form("[]"),
    output_format: str = Form("tcity"),
    custom_params: Optional[str] = Form(None),  # Support custom parameters
    # v2 version specific parameters
    neo4j_uri: Optional[str] = Form(None),
    neo4j_user: Optional[str] = Form(None),
    neo4j_password: Optional[str] = Form(None),
    neo4j_db: str = Form("neo4j"),
    neo4j_label: str = Form("CPAGNode"),
    wipe_neo4j: bool = Form(False),
    top_k: int = Form(40),
    top_per_plc: int = Form(20),
    build_enhanced: bool = Form(False),
    pre_window: int = Form(20),
    post_window: int = Form(20),
    per_tag: int = Form(5),
    top_k_analog: int = Form(3),
    visualize: bool = Form(True)
):
    """Async CPAG generation interface - v2"""
    task_id = str(uuid.uuid4())
    created_at_str = datetime.utcnow().isoformat() + "Z"
    
    # Parse parameters
    try:
        device_map_dict = json.loads(device_map) if device_map else {}
        rules_list = json.loads(rules) if rules else []
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in device_map or rules")
    
    # Receive file (compatible with old parameter 'file')
    try:
        pcap_file, csv_file = assign_compatible_file_param(file, pcap_file, csv_file)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if pcap_file is None and csv_file is None:
        raise HTTPException(status_code=400, detail="An input file is required")
    temp_file_path = None
    temp_csv_path = None
    
    # Save pcap file
    if pcap_file is not None:
        try:
            temp_file_path = await save_upload_validated(pcap_file, [".pcap", ".pcapng"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # Save CSV file
    if csv_file is not None:
        try:
            temp_csv_path = await save_upload_validated(csv_file, [".csv"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # Parse custom parameters
    params_dict = {}
    if custom_params:
        try:
            params_dict = json.loads(custom_params)
        except json.JSONDecodeError:
            cleanup_temp_files([temp_file_path, temp_csv_path])
            raise HTTPException(status_code=400, detail="Invalid custom_params JSON")

    # Start Celery task (if files are available)
    if temp_file_path or temp_csv_path:
        enqueued = False
        try:
            from infrastructure.celery_app import celery_app as _celery
            _celery.send_task(
                'api.v2.tasks.generate_cpag',
                args=[
                    task_id,
                    temp_file_path,
                    temp_csv_path,
                    device_map_dict,
                    rules_list,
                    output_format,
                    neo4j_uri,
                    neo4j_user,
                    neo4j_password,
                    neo4j_db,
                    neo4j_label,
                    wipe_neo4j,
                    top_k,
                    top_per_plc,
                    build_enhanced,
                    pre_window,
                    post_window,
                    per_tag,
                    top_k_analog,
                    visualize,
                    params_dict  # Add custom parameters
                ]
            )
            enqueued = True
        except Exception:
            enqueued = False
        if not enqueued:
            # If Celery is not available, return error directly
            cleanup_temp_files([temp_file_path, temp_csv_path])
            raise HTTPException(status_code=503, detail="Task queue service unavailable")
    
    return CPAGResponse(
        id=task_id,
        task_id=task_id,
        status="processing",
        created_at=created_at_str,
        version=VERSION,
    )

@app.get("/cpag/status/batch")
async def get_batch_task_status(task_ids: str = ""):
    identifiers = [value.strip() for value in task_ids.split(',') if value.strip()]
    if len(identifiers) > 100:
        raise HTTPException(400, "At most 100 task identifiers")
    result = {}
    for identifier in identifiers:
        try:
            result[identifier] = await get_task_status(identifier)
        except HTTPException as exc:
            result[identifier] = {"task_id": identifier, "status": "not_found" if exc.status_code == 404 else "invalid", "version": VERSION}
    return result

@app.get("/cpag/status/{task_id}")
async def get_task_status(task_id: str):
    from .synthetic import task_dir
    try:
        task_dir(task_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest:
        return manifest
    if redis_client:
        try:
            value = redis_client.get(f"task_status:{task_id}")
            if value:
                return json.loads(value)
        except Exception:
            pass
    raise HTTPException(404, "Task not found")

@app.get("/cpag/result/{task_id}")
async def get_task_result(task_id: str):
    """获取任务结果 - 返回可下载的文件"""
    from .synthetic import task_dir as bounded_dir
    try:
        task_dir = str(bounded_dir(task_id))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    
    # Prioritize reading files recorded in manifest
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest and manifest.get('synthetic'):
        from .synthetic import verify_http_publication, artifact_path
        verify_http_publication(task_id, manifest)
        return FileResponse(path=str(artifact_path(task_id, 'graph.json')),
                            filename=f'cpag-{task_id}.json', media_type='application/json')
    if manifest and isinstance(manifest.get('files'), list):
        for fn in manifest['files']:
            if fn.endswith('.json'):
                fp = os.path.join(task_dir, fn)
                if os.path.exists(fp):
                    return FileResponse(
                        path=fp,
                        filename=f"cpag-{task_id}.json",
                        media_type='application/json'
                    )

    for result_file in [
        os.path.join(task_dir, 'cpag_enhanced.json'),
        os.path.join(task_dir, 'cpag_tcity.json'),
        os.path.join(task_dir, 'cpag_units.json')
    ]:
        if os.path.exists(result_file):
            return FileResponse(
                path=result_file,
                filename=f"cpag-{task_id}.json",
                media_type='application/json'
            )
    raise HTTPException(status_code=404, detail="Result not found")

@app.get("/cpag/result/{task_id}/json")
async def get_task_result_json(task_id: str):
    """获取任务结果 - 返回 JSON 数据"""
    from .synthetic import task_dir as bounded_dir, artifact_path
    try:
        bounded_dir(task_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest and manifest.get('synthetic'):
        from .synthetic import verify_http_publication
        verify_http_publication(task_id, manifest)
        data = {name: json.loads(artifact_path(task_id, name + '.json').read_text())
                for name in ['graph', 'quality', 'events', 'run_manifest']}
        return {"task_id": task_id, "status": "completed", "synthetic": True, "data": data}
    import redis
    
    # First try to get from Redis
    try:
        redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            decode_responses=True
        )
        result = redis_client.get(f"task_result:{task_id}")
        if result:
            result_data = json.loads(result)
            # Return formatted data
            return {
                "task_id": task_id,
                "status": result_data.get('status', 'unknown'),
                "data": {
                    "units": result_data.get('units', []),
                    "graph": result_data.get('result', {}),
                    "cpag_units": len(result_data.get('units', [])),
                    "nodes": len(result_data.get('result', {}).get('nodes', [])),
                    "edges": len(result_data.get('result', {}).get('edges', []))
                },
                "created_at": result_data.get('created_at'),
                "duration": result_data.get('duration', 0)
            }
    except:
        pass
    
    # If not in Redis, try reading from file
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    
    # Read enhanced JSON file
    enhanced_file = os.path.join(task_dir, 'cpag_enhanced.json')
    if os.path.exists(enhanced_file):
        with open(enhanced_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return {
                "task_id": task_id,
                "status": "completed",
                "data": {
                    "units": data.get('units', []),
                    "graph": data.get('graph_data', {}),
                    "cpag_units": len(data.get('units', [])),
                    "nodes": len(data.get('graph_data', {}).get('nodes', [])),
                    "edges": len(data.get('graph_data', {}).get('edges', []))
                }
            }
    
    raise HTTPException(status_code=404, detail="Result not found")

@app.get("/cpag/tasks", response_model=List[TaskInfo])
async def get_task_list():
    """获取所有任务列表"""
    tasks: List[TaskInfo] = []
    manifests = list_tasks_from_manifests(OUTPUT_BASE_DIR)
    for m in manifests:
        # Ensure time format includes Z suffix
        created_at = m.get('created_at', '')
        if created_at and not created_at.endswith('Z'):
            created_at += 'Z'
            
        tasks.append(TaskInfo(
            task_id=m.get('task_id', ''),
            status=m.get('status', 'processing'),
            created_at=created_at,
            version=VERSION,
            files=m.get('files', []),
            result_url=f"/cpag/result/{m.get('task_id','')}" if m.get('status') == 'completed' else None,
            file_size=m.get('file_size'),
            file_name=m.get('file_name')
        ))
    
    # Sort by creation time in descending order
    tasks.sort(key=lambda x: x.created_at, reverse=True)
    return tasks

@app.get("/cpag/download/{task_id}/{filename}")
async def download_file(task_id: str, filename: str):
    """下载任务文件"""
    from .synthetic import artifact_path, task_dir, verify_http_publication
    try:
        task_dir(task_id)
        manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
        if manifest and manifest.get('synthetic'):
            verify_http_publication(task_id, manifest)
        path = artifact_path(task_id, filename)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except FileNotFoundError:
        raise HTTPException(404, "File not found")
    return FileResponse(path=str(path), filename=filename, media_type='application/octet-stream')

@app.get("/cpag/queue/status")
async def get_queue_status():
    """获取任务队列状态 - v2版本"""
    current_active = 0
    if redis_client:
        try:
            current_active = len(redis_client.smembers("v2_active_tasks"))
        except Exception:
            pass
    
    from core.config import get_config
    config = get_config()
    MAX_CONCURRENT_TASKS = config.max_concurrent_tasks_v2
    
    return {
        "active_tasks": current_active,
        "max_concurrent_tasks": MAX_CONCURRENT_TASKS,
        "available_slots": max(0, MAX_CONCURRENT_TASKS - current_active),
        "queue_healthy": current_active < MAX_CONCURRENT_TASKS,
        "version": "v2"
    }


# Register the explicitly opted-in synthetic execution bridge once.
from .synthetic import register as register_synthetic
register_synthetic(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
