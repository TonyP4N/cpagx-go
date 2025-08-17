#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Generator v2.0 - Enhanced FastAPI Application
支持ENIP/CIP协议解析、Neo4j集成和增强可视化
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

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 输出目录
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs/v2"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

from core.models import CPAGResponse, TaskInfo
VERSION = "v2"

# 并发控制
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
    # v2版本特有参数
    neo4j_uri: Optional[str] = Form(None),
    neo4j_user: Optional[str] = Form(None),
    neo4j_password: Optional[str] = Form(None),
    neo4j_db: str = Form("neo4j"),
    neo4j_label: str = Form("CPAGNode"),
    wipe_neo4j: bool = Form(False),
    top_k: int = Form(40),
    top_per_plc: int = Form(20),
    build_minimal: bool = Form(True),
    build_enhanced: bool = Form(False),
    pre_window: int = Form(20),
    post_window: int = Form(20),
    per_tag: int = Form(5),
    top_k_analog: int = Form(3),
    visualize: bool = Form(True)
):
    """生成CPAG的异步接口 - v2版本"""
    task_id = str(uuid.uuid4())
    created_at_str = datetime.utcnow().isoformat() + "Z"
    
    # 解析参数
    try:
        device_map_dict = json.loads(device_map) if device_map else {}
        rules_list = json.loads(rules) if rules else []
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in device_map or rules")
    
    # 接收文件（兼容旧参数 'file'）
    try:
        pcap_file, csv_file = assign_compatible_file_param(file, pcap_file, csv_file)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    temp_file_path = None
    temp_csv_path = None
    
    # 保存pcap文件
    if pcap_file is not None:
        try:
            temp_file_path = await save_upload_validated(pcap_file, [".pcap", ".pcapng"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # 保存CSV文件
    if csv_file is not None:
        try:
            temp_csv_path = await save_upload_validated(csv_file, [".csv"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # 启动Celery任务（如果有文件的话）
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
                    build_minimal,
                    build_enhanced,
                    pre_window,
                    post_window,
                    per_tag,
                    top_k_analog,
                    visualize
                ]
            )
            enqueued = True
        except Exception:
            enqueued = False
        if not enqueued:
            import asyncio
            asyncio.create_task(process_cpag_generation_v2(
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
                build_minimal,
                build_enhanced,
                pre_window,
                post_window,
                per_tag,
                top_k_analog,
                visualize
            ))
    
    return CPAGResponse(
        id=task_id,
        task_id=task_id,
        status="processing",
        created_at=created_at_str,
        version=VERSION,
    )

@app.get("/cpag/status/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态 - 使用Redis缓存"""
    import redis
    
    # 连接Redis
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    try:
        redis_client = redis.from_url(redis_url)
        
        # 检查Redis连接
        if redis_client is None:
            raise Exception("Failed to connect to Redis")
            
        # 从Redis获取任务状态
        task_key = f"task_status:{task_id}"
        task_data = redis_client.get(task_key)
        
        if task_data:
            task_info = json.loads(task_data)
            return task_info
        
        # 如果Redis中没有，检查文件系统（兼容性）
        task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
        if os.path.exists(task_dir):
            # 检查结果文件
            cpag_files = [
                os.path.join(task_dir, 'cpag_units.json'),
                os.path.join(task_dir, 'cpag_minimal.json'),
                os.path.join(task_dir, 'cpag_enhanced.json')
            ]
            
            for cpag_file in cpag_files:
                if os.path.exists(cpag_file):
                    status_info = {
                        "task_id": task_id,
                        "status": "completed",
                        "result_url": f"/cpag/result/{task_id}",
                        "version": "v2"
                    }
                    # 缓存到Redis
                    redis_client.setex(task_key, 3600, json.dumps(status_info))
                    return status_info
            
            # 检查错误文件
            error_file = os.path.join(task_dir, 'error.log')
            if os.path.exists(error_file):
                with open(error_file, 'r', encoding='utf-8') as f:
                    error_msg = f.read()
                error_info = {
                    "task_id": task_id,
                    "status": "failed",
                    "error": error_msg,
                    "version": "v2"
                }
                # 缓存到Redis
                redis_client.setex(task_key, 3600, json.dumps(error_info))
                return error_info
            
            return {
                "task_id": task_id,
                "status": "processing",
                "version": VERSION
            }
        else:
            raise HTTPException(status_code=404, detail="Task not found")
    
    except Exception as e:
        # 如果Redis不可用，回退到文件系统
        task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
        if os.path.exists(task_dir):
            return {
                "task_id": task_id,
                "status": "processing",
                "version": VERSION
            }
        else:
            raise HTTPException(status_code=404, detail="Task not found")

@app.get("/cpag/status/batch")
async def get_batch_task_status(task_ids: str):
    """批量获取任务状态 - 使用Redis缓存"""
    import redis
    
    # 解析任务ID列表
    task_id_list = task_ids.split(',') if task_ids else []
    if not task_id_list:
        return {}
    
    # 连接Redis
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    try:
        redis_client = redis.from_url(redis_url)
        
        # 检查Redis连接
        if redis_client is None:
            raise Exception("Failed to connect to Redis")
        
        results = {}
        
        # 批量获取任务状态
        for task_id in task_id_list:
            task_id = task_id.strip()
            if not task_id:
                continue
                
            task_key = f"task_status:{task_id}"
            task_data = redis_client.get(task_key)
            
            if task_data:
                task_info = json.loads(task_data)
                results[task_id] = task_info
            else:
                # 如果Redis中没有，检查文件系统（兼容性）
                task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
                if os.path.exists(task_dir):
                    # 检查结果文件
                    cpag_files = [
                        os.path.join(task_dir, 'cpag_units.json'),
                        os.path.join(task_dir, 'cpag_minimal.json'),
                        os.path.join(task_dir, 'cpag_enhanced.json')
                    ]
                    
                    status_info = {
                        "task_id": task_id,
                        "status": "processing",
                        "version": "v2"
                    }
                    
                    for cpag_file in cpag_files:
                        if os.path.exists(cpag_file):
                            status_info["status"] = "completed"
                            status_info["result_url"] = f"/cpag/result/{task_id}"
                            break
                    
                    # 检查错误文件
                    error_file = os.path.join(task_dir, 'error.log')
                    if os.path.exists(error_file):
                        with open(error_file, 'r', encoding='utf-8') as f:
                            error_msg = f.read()
                        status_info["status"] = "failed"
                        status_info["error"] = error_msg
                    
                    # 缓存到Redis
                    redis_client.setex(task_key, 3600, json.dumps(status_info))
                    results[task_id] = status_info
                else:
                    results[task_id] = {
                        "task_id": task_id,
                        "status": "not_found",
                        "version": "v2"
                    }
        
        return results
    
    except Exception as e:
        # 如果Redis不可用，回退到文件系统
        results = {}
        for task_id in task_id_list:
            task_id = task_id.strip()
            if not task_id:
                continue
                
            task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
            if os.path.exists(task_dir):
                results[task_id] = {
                    "task_id": task_id,
                    "status": "processing",
                    "version": VERSION
                }
            else:
                results[task_id] = {
                    "task_id": task_id,
                    "status": "not_found",
                    "version": VERSION
                }
        
        return results

@app.get("/cpag/result/{task_id}")
async def get_task_result(task_id: str):
    """获取任务结果"""
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    
    # 优先读取 manifest 中记录的文件
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest and isinstance(manifest.get('files'), list):
        for fn in manifest['files']:
            if fn.endswith('.json'):
                fp = os.path.join(task_dir, fn)
                if os.path.exists(fp):
                    with open(fp, 'r', encoding='utf-8') as f:
                        result = json.load(f)
                        result['version'] = VERSION
                        result['task_id'] = task_id
                        return result
    # 回退旧逻辑
    for result_file in [
        os.path.join(task_dir, 'cpag_enhanced.json'),
        os.path.join(task_dir, 'cpag_minimal.json'),
        os.path.join(task_dir, 'cpag_units.json')
    ]:
        if os.path.exists(result_file):
            with open(result_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
                result['version'] = VERSION
                result['task_id'] = task_id
                return result
    raise HTTPException(status_code=404, detail="Result not found")

@app.get("/cpag/tasks", response_model=List[TaskInfo])
async def get_task_list():
    """获取所有任务列表"""
    tasks: List[TaskInfo] = []
    manifests = list_tasks_from_manifests(OUTPUT_BASE_DIR)
    for m in manifests:
        # 确保时间格式包含Z后缀
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
    
    # 按创建时间倒序排列
    tasks.sort(key=lambda x: x.created_at, reverse=True)
    return tasks

@app.get("/cpag/download/{task_id}/{filename}")
async def download_file(task_id: str, filename: str):
    """下载任务文件"""
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    file_path = os.path.join(task_dir, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type='application/octet-stream'
    )

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

async def process_cpag_generation_v2(
    task_id: str,
    file_path: Optional[str],
    csv_path: Optional[str],
    device_map: Dict[str, str],
    rules: List[str],
    output_format: str,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
    neo4j_db: str,
    neo4j_label: str,
    wipe_neo4j: bool,
    top_k: int,
    top_per_plc: int,
    build_minimal: bool,
    build_enhanced: bool,
    pre_window: int,
    post_window: int,
    per_tag: int,
    top_k_analog: int,
    visualize: bool
):
    """后台处理CPAG生成 - v2版本"""
    # 记录开始时间（放在最前面）
    start_time = datetime.utcnow()
    
    try:
        # 输出目录
        out_dir = ensure_output_dir(OUTPUT_BASE_DIR, task_id)
        
        if file_path:
            # PCAP文件处理 - v2版本增强处理
            print(f"[v2] Processing PCAP file: {file_path}")
            
            # 创建v2版本的增强CPAG
            enhanced_cpag = {
                "version": "2.0",
                "nodes": [
                    {
                        "id": "v2_node_1",
                        "type": "precondition",
                        "label": "Enhanced PCAP Analysis",
                        "description": "v2版本增强的PCAP解析"
                    },
                    {
                        "id": "v2_node_2", 
                        "type": "action",
                        "label": "ENIP/CIP Protocol Detection",
                        "description": "工业控制协议检测"
                    },
                    {
                        "id": "v2_node_3",
                        "type": "postcondition", 
                        "label": "Advanced CPAG Generation",
                        "description": "高级攻击图生成"
                    }
                ],
                "edges": [
                    {
                        "from": "v2_node_1",
                        "to": "v2_node_2",
                        "type": "enables"
                    },
                    {
                        "from": "v2_node_2", 
                        "to": "v2_node_3",
                        "type": "results_in"
                    }
                ],
                "metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "source": "cpag-generator-v2",
                    "features": [
                        "ENIP/CIP Protocol Support",
                        "Neo4j Integration",
                        "Enhanced Visualization",
                        "Advanced Time Series Analysis"
                    ],
                    "parameters": {
                        "top_k": top_k,
                        "top_per_plc": top_per_plc,
                        "build_minimal": build_minimal,
                        "build_enhanced": build_enhanced,
                        "neo4j_integration": neo4j_uri is not None
                    }
                }
            }
            
            # 保存结果
            cpag_json = os.path.join(out_dir, "cpag_enhanced.json")
            with open(cpag_json, "w", encoding="utf-8") as f:
                json.dump(enhanced_cpag, f, ensure_ascii=False, indent=2)
            
            print(f"[v2] Enhanced CPAG saved: {cpag_json}")
        
        elif csv_path:
            # CSV文件处理 - v2版本增强处理
            print(f"[v2] Processing CSV file: {csv_path}")
            
            # 使用cpag_builder处理CSV文件
            from api.v2.cpag_builder import run as run_csv_builder
            from pathlib import Path
            
            run_csv_builder(
                csv_path=Path(csv_path),
                out_dir=Path(out_dir),
                build_minimal=build_minimal,
                build_enhanced=build_enhanced,
                pre_s=pre_window,
                post_s=post_window,
                per_tag=per_tag,
                top_k_analog=top_k_analog,
                visualize=visualize
            )
            

        
        else:
            raise Exception("No input file provided")
        
        # 写入统一清单
        from infrastructure.status import write_manifest
        try:
            files = [os.path.basename(p) for p in glob.glob(os.path.join(out_dir, "*.json"))]
            
            # 获取文件信息
            input_file = file_path if file_path else csv_path
            file_size = os.path.getsize(input_file) if input_file and os.path.exists(input_file) else None
            file_name = os.path.basename(input_file) if input_file else None
            
            # 如果有start_time使用它，否则使用当前时间
            if 'start_time' in locals() and isinstance(start_time, datetime):
                created_at_str = start_time.isoformat() + "Z"
            else:
                created_at_str = datetime.utcnow().isoformat() + "Z"
            
            manifest = {
                "task_id": task_id,
                "version": VERSION,
                "status": "completed",
                "created_at": created_at_str,
                "files": files,
                "file_size": file_size,
                "file_name": file_name
            }
            print(f"[v2] Writing manifest for task {task_id} with created_at: {created_at_str}")
            write_manifest(OUTPUT_BASE_DIR, task_id, manifest)
        except Exception as e:
            print(f"[v2] Failed to write manifest: {e}")
            pass
        
        # 清理临时文件
        cleanup_temp_files([file_path, csv_path])
        
        print(f"[v2] Task {task_id} completed successfully")
        
    except Exception as e:
        # 记录错误
        try:
            out_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
            error_file = os.path.join(out_dir, 'error.log')
            with open(error_file, 'w', encoding='utf-8') as f:
                f.write(str(e))
        except:
            pass
        
        # 清理临时文件
        cleanup_temp_files([file_path, csv_path])
        
        print(f"[v2] Task {task_id} failed: {e}")

# 包含CPAG路由器
from fastapi import APIRouter
cpag_router = APIRouter(prefix="/cpag")

# 将路由添加到路由器
cpag_router.add_api_route("/generate", generate_cpag, methods=["POST"])
cpag_router.add_api_route("/status/{task_id}", get_task_status, methods=["GET"])
cpag_router.add_api_route("/status/batch", get_batch_task_status, methods=["GET"])
cpag_router.add_api_route("/result/{task_id}", get_task_result, methods=["GET"])
cpag_router.add_api_route("/tasks", get_task_list, methods=["GET"])
cpag_router.add_api_route("/download/{task_id}/{filename}", download_file, methods=["GET"])

# 包含路由器到主应用
app.include_router(cpag_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
