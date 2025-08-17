from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Dict, List, Optional
import uuid
import asyncio
from datetime import datetime
import os
import tempfile
import json
import glob

# Import from core and infrastructure modules
from core.generators import PCAPCPAGGenerator, CSVCPAGGenerator
from core.models import CPAGResponse, TaskInfo
from core.config import get_config
from infrastructure.status import write_manifest, read_manifest, list_tasks_from_manifests
from infrastructure.files import (
    ensure_output_dir,
    save_upload_validated,
    cleanup_temp_files,
    assign_compatible_file_param,
)

app = FastAPI(title="CPAG Generator", version="1.0.0")

# 创建子应用来处理 /cpag 前缀
from fastapi import APIRouter
cpag_router = APIRouter(prefix="/cpag")

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 获取配置
config = get_config()

# 输出目录
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs/v1"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

VERSION = "v1"

# 并发控制
MAX_CONCURRENT_TASKS = config.max_concurrent_tasks_v1
import redis
try:
    redis_client = redis.from_url(config.redis_url)
except Exception:
    redis_client = None

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cpag-generator-v1", "version": VERSION, "port": int(os.getenv("PORT", 8000))}

@cpag_router.post("/generate", response_model=CPAGResponse)
async def generate_cpag(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    pcap_file: Optional[UploadFile] = File(None),
    csv_file: Optional[UploadFile] = File(None),
    assets_file: Optional[UploadFile] = File(None),
    device_map: str = Form("{}"),
    rules: str = Form("[]")
):
    """生成CPAG的异步接口"""
    task_id = str(uuid.uuid4())
    
    # 检查并发限制
    current_active = 0
    if redis_client:
        try:
            current_active = len(redis_client.smembers("v1_active_tasks"))
        except Exception:
            pass
    
    if current_active >= MAX_CONCURRENT_TASKS:
        raise HTTPException(
            status_code=429, 
            detail=f"Too many concurrent tasks. Maximum allowed: {MAX_CONCURRENT_TASKS}. Current active: {current_active}"
        )
    
    # 添加到活跃任务集合
    if redis_client:
        try:
            redis_client.sadd("v1_active_tasks", task_id)
            redis_client.expire("v1_active_tasks", 3600)  # 1小时过期
        except Exception:
            pass
    
    # 解析参数
    try:
        device_map_dict = json.loads(device_map) if device_map else {}
        rules_list = json.loads(rules) if rules else []
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail="Invalid JSON in device_map or rules")
    
    # 接收文件（兼容旧参数 'file'）
    try:
        pcap_file, csv_file = assign_compatible_file_param(file, pcap_file, csv_file)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    temp_file_path = None
    temp_csv_path = None
    temp_assets_path = None
    
    # 保存pcap文件
    file_size = None
    file_name = None
    if pcap_file is not None:
        try:
            temp_file_path = await save_upload_validated(pcap_file, [".pcap", ".pcapng"])
            file_size = pcap_file.size
            file_name = pcap_file.filename
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # 保存CSV
    if csv_file is not None:
        try:
            temp_csv_path = await save_upload_validated(csv_file, [".csv"])
            file_size = csv_file.size
            file_name = csv_file.filename
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # 保存assets
    if assets_file is not None:
        try:
            temp_assets_path = await save_upload_validated(assets_file, [".yaml", ".yml"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    # 初始化任务状态
    created_at_str = datetime.utcnow().isoformat() + "Z"
    task_data = {
        "status": "processing",
        "created_at": created_at_str,
        "result": None,
        "error": None,
        "pcap_path": temp_file_path,
        "csv_path": temp_csv_path,
        "assets_path": temp_assets_path,
    }
    
    # 任务处理：优先队列（Celery），失败则退回进程内后台任务
    enqueued = False
    try:
        from infrastructure.celery_app import celery_app as _celery
        _celery.send_task(
            'api.v1.tasks.generate_cpag',
            args=[
                task_id,
                temp_file_path,
                temp_csv_path,
                device_map_dict,
                rules_list,
                OUTPUT_BASE_DIR,
                file_size,
                file_name,
            ]
        )
        enqueued = True
    except Exception:
        enqueued = False
    if not enqueued and background_tasks:
        # 检查并发限制
        current_active = 0
        if redis_client:
            try:
                current_active = len(redis_client.smembers("v1_active_tasks"))
            except Exception:
                pass
        
        if current_active >= MAX_CONCURRENT_TASKS:
            raise HTTPException(
                status_code=429, 
                detail=f"Too many concurrent tasks. Maximum allowed: {MAX_CONCURRENT_TASKS}. Current active: {current_active}"
            )
        
        # 添加到活跃任务集合
        if redis_client:
            try:
                redis_client.sadd("v1_active_tasks", task_id)
                redis_client.expire("v1_active_tasks", 3600)  # 1小时过期
            except Exception:
                pass
        
        background_tasks.add_task(
            process_cpag_generation,
            task_id,
            temp_file_path,
            temp_csv_path,
            temp_assets_path,
            device_map_dict,
            rules_list
        )
    
    return CPAGResponse(
        id=task_id,
        task_id=task_id,
        status="processing",
        created_at=created_at_str,
        version=VERSION,
    )

@cpag_router.get("/status/batch")
async def get_batch_task_status(task_ids: str = Query(..., description="Comma-separated list of task IDs")):
    """批量获取任务状态"""
    # 解析任务ID列表
    task_id_list = task_ids.split(',') if task_ids else []
    if not task_id_list:
        return {}
    
    results = {}
    
    # 批量获取任务状态
    for task_id in task_id_list:
        task_id = task_id.strip()
        if not task_id:
            continue
            
        manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
        if manifest is not None:
            status = manifest.get("status", "processing")
            results[task_id] = {
                "task_id": task_id,
                "status": status,
                "result_url": f"/cpag/result/{task_id}" if status == "completed" else None,
                "version": VERSION
            }
        else:
            # 如果manifest不存在，检查Celery任务状态
            try:
                from infrastructure.celery_app import celery_app as _celery
                # 检查任务是否在运行
                active_tasks = _celery.control.inspect().active()
                if active_tasks:
                    for worker, tasks in active_tasks.items():
                        for task in tasks:
                            if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                                results[task_id] = {
                                    "task_id": task_id,
                                    "status": "processing",
                                    "result_url": None,
                                    "version": VERSION
                                }
                                break
                        if task_id in results:
                            break
                
                # 如果还没找到，检查保留的任务
                if task_id not in results:
                    reserved_tasks = _celery.control.inspect().reserved()
                    if reserved_tasks:
                        for worker, tasks in reserved_tasks.items():
                            for task in tasks:
                                if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                                    results[task_id] = {
                                        "task_id": task_id,
                                        "status": "processing",
                                        "result_url": None,
                                        "version": VERSION
                                    }
                                    break
                            if task_id in results:
                                break
                
                # 如果还是没找到，检查是否有结果文件存在
                if task_id not in results:
                    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
                    if os.path.exists(task_dir):
                        cpag_file = os.path.join(task_dir, 'cpag.json')
                        if os.path.exists(cpag_file):
                            results[task_id] = {
                                "task_id": task_id,
                                "status": "completed",
                                "result_url": f"/cpag/result/{task_id}",
                                "version": VERSION
                            }
                        else:
                            results[task_id] = {
                                "task_id": task_id,
                                "status": "not_found",
                                "version": VERSION
                            }
                    else:
                        results[task_id] = {
                            "task_id": task_id,
                            "status": "not_found",
                            "version": VERSION
                        }
            except Exception as e:
                print(f"Error checking Celery task status for {task_id}: {e}")
                results[task_id] = {
                    "task_id": task_id,
                    "status": "not_found",
                    "version": VERSION
                }
    
    return results

@cpag_router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest is not None:
        status = manifest.get("status", "processing")
        return {
            "task_id": task_id,
            "status": status,
            "result_url": f"/cpag/result/{task_id}" if status == "completed" else None,
            "version": VERSION
        }
    
    # 如果manifest不存在，检查Celery任务状态
    try:
        from infrastructure.celery_app import celery_app as _celery
        # 检查任务是否在运行
        active_tasks = _celery.control.inspect().active()
        if active_tasks:
            for worker, tasks in active_tasks.items():
                for task in tasks:
                    if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                        return {
                            "task_id": task_id,
                            "status": "processing",
                            "result_url": None,
                            "version": VERSION
                        }
        
        # 检查任务是否已完成但manifest未写入
        reserved_tasks = _celery.control.inspect().reserved()
        if reserved_tasks:
            for worker, tasks in reserved_tasks.items():
                for task in tasks:
                    if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                        return {
                            "task_id": task_id,
                            "status": "processing",
                            "result_url": None,
                            "version": VERSION
                        }
        
        # 检查是否有结果文件存在（即使没有manifest）
        task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
        if os.path.exists(task_dir):
            cpag_file = os.path.join(task_dir, 'cpag.json')
            if os.path.exists(cpag_file):
                return {
                    "task_id": task_id,
                    "status": "completed",
                    "result_url": f"/cpag/result/{task_id}",
                    "version": VERSION
                }
    except Exception as e:
        print(f"Error checking Celery task status: {e}")
    
    # 如果都找不到，返回404
    raise HTTPException(status_code=404, detail="Task not found")

@cpag_router.get("/result/{task_id}")
async def get_task_result(task_id: str):
    """获取任务结果"""
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    # 优先读取清单中记录的主要结果文件
    manifest = read_manifest(OUTPUT_BASE_DIR, task_id)
    if manifest and isinstance(manifest.get("files"), list):
        primary = None
        for f in manifest["files"]:
            if isinstance(f, str) and f.endswith("cpag.json"):
                primary = os.path.join(task_dir, f)
                break
        if primary and os.path.exists(primary):
            with open(primary, 'r', encoding='utf-8') as fh:
                return json.load(fh)
    # 兼容：无清单或未记录主文件，降级读取默认 cpag.json
    cpag_file = os.path.join(task_dir, 'cpag.json')
    if os.path.exists(cpag_file):
        with open(cpag_file, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    raise HTTPException(status_code=404, detail="Result not found")

@cpag_router.get("/tasks", response_model=List[TaskInfo])
async def get_task_list():
    """获取所有任务列表"""
    tasks: List[TaskInfo] = []
    manifests = list_tasks_from_manifests(OUTPUT_BASE_DIR)
    
    for m in manifests:
        status = m.get("status", "processing")
        task_id = m.get("task_id", "")
        
        # 如果状态是processing，检查是否真的还在运行
        if status == "processing":
            try:
                from infrastructure.celery_app import celery_app as _celery
                # 检查任务是否还在运行
                active_tasks = _celery.control.inspect().active()
                reserved_tasks = _celery.control.inspect().reserved()
                
                is_still_running = False
                if active_tasks:
                    for worker, tasks in active_tasks.items():
                        for task in tasks:
                            if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                                is_still_running = True
                                break
                        if is_still_running:
                            break
                
                if not is_still_running and reserved_tasks:
                    for worker, tasks in reserved_tasks.items():
                        for task in tasks:
                            if task.get('id') == task_id or task.get('args', []) and len(task.get('args', [])) > 0 and task.get('args', [])[0] == task_id:
                                is_still_running = True
                                break
                        if is_still_running:
                            break
                
                # 如果不在运行，检查是否有结果文件
                if not is_still_running:
                    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
                    if os.path.exists(task_dir):
                        cpag_file = os.path.join(task_dir, 'cpag.json')
                        if os.path.exists(cpag_file):
                            status = "completed"
                        else:
                            status = "failed"
            except Exception as e:
                print(f"Error checking task status for {task_id}: {e}")
        
        tasks.append(TaskInfo(
            task_id=task_id,
            status=status,
            created_at=m.get("created_at", ""),
            version=VERSION,
            files=m.get("files", []),
            result_url=f"/cpag/result/{task_id}" if status == "completed" else None,
            file_size=m.get("file_size"),  # 文件大小
            file_name=m.get("file_name")   # 原始文件名
        ))
    
    # 按创建时间倒序排列
    tasks.sort(key=lambda x: x.created_at, reverse=True)
    return tasks

@cpag_router.get("/download/{task_id}/{filename}")
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

@cpag_router.get("/queue/status")
async def get_queue_status():
    """获取任务队列状态 - v1版本"""
    current_active = 0
    if redis_client:
        try:
            current_active = len(redis_client.smembers("v1_active_tasks"))
        except Exception:
            pass
    
    return {
        "active_tasks": current_active,
        "max_concurrent_tasks": MAX_CONCURRENT_TASKS,
        "available_slots": max(0, MAX_CONCURRENT_TASKS - current_active),
        "queue_healthy": current_active < MAX_CONCURRENT_TASKS,
        "version": VERSION
    }

async def process_cpag_generation(
    task_id: str,
    file_path: Optional[str],
    csv_path: Optional[str],
    assets_path: Optional[str],
    device_map: Dict[str, str],
    rules: List[str]
):
    """后台处理CPAG生成"""
    try:
        # 输出目录
        out_dir = ensure_output_dir(OUTPUT_BASE_DIR, task_id)
        
        # 1. 解析PCAP
        pcap_data = None
        if file_path:
            pcap_generator = PCAPCPAGGenerator()
            pcap_data = pcap_generator.parse_pcap(file_path)
        
        # 2. Historian CSV 解析
        csv_df = None
        if csv_path:
            csv_generator = CSVCPAGGenerator()
            csv_df = csv_generator.parse_csv(csv_path)
        
        # 3. 构建CPAG
        cpag_graph = {}
        
        if pcap_data:
            pcap_generator = PCAPCPAGGenerator()
            cpag_graph = pcap_generator.build_cpag(pcap_data, device_map)
        elif csv_df is not None and not csv_df.empty:
            csv_generator = CSVCPAGGenerator()
            cpag_graph = csv_generator.build_cpag(csv_df, device_map)
        else:
            # 创建基本的CPAG结构
            cpag_graph = {
                "nodes": [],
                "edges": [],
                "metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "source": "cpag-generator"
                }
            }
        
        # 4. 导出cpag.json
        cpag_json_path = os.path.join(out_dir, 'cpag.json')
        with open(cpag_json_path, 'w', encoding='utf-8') as f:
            json.dump(cpag_graph, f, ensure_ascii=False, indent=2)
        
        # 写入统一清单
        manifest = {
            "task_id": task_id,
            "version": VERSION,
            "status": "completed",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "files": ["cpag.json"],
        }
        try:
            write_manifest(OUTPUT_BASE_DIR, task_id, manifest)
        except Exception:
            pass

        # 清理临时文件
        cleanup_temp_files([file_path, csv_path, assets_path])
        
    except Exception as e:
        # 写入错误状态到manifest
        error_manifest = {
            "task_id": task_id,
            "version": VERSION,
            "status": "failed",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "error": str(e),
            "files": [],
        }
        try:
            write_manifest(OUTPUT_BASE_DIR, task_id, error_manifest)
        except Exception:
            pass
        
        # 清理临时文件
        cleanup_temp_files([file_path, csv_path, assets_path])
    finally:
        # 从活跃任务集合中移除
        if redis_client:
            try:
                redis_client.srem("v1_active_tasks", task_id)
            except Exception:
                pass

# 包含CPAG路由器
app.include_router(cpag_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 