from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import uuid
import asyncio
from datetime import datetime
import os
import tempfile
import json

from cpaggen.parser import PCAPParser
from cpaggen.mapper import DeviceMapper
from cpaggen.rule_engine import RuleEngine
from cpaggen.tcity_exporter import TCITYExporter

app = FastAPI(title="CPAG Generator", version="1.0.0")

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 内存存储任务状态（生产环境应使用Redis）
task_status = {}

class CPAGResponse(BaseModel):
    task_id: str
    status: str
    created_at: datetime
    result_url: Optional[str] = None
    error: Optional[str] = None

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cpag-generator"}

@app.post("/generate", response_model=CPAGResponse)
async def generate_cpag(
    file: UploadFile = File(...),
    device_map: str = Form("{}"),
    rules: str = Form("[]"),
    output_format: str = Form("tcity"),
    background_tasks: BackgroundTasks = None
):
    """生成CPAG的异步接口"""
    task_id = str(uuid.uuid4())
    
    # 解析参数
    try:
        device_map_dict = json.loads(device_map) if device_map else {}
        rules_list = json.loads(rules) if rules else []
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in device_map or rules")
    
    # 验证文件格式
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in ['.pcap', '.pcapng', '.csv']:
        raise HTTPException(status_code=400, detail="Unsupported file format. Only .pcap, .pcapng, .csv are supported")
    
    # 创建临时文件
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp_file:
        content = await file.read()
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    # 初始化任务状态
    task_status[task_id] = {
        "status": "processing",
        "created_at": datetime.now(),
        "result": None,
        "error": None,
        "file_path": temp_file_path
    }
    
    # 后台任务处理
    background_tasks.add_task(
        process_cpag_generation,
        task_id,
        temp_file_path,
        device_map_dict,
        rules_list,
        output_format
    )
    
    return CPAGResponse(
        task_id=task_id,
        status="processing",
        created_at=datetime.now()
    )

@app.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    if task_id not in task_status:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = task_status[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "created_at": task["created_at"],
        "result_url": f"/result/{task_id}" if task["result"] else None,
        "error": task["error"]
    }

@app.get("/result/{task_id}")
async def get_task_result(task_id: str):
    """获取任务结果"""
    if task_id not in task_status:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = task_status[task_id]
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Task not completed")
    
    return task["result"]

async def process_cpag_generation(
    task_id: str,
    file_path: str,
    device_map: Dict[str, str],
    rules: List[str],
    output_format: str
):
    """后台处理CPAG生成"""
    try:
        # 1. 解析文件
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in ['.pcap', '.pcapng']:
            parser = PCAPParser()
            packets = await parser.parse_pcap(file_path)
        elif file_extension == '.csv':
            # TODO: 实现CSV解析器
            packets = []  # 临时占位
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")
        
        # 2. 设备映射
        mapper = DeviceMapper()
        mapped_data = mapper.map_devices(packets, device_map)
        
        # 3. 规则引擎处理
        rule_engine = RuleEngine()
        attack_graph = rule_engine.process_rules(mapped_data, rules)
        
        # 4. 导出结果
        if output_format == "tcity":
            exporter = TCITYExporter()
            result = exporter.export_tcity(attack_graph)
        else:
            result = attack_graph
        
        # 更新任务状态
        task_status[task_id]["status"] = "completed"
        task_status[task_id]["result"] = result
        
        # 清理临时文件
        try:
            os.unlink(file_path)
        except:
            pass
        
    except Exception as e:
        task_status[task_id]["status"] = "failed"
        task_status[task_id]["error"] = str(e)
        # 清理临时文件
        try:
            if "file_path" in task_status[task_id]:
                os.unlink(task_status[task_id]["file_path"])
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 