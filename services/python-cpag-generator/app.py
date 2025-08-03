from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import uuid
import asyncio
from datetime import datetime

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

class CPAGRequest(BaseModel):
    pcap_file: str
    device_map: Dict[str, str]
    rules: List[str]
    output_format: str = "tcity"

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
async def generate_cpag(request: CPAGRequest, background_tasks: BackgroundTasks):
    """生成CPAG的异步接口"""
    task_id = str(uuid.uuid4())
    
    # 初始化任务状态
    task_status[task_id] = {
        "status": "processing",
        "created_at": datetime.now(),
        "result": None,
        "error": None
    }
    
    # 后台任务处理
    background_tasks.add_task(
        process_cpag_generation,
        task_id,
        request.pcap_file,
        request.device_map,
        request.rules,
        request.output_format
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
    pcap_file: str,
    device_map: Dict[str, str],
    rules: List[str],
    output_format: str
):
    """后台处理CPAG生成"""
    try:
        # 1. 解析PCAP文件
        parser = PCAPParser()
        packets = await parser.parse_pcap(pcap_file)
        
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
        
    except Exception as e:
        task_status[task_id]["status"] = "failed"
        task_status[task_id]["error"] = str(e)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 