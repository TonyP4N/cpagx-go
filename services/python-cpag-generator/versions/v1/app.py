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

# Import from local modules instead of non-existent cpaggen package
from pcap_service import PCAPCPAGGenerator
from csv_service import CSVCPAGGenerator

app = FastAPI(title="CPAG Generator", version="1.0.0")

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 输出目录
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

class CPAGResponse(BaseModel):
    id: str
    task_id: str
    status: str
    created_at: str
    result_url: Optional[str] = None
    error: Optional[str] = None

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cpag-generator"}

@app.post("/generate", response_model=CPAGResponse)
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
    
    # 解析参数
    try:
        device_map_dict = json.loads(device_map) if device_map else {}
        rules_list = json.loads(rules) if rules else []
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in device_map or rules")
    
    # 接收文件（兼容旧参数 'file'）
    if file is not None and pcap_file is None and csv_file is None:
        ext = os.path.splitext(file.filename or "")[1].lower()
        if ext in [".pcap", ".pcapng"]:
            pcap_file = file
        elif ext in [".csv"]:
            csv_file = file
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format for 'file' param. Use pcap_file/csv_file explicitly.")

    temp_file_path = None
    temp_csv_path = None
    temp_assets_path = None
    
    # 保存pcap
    if pcap_file is not None:
        pcap_ext = os.path.splitext(pcap_file.filename or "")[1].lower()
        if pcap_ext not in ['.pcap', '.pcapng']:
            raise HTTPException(status_code=400, detail="Unsupported PCAP format. Only .pcap/.pcapng")
        with tempfile.NamedTemporaryFile(delete=False, suffix=pcap_ext) as temp_file:
            content = await pcap_file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name

    # 保存CSV
    if csv_file is not None:
        csv_ext = os.path.splitext(csv_file.filename or "")[1].lower()
        if csv_ext != '.csv':
            raise HTTPException(status_code=400, detail="Unsupported CSV format. Only .csv")
        with tempfile.NamedTemporaryFile(delete=False, suffix=csv_ext) as temp_csv:
            content = await csv_file.read()
            temp_csv.write(content)
            temp_csv_path = temp_csv.name

    # 保存assets
    if assets_file is not None:
        assets_ext = os.path.splitext(assets_file.filename or "")[1].lower()
        if assets_ext not in ['.yaml', '.yml']:
            raise HTTPException(status_code=400, detail="Unsupported assets format. Only .yaml/.yml")
        with tempfile.NamedTemporaryFile(delete=False, suffix=assets_ext) as temp_assets:
            content = await assets_file.read()
            temp_assets.write(content)
            temp_assets_path = temp_assets.name
    
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
    
    # 后台任务处理
    if background_tasks:
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
    )

@app.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    # 简化：直接从文件系统检查
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    if os.path.exists(task_dir):
        cpag_file = os.path.join(task_dir, 'cpag.json')
        if os.path.exists(cpag_file):
            return {
                "task_id": task_id,
                "status": "completed",
                "result_url": f"/result/{task_id}"
            }
        else:
            return {
                "task_id": task_id,
                "status": "processing"
            }
    else:
        raise HTTPException(status_code=404, detail="Task not found")

@app.get("/result/{task_id}")
async def get_task_result(task_id: str):
    """获取任务结果"""
    task_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
    cpag_file = os.path.join(task_dir, 'cpag.json')
    
    if not os.path.exists(cpag_file):
        raise HTTPException(status_code=404, detail="Result not found")
    
    with open(cpag_file, 'r', encoding='utf-8') as f:
        return json.load(f)

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
        out_dir = os.path.join(OUTPUT_BASE_DIR, task_id)
        os.makedirs(out_dir, exist_ok=True)
        
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
        
        # 清理临时文件
        for path in [file_path, csv_path, assets_path]:
            if path:
                try:
                    os.unlink(path)
                except:
                    pass
        
    except Exception as e:
        # 清理临时文件
        for path in [file_path, csv_path, assets_path]:
            if path:
                try:
                    os.unlink(path)
                except:
                    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 