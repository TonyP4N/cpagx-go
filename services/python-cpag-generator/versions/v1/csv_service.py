"""
简化的 CSV 处理服务
专门处理工业控制系统的时间序列 CSV 文件并生成 CPAG
"""

import os
import json
import pandas as pd
import networkx as nx
from typing import Dict, Any, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import tempfile
import uuid
from datetime import datetime

app = FastAPI(title="CSV CPAG Generator", version="1.0.0")

class CSVCPAGGenerator:
    """简化的 CSV CPAG 生成器"""
    
    def __init__(self):
        pass
    
    def parse_csv(self, csv_path: str) -> pd.DataFrame:
        """解析 CSV 文件"""
        try:
            df = pd.read_csv(csv_path)
            if df.empty:
                return pd.DataFrame()
            
            # 标准化列名
            df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
            
            # 检测时间戳列
            timestamp_col = None
            for col in df.columns:
                if any(ts in col for ts in ["timestamp", "time", "datetime", "date", "ts"]):
                    timestamp_col = col
                    break
            
            if timestamp_col is None:
                # 如果没有时间戳列，使用第一列
                timestamp_col = df.columns[0]
            
            # 转换时间戳
            df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors="coerce")
            df = df.dropna(subset=[timestamp_col])
            
            # 转换为长格式
            value_cols = [c for c in df.columns if c != timestamp_col]
            if not value_cols:
                return pd.DataFrame()
            
            long_df = df.melt(id_vars=[timestamp_col], value_vars=value_cols, 
                            var_name="tag", value_name="value")
            long_df = long_df.rename(columns={timestamp_col: "timestamp"})
            
            # 提取标签类型
            long_df["tag_type"] = long_df["tag"].apply(self._extract_tag_type)
            long_df["tag_id"] = long_df["tag"].apply(self._extract_tag_id)
            
            # 数值转换
            long_df["value"] = pd.to_numeric(long_df["value"], errors="coerce")
            
            return long_df[["timestamp", "tag", "tag_type", "tag_id", "value"]]
            
        except Exception as e:
            raise RuntimeError(f"CSV 解析失败: {e}")
    
    def _extract_tag_type(self, tag: str) -> str:
        """提取标签类型"""
        if not isinstance(tag, str):
            return ""
        
        # 常见的工业控制系统标签类型
        tag_types = ["FIT", "LIT", "PIT", "AIT", "MV", "PU", "PLC", "HMI", "SCADA"]
        tag_upper = tag.upper()
        
        for tag_type in tag_types:
            if tag_type in tag_upper:
                return tag_type
        
        return ""
    
    def _extract_tag_id(self, tag: str) -> str:
        """提取标签 ID"""
        if not isinstance(tag, str):
            return ""
        
        import re
        # 查找数字 ID
        match = re.search(r'\d+', tag)
        return match.group() if match else ""
    
    def build_cpag(self, df: pd.DataFrame, device_map: Dict[str, str]) -> Dict[str, Any]:
        """构建 CPAG 图"""
        graph = nx.DiGraph()
        
        if df.empty:
            return {"nodes": [], "edges": [], "metadata": {}}
        
        # 1. 前置条件节点 (设备活跃)
        pre_nodes = []
        unique_tags = df['tag'].unique()[:5]  # 限制数量
        
        for i, tag in enumerate(unique_tags):
            pre_id = f"pre_{i}"
            graph.add_node(pre_id, 
                          type="precondition", 
                          name=f"DeviceActive({tag})", 
                          source=tag, 
                          target=tag)
            pre_nodes.append(pre_id)
        
        # 2. 动作节点 (传感器读取)
        action_nodes = []
        tag_types = df['tag_type'].unique()
        
        for i, tag_type in enumerate(tag_types[:3]):  # 限制数量
            act_id = f"act_{i}"
            graph.add_node(act_id, 
                          type="action", 
                          name=f"SensorRead({tag_type})", 
                          source=f"{tag_type}_Device", 
                          target=f"{tag_type}_Sensor")
            action_nodes.append(act_id)
        
        # 3. 后置条件节点 (传感器数据)
        post_nodes = []
        for i, tag in enumerate(unique_tags[:3]):  # 限制数量
            post_id = f"post_{i}"
            graph.add_node(post_id, 
                          type="postcondition", 
                          name=f"SensorData({tag})", 
                          source=tag, 
                          target=tag)
            post_nodes.append(post_id)
        
        # 4. 连接边
        edges = []
        edge_id = 0
        
        # 前置条件 -> 动作
        for pre_id in pre_nodes:
            for act_id in action_nodes:
                graph.add_edge(pre_id, act_id, 
                              probability=0.8, 
                              evidence=[{"source": "precondition", "detail": graph.nodes[pre_id]}])
                edges.append({
                    "id": f"e{edge_id}",
                    "source": pre_id,
                    "target": act_id,
                    "probability": 0.8,
                    "evidence": [{"source": "precondition", "detail": graph.nodes[pre_id]}]
                })
                edge_id += 1
        
        # 动作 -> 后置条件
        for act_id in action_nodes:
            for post_id in post_nodes:
                graph.add_edge(act_id, post_id, 
                              probability=0.7, 
                              evidence=[{"source": "action", "detail": graph.nodes[act_id]}])
                edges.append({
                    "id": f"e{edge_id}",
                    "source": act_id,
                    "target": post_id,
                    "probability": 0.7,
                    "evidence": [{"source": "action", "detail": graph.nodes[act_id]}]
                })
                edge_id += 1
        
        # 5. 转换为字典格式
        nodes = []
        for i, (nid, data) in enumerate(graph.nodes(data=True)):
            nodes.append({
                "id": nid,
                "type": data.get("type", ""),
                "name": data.get("name", ""),
                "source": data.get("source", ""),
                "target": data.get("target", "")
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": "csv",
                "device_map": device_map,
                "total_records": len(df),
                "unique_tags": len(df['tag'].unique()),
                "generated_at": datetime.now().isoformat()
            }
        }

# 全局生成器实例
generator = CSVCPAGGenerator()

@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "service": "csv-cpag-generator"}

@app.post("/generate")
async def generate_cpag(
    csv_file: UploadFile = File(...),
    device_map: str = Form("{}")
):
    """生成 CPAG"""
    try:
        # 解析设备映射
        device_map_dict = json.loads(device_map) if device_map else {}
        
        # 验证文件类型
        if not csv_file.filename.lower().endswith('.csv'):
            raise HTTPException(status_code=400, detail="只支持 CSV 文件")
        
        # 保存临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as temp_file:
            content = await csv_file.read()
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            # 解析 CSV
            df = generator.parse_csv(temp_path)
            
            # 构建 CPAG
            cpag_data = generator.build_cpag(df, device_map_dict)
            
            # 生成输出目录
            task_id = str(uuid.uuid4())
            output_dir = f"outputs/{task_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存结果
            output_file = os.path.join(output_dir, "cpag.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(cpag_data, f, ensure_ascii=False, indent=2)
            
            return {
                "status": "success",
                "task_id": task_id,
                "output_file": output_file,
                "nodes_count": len(cpag_data["nodes"]),
                "edges_count": len(cpag_data["edges"]),
                "cpag_data": cpag_data
            }
            
        finally:
            # 清理临时文件
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"处理失败: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
