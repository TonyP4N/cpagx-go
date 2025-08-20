#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Celery Tasks for CPAG Generator v2.0
Enhanced with RabbitMQ, Redis, Neo4j, and InfluxDB
"""

import os
import json
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import pandas as pd
import networkx as nx
from celery import current_task
from infrastructure.celery_app import celery_app
import redis
from neo4j import GraphDatabase
# Optional InfluxDB dependency placeholders to avoid import errors at module import time
try:
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS
    INFLUXDB_AVAILABLE = True
except ImportError:
    InfluxDBClient = None  # type: ignore
    Point = None  # type: ignore
    SYNCHRONOUS = None  # type: ignore
    INFLUXDB_AVAILABLE = False
    print("Warning: InfluxDB client not available, metrics collection will be disabled")

# 任务并发控制
from core.config import get_config
config = get_config()
MAX_CONCURRENT_TASKS = config.max_concurrent_tasks_v2

# 输出目录
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs/v2"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

# 数据库连接
try:
    redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
except Exception:
    redis_client = None

neo4j_driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
    auth=(os.getenv('NEO4J_USER', 'neo4j'), os.getenv('NEO4J_PASSWORD', 'password'))
)

# InfluxDB客户端初始化
influx_client = None
write_api = None

if INFLUXDB_AVAILABLE and InfluxDBClient is not None:
    try:
        influx_url = os.getenv('INFLUXDB_URL', 'http://localhost:8086')
        influx_token = os.getenv('INFLUXDB_TOKEN', 'cpagx-admin-token-2024')
        influx_org = os.getenv('INFLUXDB_ORG', 'cpagx')
        
        if influx_token and influx_token != 'your-token-here':
            influx_client = InfluxDBClient(
                url=influx_url,
                token=influx_token,
                org=influx_org
            )
            write_api = influx_client.write_api(write_options=SYNCHRONOUS)
            print(f"InfluxDB client initialized successfully: {influx_url}")
        else:
            print("Warning: InfluxDB token not configured, metrics collection disabled")
    except Exception as e:
        print(f"Warning: Failed to initialize InfluxDB client: {e}")
        influx_client = None
        write_api = None

@celery_app.task(bind=True)
def generate_cpag(
    self,
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
    """生成CPAG的Celery任务 - 带并发控制"""
    try:
        # 检查并发限制
        current_active = 0
        if redis_client:
            try:
                current_active = len(redis_client.smembers("v2_active_tasks"))
            except Exception:
                pass
        
        if current_active >= MAX_CONCURRENT_TASKS:
            raise Exception(f"Too many concurrent tasks. Maximum allowed: {MAX_CONCURRENT_TASKS}")
        
        # 添加到活跃任务集合
        if redis_client:
            try:
                redis_client.sadd("v2_active_tasks", task_id)
                redis_client.expire("v2_active_tasks", 3600)  # 1小时过期
            except Exception:
                pass
        
        # 更新任务状态到Redis
        if redis_client is not None:
            try:
                status_info = {
                    "task_id": task_id,
                    "status": "processing",
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception:
                pass
        
        # 更新任务状态
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Starting CPAG generation...'}
        )
        
        # 记录任务开始时间
        start_time: Optional[datetime] = datetime.utcnow()
        record_task_metric(task_id, 'task_started', start_time)
        
        # 步骤1: 文件类型检测和处理 (40%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 20, 'total': 100, 'status': 'Detecting file type and processing...'}
        )
        
        # 使用统一的文件处理器（v2的核心功能）
        from .unified_cpag_processor import UnifiedCPAGProcessor
        
        # 确定要处理的文件
        input_file = file_path if file_path else csv_path
        if not input_file:
            raise ValueError("No input file provided")
        
        # 准备Neo4j配置
        neo4j_config = None
        if neo4j_uri and neo4j_user and neo4j_password:
            neo4j_config = {
                'uri': neo4j_uri,
                'user': neo4j_user,
                'password': neo4j_password,
                'database': neo4j_db,
                'label': neo4j_label,
                'wipe': wipe_neo4j,
                'task_id': task_id  # 添加task_id用于数据隔离
            }
        
        # 创建统一处理器
        processor = UnifiedCPAGProcessor()
        
        # 处理文件
        processing_result = processor.process_file(
            file_path=input_file,
            output_dir=os.path.join(os.getenv("OUTPUT_DIR", "outputs/v2"), task_id),
            device_map=device_map,
            rules=rules,
            max_pkts=120000,  # 从kwargs中提取或使用默认值
            target_cip=8000,
            top_k=top_k,
            top_per_plc=top_per_plc,
            neo4j_config=neo4j_config,
            build_minimal=build_minimal,
            build_enhanced=build_enhanced,
            pre_window=pre_window,
            post_window=post_window,
            per_tag=per_tag,
            top_k_analog=top_k_analog,
            visualize=visualize
        )
        
        if processing_result.get('status') == 'failed':
            raise Exception(processing_result.get('error', 'Processing failed'))
        
        # 获取处理结果
        cpag_graph = processing_result.get('graph_data', {})
        
        # 步骤2: Neo4j存储结果检查 (60%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 60, 'total': 100, 'status': 'Checking Neo4j storage...'}
        )
        
        # Neo4j存储已在统一处理器中完成，检查结果
        neo4j_stored = processing_result.get('neo4j_stored', False)
        neo4j_error = processing_result.get('neo4j_error')
        
        if neo4j_config:
            if neo4j_stored:
                print("SUCCESS: Data successfully stored to Neo4j")
            else:
                print(f"WARNING: Neo4j storage failed: {neo4j_error}")
        else:
            print("INFO: Neo4j storage skipped (no configuration provided)")
        
        # 步骤3: 生成可视化 (80%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 80, 'total': 100, 'status': 'Generating visualizations...'}
        )
        
        if visualize:
            generate_visualizations(cpag_graph, task_id)
        
        # 步骤4: 完成 (100%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 100, 'total': 100, 'status': 'Task completed successfully'}
        )
        
        # 记录任务完成时间
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds() if isinstance(start_time, datetime) else 0.0
        record_task_metric(task_id, 'task_completed', end_time, {'duration': duration})
        
        # 保存结果到Redis
        result = {
            'task_id': task_id,
            'status': 'completed',
            'result': cpag_graph,
            'created_at': (start_time.isoformat() + "Z") if isinstance(start_time, datetime) else None,
            'completed_at': end_time.isoformat(),
            'duration': duration,
            'version': 'v2'
        }
        
        if redis_client is not None:
            try:
                redis_client.setex(f"task_result:{task_id}", 3600, json.dumps(result))
                # 更新状态
                status_info = {
                    "task_id": task_id,
                    "status": "completed",
                    "result_url": f"/cpag/result/{task_id}",
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception:
                pass
        
        # 写入manifest文件
        try:
            from infrastructure.status import write_manifest
            # 获取文件信息
            input_file = file_path if file_path else csv_path
            file_size = os.path.getsize(input_file) if input_file and os.path.exists(input_file) else None
            file_name = os.path.basename(input_file) if input_file else None
            
            # 确保使用正确的时间格式
            if isinstance(start_time, datetime):
                created_at_str = start_time.isoformat() + "Z"
            else:
                created_at_str = datetime.utcnow().isoformat() + "Z"
                print(f"Warning: start_time is not datetime for task {task_id}, using current time")
            
            manifest = {
                "task_id": task_id,
                "version": "v2",
                "status": "completed",
                "created_at": created_at_str,
                "files": ["cpag_enhanced.json", "cpag_minimal.json"],
                "file_size": file_size,
                "file_name": file_name
            }
            print(f"Writing manifest for task {task_id} with created_at: {created_at_str}")
            write_manifest(OUTPUT_BASE_DIR, task_id, manifest)
        except Exception as e:
            print(f"Failed to write manifest for task {task_id}: {e}")
        
        # 清理临时文件
        cleanup_temp_files([file_path, csv_path])
        
        return result
        
    except Exception as e:
        # 记录错误
        error_time = datetime.utcnow()
        record_task_metric(task_id, 'task_failed', error_time, {'error': str(e)})
        
        # 保存错误信息到Redis
        st = locals().get('start_time')
        created_at_value = (st.isoformat() + "Z") if isinstance(st, datetime) else (datetime.utcnow().isoformat() + "Z")
        error_result = {
            'task_id': task_id,
            'status': 'failed',
            'error': str(e),
            'created_at': created_at_value,
            'failed_at': error_time.isoformat(),
            'version': 'v2'
        }
        
        if redis_client is not None:
            try:
                redis_client.setex(f"task_result:{task_id}", 3600, json.dumps(error_result))
                # 更新状态
                status_info = {
                    "task_id": task_id,
                    "status": "failed",
                    "error": str(e),
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception:
                pass
        
        # 写入错误manifest文件
        try:
            from infrastructure.status import write_manifest
            # 获取文件信息
            input_file = file_path if file_path else csv_path
            file_size = os.path.getsize(input_file) if input_file and os.path.exists(input_file) else None
            file_name = os.path.basename(input_file) if input_file else None
            
            error_manifest = {
                "task_id": task_id,
                "version": "v2",
                "status": "failed",
                "created_at": (st.isoformat() + "Z") if isinstance(st, datetime) else (datetime.utcnow().isoformat() + "Z"),
                "error": str(e),
                "files": [],
                "file_size": file_size,
                "file_name": file_name
            }
            write_manifest(OUTPUT_BASE_DIR, task_id, error_manifest)
        except Exception as manifest_error:
            print(f"Failed to write error manifest for task {task_id}: {manifest_error}")
        
        # 清理临时文件
        cleanup_temp_files([file_path, csv_path])
        
        raise
    finally:
        # 从活跃任务集合中移除
        if redis_client:
            try:
                redis_client.srem("v2_active_tasks", task_id)
            except Exception:
                pass

@celery_app.task
def analyze_network(task_id: str, network_data: Dict[str, Any]):
    """网络分析任务"""
    try:
        # 网络分析逻辑
        analysis_result = perform_network_analysis(network_data)
        
        # 存储分析结果到InfluxDB
        record_network_metrics(task_id, analysis_result)
        
        return analysis_result
    except Exception as e:
        record_task_metric(task_id, 'network_analysis_failed', datetime.utcnow(), {'error': str(e)})
        raise

@celery_app.task
def build_graph(task_id: str, analysis_data: Dict[str, Any]):
    """图构建任务"""
    try:
        # 图构建逻辑
        graph_result = build_attack_graph(analysis_data)
        
        # 存储图数据到Neo4j
        store_graph_to_neo4j(task_id, graph_result)
        
        return graph_result
    except Exception as e:
        record_task_metric(task_id, 'graph_building_failed', datetime.utcnow(), {'error': str(e)})
        raise

# 辅助函数
def parse_input_files(file_path: Optional[str], csv_path: Optional[str]) -> Dict[str, Any]:
    """解析输入文件"""
    parsed_data = {}
    
    if file_path:
        # 解析PCAP文件
        parsed_data['pcap'] = parse_pcap_file(file_path)
    
    if csv_path:
        # 解析CSV文件
        parsed_data['csv'] = parse_csv_file(csv_path)
    
    return parsed_data

def analyze_network_traffic(parsed_data: Dict[str, Any], device_map: Dict[str, str]) -> Dict[str, Any]:
    """分析网络流量"""
    # 网络分析逻辑
    return {
        'devices': device_map,
        'traffic_patterns': {},
        'anomalies': [],
        'timeline': []
    }

def build_cpag_graph(network_analysis: Dict[str, Any], rules: List[str], minimal: bool, enhanced: bool) -> Dict[str, Any]:
    """构建CPAG图"""
    # 构建CPAG图的逻辑
    return {
        'nodes': [],
        'edges': [],
        'metadata': {
            'generated_at': datetime.utcnow().isoformat(),
            'version': 'v2',
            'rules_applied': rules
        }
    }

def store_to_neo4j(cpag_graph: Dict[str, Any], uri: str, user: str, password: str, db: str, label: str, wipe: bool):
    """存储到Neo4j"""
    from api.v2.cpag_e2e_module import store_cpag_to_neo4j
    try:
        store_cpag_to_neo4j(cpag_graph, uri, user, password, db, label, wipe)
        print(f"Successfully stored CPAG to Neo4j: {len(cpag_graph.get('nodes', []))} nodes, {len(cpag_graph.get('edges', []))} edges")
    except Exception as e:
        print(f"Failed to store to Neo4j: {e}")
        raise

def generate_visualizations(cpag_graph: Dict[str, Any], task_id: str):
    """生成可视化"""
    # 生成图表的逻辑
    pass

def record_task_metric(task_id: str, event: str, timestamp: datetime, additional_data: Optional[Dict[str, Any]] = None):
    """记录任务指标到InfluxDB"""
    if Point is None or write_api is None:
        return
    point = Point("task_events").tag("task_id", task_id).tag("event", event).field("timestamp", timestamp.timestamp())
    
    if additional_data:
        for key, value in additional_data.items():
            if isinstance(value, (int, float)):
                point = point.field(key, value)
            else:
                point = point.tag(key, str(value))
    
    write_api.write(bucket=os.getenv('INFLUXDB_BUCKET', 'cpagx_data'), record=point)

def record_network_metrics(task_id: str, analysis_result: Dict[str, Any]):
    """记录网络指标到InfluxDB"""
    if Point is None or write_api is None:
        return
    point = Point("network_analysis").tag("task_id", task_id).field("devices_count", len(analysis_result.get('devices', {}))).field("anomalies_count", len(analysis_result.get('anomalies', [])))
    
    write_api.write(bucket=os.getenv('INFLUXDB_BUCKET', 'cpagx_data'), record=point)

def record_health_metrics(health_status: Dict[str, Any]):
    """记录健康指标到InfluxDB"""
    if Point is None or write_api is None:
        return
    point = Point("system_health").field("redis", 1 if health_status.get('redis') else 0).field("neo4j", 1 if health_status.get('neo4j') else 0).field("influxdb", 1 if health_status.get('influxdb') else 0).field("overall", 1 if health_status.get('overall') else 0)
    
    write_api.write(bucket=os.getenv('INFLUXDB_BUCKET', 'cpagx_data'), record=point)

def cleanup_temp_files(file_paths: List[Optional[str]]):
    """清理临时文件"""
    for file_path in file_paths:
        if file_path and os.path.exists(file_path):
            try:
                os.unlink(file_path)
            except:
                pass

def delete_old_metrics(cutoff_date: datetime):
    """删除旧指标"""
    # InfluxDB删除旧数据的逻辑
    pass

def parse_pcap_file(file_path: str) -> Dict[str, Any]:
    """解析PCAP文件"""
    # PCAP解析逻辑
    return {}

def parse_csv_file(file_path: str) -> Dict[str, Any]:
    """解析CSV文件"""
    # CSV解析逻辑
    return {}

def perform_network_analysis(network_data: Dict[str, Any]) -> Dict[str, Any]:
    """执行网络分析"""
    # 网络分析逻辑
    return {}

def build_attack_graph(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """构建攻击图"""
    # 攻击图构建逻辑
    return {}

def store_graph_to_neo4j(task_id: str, graph_result: Dict[str, Any]):
    """存储图到Neo4j"""
    # Neo4j存储逻辑
    pass

@celery_app.task(name='api.v2.tasks.collect_metrics')
def collect_metrics():
    """收集系统指标"""
    try:
        # 检查Redis连接
        redis_health = False
        try:
            if redis_client is not None:
                redis_client.ping()
                redis_health = True
        except Exception:
            pass
        
        # 检查Neo4j连接
        neo4j_health = False
        try:
            with neo4j_driver.session() as session:
                session.run("RETURN 1")
                neo4j_health = True
        except:
            pass
        
        # 检查InfluxDB连接
        influxdb_health = False
        try:
            if influx_client is not None:
                influx_client.ping()
                influxdb_health = True
        except:
            pass
        
        # 记录健康状态
        health_status = {
            'redis': redis_health,
            'neo4j': neo4j_health,
            'influxdb': influxdb_health,
            'overall': all([redis_health, neo4j_health, influxdb_health])
        }
        
        record_health_metrics(health_status)
        
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'health': health_status
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

@celery_app.task(name='api.v2.tasks.health_check')
def health_check():
    """系统健康检查"""
    try:
        # 检查各个服务的健康状态
        services_health = {}
        
        # Redis健康检查
        try:
            if redis_client is not None:
                redis_client.ping()
                services_health['redis'] = 'healthy'
            else:
                services_health['redis'] = 'unavailable'
        except Exception as e:
            services_health['redis'] = f'unhealthy: {str(e)}'
        
        # Neo4j健康检查
        try:
            with neo4j_driver.session() as session:
                session.run("RETURN 1")
                services_health['neo4j'] = 'healthy'
        except Exception as e:
            services_health['neo4j'] = f'unhealthy: {str(e)}'
        
        # InfluxDB健康检查
        try:
            if influx_client is not None:
                influx_client.ping()
                services_health['influxdb'] = 'healthy'
            else:
                services_health['influxdb'] = 'unavailable'
        except Exception as e:
            services_health['influxdb'] = f'unhealthy: {str(e)}'
        
        # 记录健康检查结果
        record_health_metrics({
            'redis': services_health.get('redis') == 'healthy',
            'neo4j': services_health.get('neo4j') == 'healthy',
            'influxdb': services_health.get('influxdb') == 'healthy',
            'overall': all(v == 'healthy' for v in services_health.values())
        })
        
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'services': services_health
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

@celery_app.task(name='api.v2.tasks.cleanup_old_tasks')
def cleanup_old_tasks():
    """清理旧任务数据"""
    try:
        # 清理7天前的任务数据
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        # 清理Redis中的旧任务状态
        try:
            # 获取所有任务状态键
            task_keys = redis_client.keys("task_status:*") if redis_client is not None else []
            for key in task_keys:
                task_data = redis_client.get(key) if redis_client is not None else None
                if task_data:
                    task_info = json.loads(task_data)
                    created_at = datetime.fromisoformat(task_info.get('created_at', '').replace('Z', '+00:00'))
                    if created_at < cutoff_date:
                        if redis_client is not None:
                            redis_client.delete(key)
        except Exception as e:
            print(f"清理Redis数据失败: {e}")
        
        # 清理InfluxDB中的旧指标
        try:
            delete_old_metrics(cutoff_date)
        except Exception as e:
            print(f"清理InfluxDB数据失败: {e}")
        
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
