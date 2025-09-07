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
from celery import current_task
from infrastructure.celery_app import celery_app
import redis
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

# Task concurrency control
from core.config import get_config
config = get_config()
MAX_CONCURRENT_TASKS = config.max_concurrent_tasks_v2

# Output directory
OUTPUT_BASE_DIR = os.path.abspath(os.getenv("OUTPUT_DIR", "outputs/v2"))
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

# Redis connection
try:
    redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
except Exception:
    redis_client = None

# Neo4j connection managed by UnifiedCPAGProcessor
# Keep neo4j_driver for health checks only
try:
    from neo4j import GraphDatabase
    neo4j_driver = GraphDatabase.driver(
        os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        auth=(os.getenv('NEO4J_USER', 'neo4j'), os.getenv('NEO4J_PASSWORD', 'password'))
    )
except ImportError:
    neo4j_driver = None
    print("Warning: Neo4j driver not available for health checks")

# InfluxDB client initialization
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
    build_enhanced: bool,
    pre_window: int,
    post_window: int,
    per_tag: int,
    top_k_analog: int,
    visualize: bool,
    custom_params: Optional[Dict[str, Any]] = None
):
    """Generate CPAG Celery task with concurrency control"""
    try:
        # Check concurrency limits
        if redis_client:
            try:
                current_active = len(redis_client.smembers("v2_active_tasks"))
                if current_active >= MAX_CONCURRENT_TASKS:
                    raise Exception(f"Too many concurrent tasks. Maximum allowed: {MAX_CONCURRENT_TASKS}")
                
                # Add to active task set
                redis_client.sadd("v2_active_tasks", task_id)
                redis_client.expire("v2_active_tasks", 3600)
            except Exception as e:
                print(f"Redis concurrency check failed: {e}")
        
        # Update task status to Redis
        if redis_client:
            try:
                status_info = {
                    "task_id": task_id,
                    "status": "processing",
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception as e:
                print(f"Failed to update task status to Redis: {e}")
        
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Starting CPAG generation...'}
        )
        
        # Record task start time
        start_time: Optional[datetime] = datetime.utcnow()
        record_task_metric(task_id, 'task_started', start_time)
        
        # Step 1: File type detection and processing (40%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 20, 'total': 100, 'status': 'Detecting file type and processing...'}
        )
        
        # Use unified file processor (core v2 functionality)
        from .unified_cpag_processor import UnifiedCPAGProcessor
        
        # Determine file to process
        input_file = file_path if file_path else csv_path
        if not input_file:
            raise ValueError("No input file provided")
        
        # Prepare Neo4j configuration
        neo4j_config = None
        if neo4j_uri and neo4j_user and neo4j_password:
            neo4j_config = {
                'uri': neo4j_uri,
                'user': neo4j_user,
                'password': neo4j_password,
                'database': neo4j_db,
                'label': neo4j_label,
                'wipe': wipe_neo4j,
                'task_id': task_id  # Add task_id for data isolation
            }
            print(f"Neo4j config prepared for task {task_id}: uri={neo4j_uri}, user={neo4j_user}")
        else:
            print(f"No Neo4j config for task {task_id}: uri={neo4j_uri}, user={neo4j_user}, password={'***' if neo4j_password else 'None'}")
        
        # Create unified processor
        processor = UnifiedCPAGProcessor(use_structured_matching=True)
        
        # Process file
        processing_result = processor.process_file(
            file_path=input_file,
            output_dir=os.path.join(os.getenv("OUTPUT_DIR", "outputs/v2"), task_id),
            device_map=device_map,
            rules=rules,
            max_pkts=120000,  # Extract from kwargs or use default
            target_cip=8000,
            top_k=top_k,
            top_per_plc=top_per_plc,
            neo4j_config=neo4j_config,
            build_enhanced=build_enhanced,
            pre_window=pre_window,
            post_window=post_window,
            per_tag=per_tag,
            top_k_analog=top_k_analog,
            visualize=visualize,
            custom_params=custom_params  # Pass custom parameters
        )
        
        if processing_result.get('status') == 'failed':
            raise Exception(processing_result.get('error', 'Processing failed'))
        
        # Get processing results
        cpag_graph = processing_result.get('graph_data', {})
        cpag_units = processing_result.get('units', processing_result.get('cpag_units', []))
        
        # Step 2: Neo4j storage result check (60%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 60, 'total': 100, 'status': 'Checking Neo4j storage...'}
        )
        
        # Neo4j storage completed in unified processor, check results
        neo4j_stored = processing_result.get('neo4j_stored', False)
        neo4j_error = processing_result.get('neo4j_error')
        
        if neo4j_config:
            if neo4j_stored:
                print("SUCCESS: Data successfully stored to Neo4j")
            else:
                print(f"WARNING: Neo4j storage failed: {neo4j_error}")
        else:
            print("INFO: Neo4j storage skipped (no configuration provided)")
        
        # Step 3: Generate visualizations (80%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 80, 'total': 100, 'status': 'Generating visualizations...'}
        )
        
        if visualize:
            # Visualization functionality implemented in UnifiedCPAGProcessor
            print(f"Visualization completed for task {task_id}")
        
        # Step 4: Complete (100%)
        self.update_state(
            state='PROGRESS',
            meta={'current': 100, 'total': 100, 'status': 'Task completed successfully'}
        )
        
        # Record task completion time
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds() if isinstance(start_time, datetime) else 0.0
        record_task_metric(task_id, 'task_completed', end_time, {'duration': duration})
        
        # Save results to Redis
        result = {
            'task_id': task_id,
            'status': 'completed',
            'result': cpag_graph,
            'units': cpag_units,  # Add units field
            'created_at': (start_time.isoformat() + "Z") if isinstance(start_time, datetime) else None,
            'completed_at': end_time.isoformat(),
            'duration': duration,
            'version': 'v2'
        }
        
        if redis_client:
            try:
                redis_client.setex(f"task_result:{task_id}", 3600, json.dumps(result))
                # Update status
                status_info = {
                    "task_id": task_id,
                    "status": "completed",
                    "result_url": f"/cpag/result/{task_id}",
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception as e:
                print(f"Failed to save task result to Redis: {e}")
        
        # Write manifest file
        try:
            from infrastructure.status import write_manifest
            # Get file information
            input_file = file_path if file_path else csv_path
            file_size = os.path.getsize(input_file) if input_file and os.path.exists(input_file) else None
            file_name = os.path.basename(input_file) if input_file else None
            
            # Ensure correct time format
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
                "files": ["cpag_enhanced.json", "cpag_tcity.json"],
                "file_size": file_size,
                "file_name": file_name
            }
            print(f"Writing manifest for task {task_id} with created_at: {created_at_str}")
            write_manifest(OUTPUT_BASE_DIR, task_id, manifest)
        except Exception as e:
            print(f"Failed to write manifest for task {task_id}: {e}")
        
        # Clean up temporary files
        cleanup_temp_files([file_path, csv_path])
        
        return result
        
    except Exception as e:
        # Record error
        error_time = datetime.utcnow()
        record_task_metric(task_id, 'task_failed', error_time, {'error': str(e)})
        
        # Save error information to Redis
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
        
        if redis_client:
            try:
                redis_client.setex(f"task_result:{task_id}", 3600, json.dumps(error_result))
                # Update status
                status_info = {
                    "task_id": task_id,
                    "status": "failed",
                    "error": str(e),
                    "version": "v2"
                }
                redis_client.setex(f"task_status:{task_id}", 3600, json.dumps(status_info))
            except Exception as redis_error:
                print(f"Failed to save error result to Redis: {redis_error}")
        
        # Write error manifest file
        try:
            from infrastructure.status import write_manifest
            # Get file information
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
        
        # Clean up temporary files
        cleanup_temp_files([file_path, csv_path])
        
        raise
    finally:
        # Remove from active task set
        if redis_client:
            try:
                redis_client.srem("v2_active_tasks", task_id)
            except Exception as e:
                print(f"Failed to remove task from active set: {e}")


# Utility functions

def record_task_metric(task_id: str, event: str, timestamp: datetime, additional_data: Optional[Dict[str, Any]] = None):
    """Record task metrics to InfluxDB"""
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
    """Record network metrics to InfluxDB"""
    if Point is None or write_api is None:
        return
    point = Point("network_analysis").tag("task_id", task_id).field("devices_count", len(analysis_result.get('devices', {}))).field("anomalies_count", len(analysis_result.get('anomalies', [])))
    
    write_api.write(bucket=os.getenv('INFLUXDB_BUCKET', 'cpagx_data'), record=point)

def record_health_metrics(health_status: Dict[str, Any]):
    """Record health metrics to InfluxDB"""
    if Point is None or write_api is None:
        return
    point = Point("system_health").field("redis", 1 if health_status.get('redis') else 0).field("neo4j", 1 if health_status.get('neo4j') else 0).field("influxdb", 1 if health_status.get('influxdb') else 0).field("overall", 1 if health_status.get('overall') else 0)
    
    write_api.write(bucket=os.getenv('INFLUXDB_BUCKET', 'cpagx_data'), record=point)

def cleanup_temp_files(file_paths: List[Optional[str]]):
    """Clean temporary files"""
    for file_path in file_paths:
        if file_path and os.path.exists(file_path):
            try:
                os.unlink(file_path)
            except:
                pass

def delete_old_metrics(cutoff_date: datetime):
    """Remove expired metrics"""
    # InfluxDB old data deletion logic
    pass


@celery_app.task(name='api.v2.tasks.collect_metrics')
def collect_metrics():
    """Gather system health data"""
    try:
        # Check health status of services
        redis_health = _check_redis_health()
        neo4j_health = _check_neo4j_health()
        influxdb_health = _check_influxdb_health()
        
        # Record health status
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
    """System health check"""
    try:
        # Check health status of each service
        services_health = {}
        
        # Check health status of each service
        services_health = {
            'redis': _get_service_status(redis_client, lambda c: c.ping()),
            'neo4j': _get_service_status(neo4j_driver, lambda d: d.session().run("RETURN 1")),
            'influxdb': _get_service_status(influx_client, lambda c: c.ping())
        }
        
        # Record health check results
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

# Internal health check utility functions
def _check_redis_health() -> bool:
    """Redis health check"""
    try:
        return redis_client is not None and redis_client.ping()
    except Exception:
        return False

def _check_neo4j_health() -> bool:
    """Neo4j health check"""
    try:
        if neo4j_driver is None:
            return False
        with neo4j_driver.session() as session:
            session.run("RETURN 1")
        return True
    except Exception:
        return False

def _check_influxdb_health() -> bool:
    """InfluxDB health check"""
    try:
        return influx_client is not None and influx_client.ping()
    except Exception:
        return False

def _get_service_status(client, health_check_func):
    """Generic service status check"""
    if client is None:
        return 'unavailable'
    try:
        health_check_func(client)
        return 'healthy'
    except Exception as e:
        return f'unhealthy: {str(e)}'

@celery_app.task(name='api.v2.tasks.cleanup_old_tasks')
def cleanup_old_tasks():
    """Clean up old task data"""
    try:
        # Clean up task data older than 7 days
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        # Clean up old task status in Redis
        if redis_client:
            try:
                task_keys = redis_client.keys("task_status:*")
                cleaned_count = 0
                for key in task_keys:
                    task_data = redis_client.get(key)
                    if task_data:
                        task_info = json.loads(task_data)
                        created_at = datetime.fromisoformat(task_info.get('created_at', '').replace('Z', '+00:00'))
                        if created_at < cutoff_date:
                            redis_client.delete(key)
                            cleaned_count += 1
                print(f"Cleaned {cleaned_count} old task status records")
            except Exception as e:
                print(f"Failed to clean Redis data: {e}")
        
        # Clean up old metrics in InfluxDB
        try:
            delete_old_metrics(cutoff_date)
        except Exception as e:
            print(f"Failed to clean InfluxDB data: {e}")
        
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
