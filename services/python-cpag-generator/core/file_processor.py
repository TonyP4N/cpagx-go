#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Processor for CPAG Generator v2
整合cpag_builder和cpag_e2e的功能，根据文件类型自动选择处理方式
"""

import os
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

# 导入现有的处理模块
from .generators import PCAPCPAGGenerator, CSVCPAGGenerator

# 导入v2专用模块
try:
    from api.v2.cpag_builder import run as run_csv_builder
    from api.v2.cpag_e2e_module import run_pcap_processing
    V2_MODULES_AVAILABLE = True
except ImportError:
    V2_MODULES_AVAILABLE = False
    


class FileProcessor:
    """文件处理器，根据文件类型选择最佳处理方式"""
    
    def __init__(self):
        self.supported_extensions = {
            'csv': ['.csv'],
            'pcap': ['.pcap', '.pcapng']
        }
    
    def detect_file_type(self, file_path: str) -> Optional[str]:
        """检测文件类型"""
        if not file_path or not os.path.exists(file_path):
    
            return None
            
        ext = Path(file_path).suffix.lower()

        
        for file_type, extensions in self.supported_extensions.items():
            if ext in extensions:
                return file_type
                
        return None
    
    def process_csv_v2(self, csv_path: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """使用v2的cpag_builder处理CSV文件"""
        if not V2_MODULES_AVAILABLE:
            # 回退到核心生成器
            return self.process_csv_core(csv_path, output_dir, **kwargs)
            
        try:
            # 设置默认参数，输出最好的结果
            params = {
                'build_minimal': True,
                'build_enhanced': True,
                'pre_s': kwargs.get('pre_window', 20),
                'post_s': kwargs.get('post_window', 20),
                'per_tag': kwargs.get('per_tag', 5),
                'top_k_analog': kwargs.get('top_k_analog', 3),
                'visualize': kwargs.get('visualize', True)
            }
            
            # 调用v2的CSV处理器
            run_csv_builder(
                csv_path=Path(csv_path),
                out_dir=Path(output_dir),
                **params
            )
            
            # 读取生成的结果
            results = self._read_csv_results(output_dir)
            return results
            
        except Exception as e:
            print(f"Error in CSV v2 processing: {e}")
            # 回退到核心生成器
            return self.process_csv_core(csv_path, output_dir, **kwargs)
    
    def process_pcap_v2(self, pcap_path: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """使用v2的cpag_e2e处理PCAP文件"""
        if not V2_MODULES_AVAILABLE:
            # 回退到核心生成器
            return self.process_pcap_core(pcap_path, output_dir, **kwargs)
            
        try:
            # 调用模块化的PCAP处理函数
            result = run_pcap_processing(
                pcap_path=pcap_path,
                outdir=output_dir,
                max_pkts=kwargs.get('max_pkts', 120000),
                target_cip=kwargs.get('target_cip', 8000),
                top_k=kwargs.get('top_k', 40),
                top_per_plc=kwargs.get('top_per_plc', 20),
                neo4j_uri=kwargs.get('neo4j_uri'),
                neo4j_user=kwargs.get('neo4j_user'),
                neo4j_password=kwargs.get('neo4j_password'),
                neo4j_db=kwargs.get('neo4j_db', 'neo4j'),
                label=kwargs.get('neo4j_label', 'CPAGNode'),
                wipe=kwargs.get('wipe_neo4j', False)
            )
            
            # 读取生成的结果
            results = self._read_pcap_results(output_dir)
            results.update(result)
            return results
            
        except Exception as e:
            print(f"Error in PCAP v2 processing: {e}")
            # 回退到核心生成器
            return self.process_pcap_core(pcap_path, output_dir, **kwargs)
    
    def process_csv_core(self, csv_path: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """使用核心生成器处理CSV文件"""
        try:
            generator = CSVCPAGGenerator()
            csv_df = generator.parse_csv(csv_path)
            device_map = kwargs.get('device_map', {})
            
            cpag_graph = generator.build_cpag(csv_df, device_map)
            
            # 保存结果
            os.makedirs(output_dir, exist_ok=True)
            result_file = os.path.join(output_dir, 'cpag_core.json')
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(cpag_graph, f, ensure_ascii=False, indent=2)
            
            return {
                'status': 'completed',
                'method': 'core',
                'files': ['cpag_core.json'],
                'result': cpag_graph
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'method': 'core',
                'error': str(e)
            }
    
    def process_pcap_core(self, pcap_path: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """使用核心生成器处理PCAP文件"""
        try:
            generator = PCAPCPAGGenerator()
            pcap_data = generator.parse_pcap(pcap_path)
            device_map = kwargs.get('device_map', {})
            
            cpag_graph = generator.build_cpag(pcap_data, device_map)
            
            # 保存结果
            os.makedirs(output_dir, exist_ok=True)
            result_file = os.path.join(output_dir, 'cpag_core.json')
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(cpag_graph, f, ensure_ascii=False, indent=2)
            
            return {
                'status': 'completed',
                'method': 'core',
                'files': ['cpag_core.json'],
                'result': cpag_graph
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'method': 'core',
                'error': str(e)
            }
    
    def _read_csv_results(self, output_dir: str) -> Dict[str, Any]:
        """读取CSV处理结果"""
        results = {
            'status': 'completed',
            'method': 'v2_csv',
            'files': [],
            'results': {}
        }
        
        # 检查生成的文件
        expected_files = [
            'cpag_minimal.json',
            'cpag_enhanced.json',
            'cpag_minimal.png',
            'cpag_enhanced.png'
        ]
        
        for filename in expected_files:
            file_path = os.path.join(output_dir, filename)
            if os.path.exists(file_path):
                results['files'].append(filename)
                if filename.endswith('.json'):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            results['results'][filename] = json.load(f)
                    except Exception as e:
                        print(f"Error reading {filename}: {e}")
        
        # 选择最佳结果（优先enhanced，其次minimal）
        if 'cpag_enhanced.json' in results['results']:
            results['best_result'] = results['results']['cpag_enhanced.json']
        elif 'cpag_minimal.json' in results['results']:
            results['best_result'] = results['results']['cpag_minimal.json']
        
        return results
    
    def _read_pcap_results(self, output_dir: str) -> Dict[str, Any]:
        """读取PCAP处理结果"""
        results = {
            'status': 'completed',
            'method': 'v2_pcap',
            'files': [],
            'results': {}
        }
        
        # 检查生成的文件
        expected_files = [
            'cpag_units.json',
            'enip_cip_requests_parsed.csv',
            'cpag_nodes.csv',
            'cpag_edges.csv',
            'cpag_bundled_nodes.csv',
            'cpag_bundled_edges.csv'
        ]
        
        for filename in expected_files:
            file_path = os.path.join(output_dir, filename)
            if os.path.exists(file_path):
                results['files'].append(filename)
                if filename.endswith('.json'):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            results['results'][filename] = json.load(f)
                    except Exception as e:
                        print(f"Error reading {filename}: {e}")
        
        # 选择最佳结果（cpag_units.json）
        if 'cpag_units.json' in results['results']:
            results['best_result'] = results['results']['cpag_units.json']
        
        return results
    
    def process_file(self, file_path: str, output_dir: str, **kwargs) -> Dict[str, Any]:
        """处理文件的主入口"""
        file_type = self.detect_file_type(file_path)
        
        if not file_type:
            return {
                'status': 'failed',
                'error': f'Unsupported file type: {Path(file_path).suffix}'
            }
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 根据文件类型选择处理方式
        if file_type == 'csv':
            return self.process_csv_v2(file_path, output_dir, **kwargs)
        elif file_type == 'pcap':
            return self.process_pcap_v2(file_path, output_dir, **kwargs)
        else:
            return {
                'status': 'failed',
                'error': f'Unsupported file type: {file_type}'
            }


# 全局实例
file_processor = FileProcessor()
