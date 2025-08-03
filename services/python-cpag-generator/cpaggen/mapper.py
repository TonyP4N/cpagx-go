import pandas as pd
from typing import Dict, List, Any
import re

class DeviceMapper:
    def __init__(self):
        self.device_patterns = {
            'router': r'192\.168\.1\.1|10\.0\.0\.1',
            'switch': r'192\.168\.1\.2|10\.0\.0\.2',
            'firewall': r'192\.168\.1\.3|10\.0\.0\.3',
            'server': r'192\.168\.1\.(10[0-9]|1[1-9][0-9]|2[0-4][0-9]|25[0-5])',
            'workstation': r'192\.168\.1\.(2[0-4][0-9]|25[0-5])',
            'iot_device': r'192\.168\.1\.(1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
        }
    
    def map_devices(self, packets_df: pd.DataFrame, device_map: Dict[str, str]) -> pd.DataFrame:
        """
        将数据包中的IP地址映射到设备
        
        Args:
            packets_df: 解析后的数据包DataFrame
            device_map: IP到设备名称的映射字典
            
        Returns:
            包含设备映射信息的DataFrame
        """
        if packets_df.empty:
            return packets_df
        
        # 复制DataFrame避免修改原始数据
        mapped_df = packets_df.copy()
        
        # 添加设备映射列
        mapped_df['src_device'] = mapped_df['src_ip'].apply(
            lambda ip: self._map_ip_to_device(ip, device_map)
        )
        mapped_df['dst_device'] = mapped_df['dst_ip'].apply(
            lambda ip: self._map_ip_to_device(ip, device_map)
        )
        
        # 添加设备类型
        mapped_df['src_device_type'] = mapped_df['src_device'].apply(
            self._get_device_type
        )
        mapped_df['dst_device_type'] = mapped_df['dst_device'].apply(
            self._get_device_type
        )
        
        return mapped_df
    
    def _map_ip_to_device(self, ip: str, device_map: Dict[str, str]) -> str:
        """将IP地址映射到设备名称"""
        # 直接映射
        if ip in device_map:
            return device_map[ip]
        
        # 模式匹配
        for device_type, pattern in self.device_patterns.items():
            if re.match(pattern, ip):
                return f"{device_type}_{ip.replace('.', '_')}"
        
        # 默认映射
        return f"unknown_{ip.replace('.', '_')}"
    
    def _get_device_type(self, device_name: str) -> str:
        """获取设备类型"""
        if not device_name:
            return "unknown"
        
        # 从设备名称中提取类型
        for device_type in self.device_patterns.keys():
            if device_type in device_name.lower():
                return device_type
        
        return "unknown"
    
    def get_device_summary(self, mapped_df: pd.DataFrame) -> Dict[str, Any]:
        """获取设备摘要信息"""
        if mapped_df.empty:
            return {}
        
        summary = {
            'total_devices': len(set(mapped_df['src_device'].tolist() + mapped_df['dst_device'].tolist())),
            'device_types': {},
            'top_communicating_devices': {},
            'device_connections': {}
        }
        
        # 设备类型统计
        all_devices = pd.concat([mapped_df['src_device'], mapped_df['dst_device']])
        device_types = pd.concat([mapped_df['src_device_type'], mapped_df['dst_device_type']])
        
        summary['device_types'] = device_types.value_counts().to_dict()
        
        # 最活跃设备
        device_counts = all_devices.value_counts()
        summary['top_communicating_devices'] = device_counts.head(10).to_dict()
        
        # 设备连接关系
        connections = mapped_df.groupby(['src_device', 'dst_device']).size()
        summary['device_connections'] = connections.to_dict()
        
        return summary
    
    def filter_by_device_type(self, mapped_df: pd.DataFrame, device_type: str) -> pd.DataFrame:
        """按设备类型过滤"""
        return mapped_df[
            (mapped_df['src_device_type'] == device_type) |
            (mapped_df['dst_device_type'] == device_type)
        ]
    
    def get_device_communication_matrix(self, mapped_df: pd.DataFrame) -> pd.DataFrame:
        """获取设备通信矩阵"""
        if mapped_df.empty:
            return pd.DataFrame()
        
        # 创建通信矩阵
        matrix = mapped_df.groupby(['src_device', 'dst_device']).size().unstack(fill_value=0)
        
        # 填充缺失值
        matrix = matrix.fillna(0)
        
        return matrix 