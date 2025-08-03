import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from typing import List, Dict, Any
import asyncio
from .ics_layers import detect_ics_protocol, is_ics_traffic

class PCAPParser:
    """PCAP文件解析器"""
    
    def __init__(self):
        self.supported_protocols = ['tcp', 'udp', 'icmp', 'ics']
    
    async def parse_pcap(self, pcap_file: str) -> pd.DataFrame:
        """
        异步解析PCAP文件
        
        Args:
            pcap_file: PCAP文件路径
            
        Returns:
            DataFrame包含解析后的数据包信息
        """
        # 在实际实现中，这里应该使用异步文件读取
        # 目前使用同步方式作为占位符
        return await asyncio.get_event_loop().run_in_executor(
            None, self._parse_pcap_sync, pcap_file
        )
    
    def _parse_pcap_sync(self, pcap_file: str) -> pd.DataFrame:
        """同步解析PCAP文件"""
        try:
            # 读取PCAP文件
            packets = rdpcap(pcap_file)
            
            # 解析数据包
            parsed_data = []
            for packet in packets:
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    parsed_data.append(packet_info)
            
            # 转换为DataFrame
            df = pd.DataFrame(parsed_data)
            return df
            
        except Exception as e:
            raise Exception(f"Failed to parse PCAP file: {str(e)}")
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """提取单个数据包的信息"""
        try:
            # 基础信息
            packet_info = {
                'timestamp': packet.time,
                'length': len(packet),
                'protocol': 'unknown',
                'is_ics': False,
                'ics_protocols': []
            }
            
            # IP层信息
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto
                })
            
            # TCP层信息
            if TCP in packet:
                packet_info.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'flags': packet[TCP].flags,
                    'seq': packet[TCP].seq,
                    'ack': packet[TCP].ack
                })
            
            # UDP层信息
            elif UDP in packet:
                packet_info.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
            
            # ICS协议检测
            if is_ics_traffic(packet):
                packet_info['is_ics'] = True
                packet_info['ics_protocols'] = detect_ics_protocol(packet)
            
            return packet_info
            
        except Exception:
            return None
    
    def filter_by_protocol(self, df: pd.DataFrame, protocol: str) -> pd.DataFrame:
        """按协议过滤数据包"""
        if protocol.lower() == 'tcp':
            return df[df['protocol'] == 6]  # TCP协议号
        elif protocol.lower() == 'udp':
            return df[df['protocol'] == 17]  # UDP协议号
        elif protocol.lower() == 'icmp':
            return df[df['protocol'] == 1]   # ICMP协议号
        elif protocol.lower() == 'ics':
            return df[df['is_ics'] == True]  # ICS流量
        else:
            return df
    
    def get_connection_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """获取连接摘要信息"""
        if df.empty:
            return {}
        
        summary = {
            'total_packets': len(df),
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dst_ips': df['dst_ip'].nunique(),
            'protocols': df['protocol'].value_counts().to_dict(),
            'ics_packets': len(df[df['is_ics'] == True]),
            'time_range': {
                'start': df['timestamp'].min(),
                'end': df['timestamp'].max()
            }
        }
        
        # ICS协议统计
        if 'ics_protocols' in df.columns:
            all_ics_protocols = []
            for protocols in df[df['is_ics'] == True]['ics_protocols']:
                all_ics_protocols.extend(protocols)
            summary['ics_protocols'] = pd.Series(all_ics_protocols).value_counts().to_dict()
        
        return summary 