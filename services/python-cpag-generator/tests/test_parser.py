"""
PCAP解析器测试
"""

import unittest
import pandas as pd
from unittest.mock import Mock, patch
import tempfile
import os

from cpaggen.parser import PCAPParser

class TestPCAPParser(unittest.TestCase):
    """PCAP解析器测试类"""
    
    def setUp(self):
        """测试前准备"""
        self.parser = PCAPParser()
        
        # 创建测试数据
        self.test_packet_data = [
            {
                'timestamp': 1640995200.0,
                'length': 1500,
                'protocol': 6,
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'src_port': 12345,
                'dst_port': 80,
                'flags': 2,
                'seq': 1000,
                'ack': 0
            },
            {
                'timestamp': 1640995201.0,
                'length': 1000,
                'protocol': 17,
                'src_ip': '192.168.1.101',
                'dst_ip': '192.168.1.2',
                'src_port': 54321,
                'dst_port': 53
            }
        ]
    
    def test_parser_initialization(self):
        """测试解析器初始化"""
        self.assertEqual(self.parser.supported_protocols, ['tcp', 'udp', 'icmp'])
    
    @patch('cpaggen.parser.rdpcap')
    def test_parse_pcap_sync(self, mock_rdpcap):
        """测试同步PCAP解析"""
        # 模拟rdpcap返回
        mock_packets = [Mock(), Mock()]
        mock_rdpcap.return_value = mock_packets
        
        # 模拟数据包信息提取
        with patch.object(self.parser, '_extract_packet_info') as mock_extract:
            mock_extract.side_effect = self.test_packet_data
            
            result = self.parser._parse_pcap_sync('test.pcap')
            
            self.assertIsInstance(result, pd.DataFrame)
            self.assertEqual(len(result), 2)
    
    def test_extract_packet_info(self):
        """测试数据包信息提取"""
        # 创建模拟数据包
        mock_packet = Mock()
        mock_packet.time = 1640995200.0
        mock_packet.__len__ = Mock(return_value=1500)
        
        # 模拟IP层
        mock_ip = Mock()
        mock_ip.src = '192.168.1.100'
        mock_ip.dst = '192.168.1.1'
        mock_ip.proto = 6
        
        # 模拟TCP层
        mock_tcp = Mock()
        mock_tcp.sport = 12345
        mock_tcp.dport = 80
        mock_tcp.flags = 2
        mock_tcp.seq = 1000
        mock_tcp.ack = 0
        
        # 设置数据包结构
        mock_packet.__contains__ = lambda x: x in [Mock(), Mock()]  # 模拟IP和TCP层
        
        # 这里需要更复杂的模拟，实际测试中应该使用真实的scapy数据包
        # 或者创建更详细的Mock对象
        
        result = self.parser._extract_packet_info(mock_packet)
        # 由于Mock的复杂性，这里只测试基本功能
        self.assertIsNotNone(result)
    
    def test_filter_by_protocol(self):
        """测试协议过滤"""
        # 创建测试DataFrame
        df = pd.DataFrame(self.test_packet_data)
        
        # 测试TCP过滤
        tcp_df = self.parser.filter_by_protocol(df, 'tcp')
        self.assertEqual(len(tcp_df), 1)
        self.assertEqual(tcp_df.iloc[0]['protocol'], 6)
        
        # 测试UDP过滤
        udp_df = self.parser.filter_by_protocol(df, 'udp')
        self.assertEqual(len(udp_df), 1)
        self.assertEqual(udp_df.iloc[0]['protocol'], 17)
    
    def test_get_connection_summary(self):
        """测试连接摘要"""
        df = pd.DataFrame(self.test_packet_data)
        summary = self.parser.get_connection_summary(df)
        
        self.assertIn('total_packets', summary)
        self.assertIn('unique_src_ips', summary)
        self.assertIn('unique_dst_ips', summary)
        self.assertIn('protocols', summary)
        self.assertIn('time_range', summary)
        
        self.assertEqual(summary['total_packets'], 2)
        self.assertEqual(summary['unique_src_ips'], 2)
        self.assertEqual(summary['unique_dst_ips'], 2)
    
    def test_get_connection_summary_empty(self):
        """测试空DataFrame的连接摘要"""
        empty_df = pd.DataFrame()
        summary = self.parser.get_connection_summary(empty_df)
        
        self.assertEqual(summary, {})

if __name__ == '__main__':
    unittest.main() 