"""
Enhanced Confidence Calculator for CPAG Generation
Provides multi-factor confidence scoring for attack graph edges and nodes
"""

from typing import Dict, List, Any, Optional, Tuple
import math
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
import re


class ConfidenceCalculator:
    """
    Multi-factor confidence calculator for CPAG generation
    
    Considers:
    - Evidence quantity and quality
    - Protocol type and behavior patterns
    - Temporal consistency 
    - Attack pattern matching
    - Device type relevance
    - Network topology factors
    """
    
    def __init__(self):
        # Protocol confidence weights (base confidence by protocol type)
        self.protocol_weights = {
            'modbus': 0.95,      # High confidence - clear industrial protocol
            'enip': 0.90,        # High confidence - EtherNet/IP
            's7': 0.90,          # High confidence - Siemens S7
            'dnp3': 0.88,        # High confidence - DNP3
            'profinet': 0.85,    # Good confidence - Profinet
            'bacnet': 0.80,      # Good confidence - BACnet
            'ssh': 0.75,         # Medium confidence - could be legit admin
            'telnet': 0.85,      # Higher confidence - usually suspicious
            'http': 0.60,        # Lower confidence - could be normal
            'https': 0.65,       # Slightly higher than HTTP
            'ftp': 0.70,         # Medium confidence
            'snmp': 0.55,        # Lower confidence - often legitimate
            'rdp': 0.80,         # Higher confidence - remote access
            'vnc': 0.82,         # Higher confidence - remote access
            'unknown': 0.40      # Low confidence for unknown protocols
        }
        
        # Port-based protocol detection
        self.port_to_protocol = {
            502: 'modbus',
            44818: 'enip',
            102: 's7',
            2404: 's7', 
            20000: 'dnp3',
            47808: 'bacnet',
            22: 'ssh',
            23: 'telnet',
            80: 'http',
            443: 'https',
            21: 'ftp',
            161: 'snmp',
            3389: 'rdp',
            5900: 'vnc'
        }
        
        # Attack category impact weights
        self.category_weights = {
            'session': 0.7,           # Session establishment
            'reconnaissance': 0.8,    # Information gathering  
            'state_change': 0.95,     # Direct process manipulation
            'persistence': 0.85,      # Maintaining access
            'lateral_movement': 0.80, # Moving through network
            'data_exfiltration': 0.90 # Data theft
        }
        
        # Device type criticality weights
        self.device_criticality = {
            'plc': 0.95,      # Programmable Logic Controller
            'hmi': 0.90,      # Human Machine Interface
            'scada': 0.95,    # SCADA system
            'sensor': 0.75,   # Sensor readings
            'actuator': 0.90, # Process actuators
            'pump': 0.85,     # Pumps
            'valve': 0.85,    # Valves
            'workstation': 0.70,  # Engineering workstation
            'server': 0.80,   # Industrial server
            'switch': 0.60,   # Network switch
            'router': 0.65,   # Network router
            'unknown': 0.50   # Unknown device
        }
    
    def calculate_edge_confidence(self, 
                                source_node: Dict[str, Any], 
                                target_node: Dict[str, Any], 
                                evidence: Dict[str, Any],
                                context: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate confidence score for a CPAG edge
        
        Args:
            source_node: Source node information
            target_node: Target node information  
            evidence: Evidence supporting this edge
            context: Additional context (timeline, related events, etc.)
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        
        # Base confidence from protocol type
        protocol_conf = self._get_protocol_confidence(evidence)
        
        # Evidence quantity factor
        evidence_conf = self._calculate_evidence_confidence(evidence)
        
        # Attack category relevance
        category_conf = self._get_category_confidence(source_node, target_node, evidence)
        
        # Device criticality factor
        device_conf = self._get_device_confidence(target_node, evidence)
        
        # Temporal consistency factor
        temporal_conf = self._calculate_temporal_confidence(evidence, context)
        
        # Attack pattern matching
        pattern_conf = self._calculate_pattern_confidence(source_node, target_node, evidence, context)
        
        # Network topology factor
        topology_conf = self._calculate_topology_confidence(source_node, target_node, context)
        
        # Weighted combination of all factors
        weights = {
            'protocol': 0.25,
            'evidence': 0.20, 
            'category': 0.15,
            'device': 0.15,
            'temporal': 0.10,
            'pattern': 0.10,
            'topology': 0.05
        }
        
        final_confidence = (
            protocol_conf * weights['protocol'] +
            evidence_conf * weights['evidence'] +
            category_conf * weights['category'] +
            device_conf * weights['device'] +
            temporal_conf * weights['temporal'] +
            pattern_conf * weights['pattern'] +
            topology_conf * weights['topology']
        )
        
        # Apply sigmoid normalization to smooth the result
        final_confidence = self._apply_sigmoid(final_confidence)
        
        # Ensure result is in valid range
        return max(0.1, min(0.99, final_confidence))
    
    def _get_protocol_confidence(self, evidence: Dict[str, Any]) -> float:
        """Get confidence based on protocol type"""
        
        # Try to determine protocol from port
        port = evidence.get('port', evidence.get('dport', evidence.get('dest_port')))
        if port:
            try:
                port_num = int(port)
                protocol = self.port_to_protocol.get(port_num, 'unknown')
                return self.protocol_weights.get(protocol, 0.40)
            except (ValueError, TypeError):
                pass
        
        # Try to determine from service name
        service = evidence.get('service', evidence.get('service_name', ''))
        if service:
            service_lower = service.lower()
            for proto_name, weight in self.protocol_weights.items():
                if proto_name in service_lower:
                    return weight
        
        # Check for modbus function codes
        if evidence.get('modbus_function') or evidence.get('function_code'):
            return self.protocol_weights['modbus']
            
        return self.protocol_weights['unknown']
    
    def _calculate_evidence_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence quantity and quality"""
        
        count = evidence.get('count', 1)
        
        # Evidence quantity scoring (logarithmic scale)
        if count <= 0:
            quantity_score = 0.1
        elif count == 1:
            quantity_score = 0.4  # Single occurrence
        elif count <= 5:
            quantity_score = 0.6  # Few occurrences
        elif count <= 20:
            quantity_score = 0.75  # Multiple occurrences
        elif count <= 100:
            quantity_score = 0.85  # Many occurrences
        else:
            quantity_score = 0.95  # Very frequent pattern
        
        # Evidence quality factors
        quality_factors = []
        
        # Source/destination information available
        if evidence.get('source') and evidence.get('destination'):
            quality_factors.append(0.2)
        elif evidence.get('source') or evidence.get('destination'):
            quality_factors.append(0.1)
            
        # Timestamp information
        if evidence.get('timestamp') or evidence.get('timestamps'):
            quality_factors.append(0.15)
            
        # Protocol-specific details
        if evidence.get('function_code') or evidence.get('modbus_function'):
            quality_factors.append(0.25)
            
        # Service information
        if evidence.get('service'):
            quality_factors.append(0.1)
        
        quality_score = min(1.0, 0.5 + sum(quality_factors))
        
        # Combine quantity and quality
        return (quantity_score * 0.7 + quality_score * 0.3)
    
    def _get_category_confidence(self, source_node: Dict[str, Any], 
                                target_node: Dict[str, Any], 
                                evidence: Dict[str, Any]) -> float:
        """Get confidence based on attack category appropriateness"""
        
        # Determine category from nodes or evidence
        category = (target_node.get('category') or 
                   source_node.get('category') or 
                   evidence.get('category', 'session'))
        
        base_weight = self.category_weights.get(category, 0.5)
        
        # Adjust based on attack logic appropriateness
        source_type = source_node.get('type', '')
        target_type = target_node.get('type', '')
        
        # Logical flow bonuses
        if source_type == 'precondition' and target_type == 'action':
            base_weight *= 1.1  # Natural precondition -> action flow
        elif source_type == 'action' and target_type == 'postcondition':
            base_weight *= 1.1  # Natural action -> postcondition flow
        elif source_type == 'action' and target_type == 'action':
            base_weight *= 0.9  # Action chains need more scrutiny
            
        return min(1.0, base_weight)
    
    def _get_device_confidence(self, target_node: Dict[str, Any], 
                              evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on target device criticality"""
        
        # Extract device information
        device_info = (target_node.get('device') or 
                      evidence.get('device') or 
                      target_node.get('target', ''))
        
        if not device_info:
            return 0.5  # Neutral if no device info
        
        device_info_lower = str(device_info).lower()
        
        # Match device type
        for device_type, criticality in self.device_criticality.items():
            if device_type in device_info_lower:
                return criticality
        
        # Check for industrial indicators
        industrial_indicators = ['ait', 'fit', 'lit', 'pit', 'mv', 'uv', 'pump', 'plc']
        for indicator in industrial_indicators:
            if indicator in device_info_lower:
                return 0.85  # High criticality for industrial devices
        
        return self.device_criticality['unknown']
    
    def _calculate_temporal_confidence(self, evidence: Dict[str, Any], 
                                     context: Optional[Dict[str, Any]]) -> float:
        """Calculate confidence based on temporal patterns"""
        
        if not context:
            return 0.5  # Neutral if no temporal context
        
        # Check for timestamp clustering (attacks often happen in bursts)
        timestamps = evidence.get('timestamps', [])
        if len(timestamps) < 2:
            return 0.5
        
        try:
            # Convert to datetime objects if needed
            dt_timestamps = []
            for ts in timestamps[:10]:  # Limit to prevent performance issues
                if isinstance(ts, (int, float)):
                    dt_timestamps.append(datetime.fromtimestamp(ts))
                elif isinstance(ts, str):
                    dt_timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
            
            if len(dt_timestamps) < 2:
                return 0.5
            
            # Calculate time intervals
            intervals = []
            for i in range(1, len(dt_timestamps)):
                delta = (dt_timestamps[i] - dt_timestamps[i-1]).total_seconds()
                intervals.append(delta)
            
            # Clustered events (short intervals) suggest coordinated attack
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 60:  # Less than 1 minute apart
                return 0.9  # High confidence for rapid sequence
            elif avg_interval < 300:  # Less than 5 minutes apart
                return 0.8
            elif avg_interval < 3600:  # Less than 1 hour apart
                return 0.7
            else:
                return 0.6  # Spread out events, lower confidence
                
        except Exception:
            return 0.5  # Error in temporal analysis
    
    def _calculate_pattern_confidence(self, source_node: Dict[str, Any],
                                    target_node: Dict[str, Any],
                                    evidence: Dict[str, Any],
                                    context: Optional[Dict[str, Any]]) -> float:
        """Calculate confidence based on attack pattern matching"""
        
        if not context:
            return 0.5
        
        # Check for known attack patterns
        pattern_score = 0.5
        
        # Pattern 1: Progressive privilege escalation
        source_name = source_node.get('name', '')
        target_name = target_node.get('name', '')
        
        if 'Reachable' in source_name and 'Scan' in target_name:
            pattern_score += 0.2  # Network recon pattern
        elif 'Connected' in source_name and 'Read' in target_name:
            pattern_score += 0.2  # Information gathering pattern
        elif 'Read' in source_name and 'Write' in target_name:
            pattern_score += 0.3  # Escalation to control pattern
        
        # Pattern 2: Industrial protocol abuse
        if evidence.get('port') in [502, 44818, 102, 2404]:
            if 'write' in target_name.lower() or 'control' in target_name.lower():
                pattern_score += 0.25  # Industrial control abuse
        
        # Pattern 3: Lateral movement indicators
        source_ip = evidence.get('source', '')
        dest_ip = evidence.get('destination', '')
        if source_ip and dest_ip and source_ip != dest_ip:
            # Different IPs suggest lateral movement
            pattern_score += 0.1
        
        return min(1.0, pattern_score)
    
    def _calculate_topology_confidence(self, source_node: Dict[str, Any],
                                     target_node: Dict[str, Any],
                                     context: Optional[Dict[str, Any]]) -> float:
        """Calculate confidence based on network topology factors"""
        
        if not context:
            return 0.5
        
        # Network proximity factors
        topology_score = 0.5
        
        # Check if source and target are in same network segment
        source_ip = source_node.get('source', '')
        target_ip = target_node.get('target', '')
        
        if source_ip and target_ip:
            try:
                # Simple subnet check (same first 3 octets)
                source_subnet = '.'.join(source_ip.split('.')[:3])
                target_subnet = '.'.join(target_ip.split('.')[:3])
                
                if source_subnet == target_subnet:
                    topology_score += 0.2  # Same subnet increases confidence
                    
            except Exception:
                pass  # IP parsing failed
        
        # Check for device relationships in context
        device_map = context.get('device_map', {})
        if device_map:
            source_device = device_map.get(source_ip, source_ip)
            target_device = device_map.get(target_ip, target_ip)
            
            # Related devices (same naming pattern) increase confidence
            if source_device and target_device:
                if self._devices_related(source_device, target_device):
                    topology_score += 0.15
        
        return min(1.0, topology_score)
    
    def _devices_related(self, device1: str, device2: str) -> bool:
        """Check if two devices appear to be related based on naming"""
        
        # Extract base names (remove numbers)
        base1 = re.sub(r'\d+', '', device1).strip('_-')
        base2 = re.sub(r'\d+', '', device2).strip('_-')
        
        # Check for common prefixes/patterns
        if base1 and base2:
            if base1 == base2:  # Same base name
                return True
            if base1 in base2 or base2 in base1:  # One contains the other
                return True
            
        return False
    
    def _apply_sigmoid(self, x: float) -> float:
        """Apply sigmoid function to smooth confidence values"""
        try:
            # Sigmoid with adjustable parameters
            # Maps input range approximately [0.2, 0.8] to output [0.1, 0.9]
            return 1 / (1 + math.exp(-6 * (x - 0.5)))
        except (OverflowError, ValueError):
            return max(0.1, min(0.9, x))
    
    def get_confidence_explanation(self, confidence: float, 
                                  factors: Dict[str, float]) -> str:
        """Generate human-readable explanation for confidence score"""
        
        explanations = []
        
        if confidence >= 0.85:
            explanations.append("High confidence")
        elif confidence >= 0.7:
            explanations.append("Good confidence")
        elif confidence >= 0.5:
            explanations.append("Medium confidence")
        else:
            explanations.append("Low confidence")
        
        # Add factor explanations
        if factors.get('protocol', 0) > 0.8:
            explanations.append("strong protocol evidence")
        if factors.get('evidence', 0) > 0.8:
            explanations.append("multiple occurrences")
        if factors.get('device', 0) > 0.8:
            explanations.append("critical device targeted")
        
        return " - " + ", ".join(explanations)
