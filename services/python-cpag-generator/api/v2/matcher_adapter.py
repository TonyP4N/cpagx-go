#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
matcher_adapter.py
------------------
Adapter to integrate EventMatcher with existing CPAG processing pipeline.

This module bridges the gap between the current implementation and the 
structured matching logic with enhanced time-window based correlation.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime
import sys
import os

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from core.event_matcher import EventMatcher, FocalEvent, SourceType, MatchingConfig


class MatcherAdapter:
    """Adapter to integrate EventMatcher with existing processors"""
    
    def __init__(self, config: Optional[MatchingConfig] = None):
        self.matcher = EventMatcher(config)
        
    def process_network_data(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Process network data (PCAP) using paper-compliant matching.
        
        Args:
            df: DataFrame with parsed network packets
            
        Returns:
            List of PAP units
        """
        # Extract focal events from network data
        focal_events = self._extract_network_focal_events(df)
        
        # Prepare conditions DataFrame
        conditions_df = self._prepare_network_conditions(df)
        
        # Perform matching
        units = self.matcher.match_events(
            focal_events=focal_events,
            conditions_df=conditions_df,
            source=SourceType.NETWORK
        )
        
        return units
    
    def process_process_data(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Process process data (CSV) using paper-compliant matching.
        
        Args:
            df: DataFrame with time-series process data
            
        Returns:
            List of PAP units
        """
        # Extract focal events from process data
        focal_events = self._extract_process_focal_events(df)
        
        # Prepare conditions DataFrame
        conditions_df = self._prepare_process_conditions(df)
        
        # Perform matching
        units = self.matcher.match_events(
            focal_events=focal_events,
            conditions_df=conditions_df,
            source=SourceType.PROCESS
        )
        
        return units
    
    def _extract_network_focal_events(self, df: pd.DataFrame) -> List[FocalEvent]:
        """Extract focal events from network data"""
        focal_events = []
        
        # Find timestamp column
        timestamp_col = None
        for col in ['timestamp', 'time', 'Timestamp', 'Time', '_time']:
            if col in df.columns:
                timestamp_col = col
                break
        
        if timestamp_col is None:
            print("Warning: No timestamp column found in network data")
            return focal_events
        
        # Ensure timestamp is in datetime format
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
        
        # Focus on write operations, critical reads, and session establishments
        if 'service_name' in df.columns:
            # ENIP/CIP services
            write_ops = df[df['service_name'].str.contains('Write', na=False)]
            for idx, row in write_ops.iterrows():
                timestamp = row[timestamp_col]
                if pd.isna(timestamp):
                    continue
                    
                event = FocalEvent(
                    id=f"net_event_{idx}",
                    timestamp=timestamp,
                    semantics={
                        'protocol': row.get('protocol', 'enip'),
                        'operation': row['service_name'],
                        'dst': row.get('dst', ''),
                        'src': row.get('src', ''),
                        'path': row.get('path', ''),
                        'value': row.get('value', None)
                    },
                    source=SourceType.NETWORK,
                    raw_data={
                        'packet_idx': idx,
                        'service': row['service_name']
                    }
                )
                focal_events.append(event)
                
            # Also extract critical reads
            read_ops = df[df['service_name'].str.contains('Read', na=False)]
            # Sample to avoid too many events
            if len(read_ops) > 100:
                read_ops = read_ops.sample(n=100)
                
            for idx, row in read_ops.iterrows():
                timestamp = row[timestamp_col]
                if pd.isna(timestamp):
                    continue
                    
                event = FocalEvent(
                    id=f"net_event_{idx}",
                    timestamp=timestamp,
                    semantics={
                        'protocol': row.get('protocol', 'enip'),
                        'operation': row['service_name'],
                        'dst': row.get('dst', ''),
                        'src': row.get('src', ''),
                        'path': row.get('path', '')
                    },
                    source=SourceType.NETWORK,
                    raw_data={'packet_idx': idx}
                )
                focal_events.append(event)
                
        elif 'is_write' in df.columns:
            # Fallback for different schema
            writes = df[df['is_write'] == True]
            for idx, row in writes.iterrows():
                timestamp = row[timestamp_col]
                if pd.isna(timestamp):
                    continue
                    
                event = FocalEvent(
                    id=f"net_event_{idx}",
                    timestamp=timestamp,
                    semantics={
                        'protocol': 'industrial',
                        'operation': 'write',
                        'dst': row.get('dst', ''),
                        'src': row.get('src', '')
                    },
                    source=SourceType.NETWORK
                )
                focal_events.append(event)
                
        return focal_events
    
    def _extract_process_focal_events(self, df: pd.DataFrame) -> List[FocalEvent]:
        """Extract focal events from process data"""
        focal_events = []
        
        # Find timestamp column
        timestamp_col = None
        for col in ['timestamp', 'time', 'Timestamp', 'Time', '_time']:
            if col in df.columns:
                timestamp_col = col
                break
        
        if timestamp_col is None:
            # If no timestamp column found, return empty list
            print("Warning: No timestamp column found in process data")
            return focal_events
        
        # Ensure timestamp is in datetime format
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
        
        # Detect significant changes in process variables
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if col == timestamp_col or '_time' in col.lower() or 'timestamp' in col.lower():
                continue
                
            # Detect state transitions
            transitions = self._detect_transitions(df[col])
            
            for trans_idx, trans_type, magnitude in transitions:
                timestamp = df.iloc[trans_idx][timestamp_col]
                if pd.isna(timestamp):
                    continue
                
                if isinstance(timestamp, str):
                    timestamp = pd.to_datetime(timestamp)
                    
                event = FocalEvent(
                    id=f"proc_event_{col}_{trans_idx}",
                    timestamp=timestamp,
                    semantics={
                        'tag': col,
                        'change_kind': trans_type,
                        'magnitude': magnitude,
                        'value_before': df.iloc[trans_idx-1][col] if trans_idx > 0 else None,
                        'value_after': df.iloc[trans_idx][col]
                    },
                    source=SourceType.PROCESS
                )
                focal_events.append(event)
                
        return focal_events
    
    def _prepare_network_conditions(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare conditions DataFrame for network matching"""
        conditions = []
        
        # Add timestamp if missing
        if 'timestamp' not in df.columns and 'time' in df.columns:
            df['timestamp'] = pd.to_datetime(df['time'], errors='coerce')
        elif 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        elif 'Timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        elif 'Time' in df.columns:
            df['timestamp'] = pd.to_datetime(df['Time'], errors='coerce')
            
        # TCP establishment conditions
        if 'tcp_flags' in df.columns:
            # SYN-ACK indicates established connection
            tcp_estab = df[df['tcp_flags'].str.contains('SA', na=False)]
            for _, row in tcp_estab.iterrows():
                conditions.append({
                    'timestamp': row['timestamp'],
                    'tcp_established': True,
                    'src': row.get('src', ''),
                    'dst': row.get('dst', '')
                })
                
        # Service responses
        if 'is_response' in df.columns:
            responses = df[df['is_response'] == True]
            for _, row in responses.iterrows():
                conditions.append({
                    'timestamp': row['timestamp'],
                    'is_response': True,
                    'service_type': row.get('service_name', ''),
                    'response_status': 'success' if row.get('error', False) == False else 'error'
                })
                
        # Session state
        if 'service_name' in df.columns:
            sessions = df[df['service_name'] == 'Forward_Open']
            for _, row in sessions.iterrows():
                conditions.append({
                    'timestamp': row['timestamp'],
                    'service_type': 'Forward_Open',
                    'session_id': row.get('session_id', '')
                })
                
        # Connection state tracking
        if len(df) > 1:
            # Group by src-dst pairs to track connection state
            for (src, dst), group in df.groupby(['src', 'dst']):
                if len(group) > 5:  # Active connection
                    conditions.append({
                        'timestamp': group.iloc[-1]['timestamp'],
                        'conn_state': 'established',
                        'src': src,
                        'dst': dst
                    })
                    
        conditions_df = pd.DataFrame(conditions)
        # Ensure timestamp column is datetime if DataFrame is not empty
        if len(conditions_df) > 0 and 'timestamp' in conditions_df.columns:
            conditions_df['timestamp'] = pd.to_datetime(conditions_df['timestamp'], errors='coerce')
        return conditions_df
    
    def _prepare_process_conditions(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare conditions DataFrame for process matching"""
        # For process data, the entire DataFrame can serve as conditions
        # since we're looking for patterns in the time series
        df_copy = df.copy()
        
        # Ensure timestamp column is in datetime format
        if 'timestamp' in df_copy.columns:
            df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'], errors='coerce')
        elif 'time' in df_copy.columns:
            df_copy['timestamp'] = pd.to_datetime(df_copy['time'], errors='coerce')
        elif 'Timestamp' in df_copy.columns:
            df_copy['timestamp'] = pd.to_datetime(df_copy['Timestamp'], errors='coerce')
        elif 'Time' in df_copy.columns:
            df_copy['timestamp'] = pd.to_datetime(df_copy['Time'], errors='coerce')
        
        return df_copy
    
    def _detect_transitions(self, series: pd.Series, threshold: float = 0.01) -> List[tuple]:
        """Detect transitions in a time series"""
        transitions = []
        
        if len(series) < 2:
            return transitions
            
        # Convert to numeric
        numeric = pd.to_numeric(series, errors='coerce')
        
        for i in range(1, len(numeric)):
            if pd.isna(numeric.iloc[i]) or pd.isna(numeric.iloc[i-1]):
                continue
                
            diff = numeric.iloc[i] - numeric.iloc[i-1]
            if abs(diff) > threshold:
                # Classify transition type
                if diff > 0:
                    trans_type = 'rise' if diff > 0.1 else 'increase'
                else:
                    trans_type = 'fall' if diff < -0.1 else 'decrease'
                    
                transitions.append((i, trans_type, diff))
                
        return transitions


def enhance_units_with_matcher(existing_units: List[Dict[str, Any]], 
                              df: pd.DataFrame,
                              source_type: str = 'network',
                              config: Optional[MatchingConfig] = None) -> List[Dict[str, Any]]:
    """
    Enhance existing CPAG units with structured matching.
    
    This function can be used to retrofit existing implementations with
    time-window based correlation and decision rules.
    """
    adapter = MatcherAdapter(config)
    
    if source_type == 'network':
        matched_units = adapter.process_network_data(df)
    else:
        matched_units = adapter.process_process_data(df)
        
    # Merge with existing units
    # Create lookup by ID for existing units
    existing_by_id = {unit['id']: unit for unit in existing_units}
    
    # Update existing units with matched information
    for matched in matched_units:
        unit_id = matched['id']
        if unit_id in existing_by_id:
            # Update existing unit
            existing_by_id[unit_id].update({
                'pre': matched['pre'],
                'post': matched['post'],
                'conf': matched['conf'],
                'strength': matched['strength']
            })
        else:
            # Add new unit
            existing_units.append(matched)
            
    return existing_units
