#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
event_matcher.py
----------------
Implementation of structured PAP unit matching and correlation logic.

This module implements:
- Time window-based precondition/postcondition matching
- Decision rules for semantic compatibility, temporal plausibility, coherence, and context
- Exclusive matching to ensure each event gets at most one effect
- Confidence scoring based on rule satisfaction and evidence strength
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import re


class SourceType(Enum):
    """Evidence source type"""
    NETWORK = "network"
    PROCESS = "process"


class ConditionType(Enum):
    """Condition types for matching"""
    # Network conditions
    REACHABLE = "Reachable"
    SERVICE_OPEN = "ServiceOpen" 
    SESSION_ESTABLISHED = "SessionEstablished"
    MODE_REMOTE = "ModeRemote"
    SERVICE_ACK = "ServiceAck"
    CONN_ALIVE = "ConnAlive"
    RETRY = "Retry"
    EXCEPTION = "Exception"
    
    # Process conditions
    TAG_AVAILABLE = "TagAvailable"
    STABLE_BASELINE = "StableBaseline"
    MODE_AUTO = "ModeAuto"
    STATE_CHANGE = "StateChange"
    STEP = "Step"
    SLOPE_FLIP = "SlopeFlip"
    DWELL = "Dwell"


@dataclass
class FocalEvent:
    """Focal event representation"""
    id: str
    timestamp: datetime
    semantics: Dict[str, Any]  # protocol, operation, address/tag, value etc.
    source: SourceType
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class Condition:
    """Pre/postcondition representation"""
    type: ConditionType
    timestamp: datetime
    details: Dict[str, Any]
    confidence: float = 1.0


@dataclass
class MatchingConfig:
    """Configuration for matching parameters"""
    delta_pre: timedelta = timedelta(seconds=30)  # Precondition window
    delta_post: timedelta = timedelta(seconds=30)  # Postcondition window
    d_min: timedelta = timedelta(seconds=5)  # Minimum dwell/persistence
    epsilon_step: float = 0.01  # Minimum step magnitude
    tau_lag: Optional[Dict[str, timedelta]] = None  # Expected lags by protocol/device
    
    def __post_init__(self):
        if self.tau_lag is None:
            self.tau_lag = {
                'modbus': timedelta(milliseconds=100),
                'enip': timedelta(milliseconds=150),
                'dnp3': timedelta(milliseconds=200),
                'default': timedelta(milliseconds=500)
            }


class EventMatcher:
    """
    Implements matching and correlation logic as described in Section 5 of the paper.
    
    Matches focal events with pre/postconditions within time windows,
    applies decision rules, and performs exclusive matching.
    """
    
    def __init__(self, config: Optional[MatchingConfig] = None):
        self.config = config or MatchingConfig()
        
    def match_events(self, 
                    focal_events: List[FocalEvent], 
                    conditions_df: pd.DataFrame,
                    source: SourceType) -> List[Dict[str, Any]]:
        """
        Main matching algorithm as per the paper.
        
        Args:
            focal_events: List of focal events to match
            conditions_df: DataFrame with all available conditions
            source: Source type (network or process)
            
        Returns:
            List of PAP units with matched pre/postconditions
        """
        units = []
        
        # Track assigned postconditions for exclusivity
        assigned_postconditions = set()
        
        for event in focal_events:
            # Extract pre/postconditions within windows
            preconditions = self._extract_preconditions(event, conditions_df)
            postcondition_candidates = self._extract_postcondition_candidates(event, conditions_df)
            
            # Apply exclusivity and decision rules to find best match
            best_postcondition = self._exclusive_matching(
                event, postcondition_candidates, assigned_postconditions, source
            )
            
            # Create PAP unit
            unit = self._create_pap_unit(event, preconditions, best_postcondition, source)
            units.append(unit)
            
            # Mark postcondition as assigned if found
            if best_postcondition:
                assigned_postconditions.add(id(best_postcondition))
                
        return units
    
    def _extract_preconditions(self, 
                              event: FocalEvent, 
                              conditions_df: pd.DataFrame) -> List[Condition]:
        """Extract preconditions within [t_e - Δ_pre, t_e] window"""
        window_start = event.timestamp - self.config.delta_pre
        window_end = event.timestamp
        
        # Filter conditions within time window
        mask = (conditions_df['timestamp'] >= window_start) & \
               (conditions_df['timestamp'] <= window_end)
        window_df = conditions_df[mask]
        
        preconditions = []
        
        if event.source == SourceType.NETWORK:
            # Network preconditions
            preconditions.extend(self._extract_network_preconditions(event, window_df))
        else:
            # Process preconditions
            preconditions.extend(self._extract_process_preconditions(event, window_df))
            
        return preconditions
    
    def _extract_postcondition_candidates(self,
                                        event: FocalEvent,
                                        conditions_df: pd.DataFrame) -> List[Condition]:
        """Extract postcondition candidates within [t_e, t_e + Δ_post] window"""
        window_start = event.timestamp
        window_end = event.timestamp + self.config.delta_post
        
        # Filter conditions within time window
        mask = (conditions_df['timestamp'] >= window_start) & \
               (conditions_df['timestamp'] <= window_end)
        window_df = conditions_df[mask]
        
        candidates = []
        
        if event.source == SourceType.NETWORK:
            # Network postconditions
            candidates.extend(self._extract_network_postconditions(event, window_df))
        else:
            # Process postconditions  
            candidates.extend(self._extract_process_postconditions(event, window_df))
            
        return candidates
    
    def _extract_network_preconditions(self, 
                                     event: FocalEvent,
                                     window_df: pd.DataFrame) -> List[Condition]:
        """Extract network-specific preconditions"""
        preconditions = []
        
        # Check for reachability
        if 'tcp_established' in window_df.columns:
            reachable = window_df[window_df['tcp_established'] == True]
            if not reachable.empty:
                preconditions.append(Condition(
                    type=ConditionType.REACHABLE,
                    timestamp=reachable.iloc[-1]['timestamp'],
                    details={'target': event.semantics.get('dst')}
                ))
        
        # Check for service/session state
        if 'service_type' in window_df.columns:
            services = window_df[window_df['service_type'].notna()]
            for _, svc in services.iterrows():
                if svc['service_type'] == 'Forward_Open':
                    preconditions.append(Condition(
                        type=ConditionType.SESSION_ESTABLISHED,
                        timestamp=svc['timestamp'],
                        details={'service': svc['service_type']}
                    ))
                    
        return preconditions
    
    def _extract_network_postconditions(self,
                                      event: FocalEvent, 
                                      window_df: pd.DataFrame) -> List[Condition]:
        """Extract network-specific postcondition candidates"""
        candidates = []
        
        # Look for service acknowledgments
        if 'is_response' in window_df.columns:
            responses = window_df[window_df['is_response'] == True]
            for _, resp in responses.iterrows():
                if self._is_matching_response(event.semantics, resp):
                    candidates.append(Condition(
                        type=ConditionType.SERVICE_ACK,
                        timestamp=resp['timestamp'],
                        details={
                            'status': resp.get('response_status', 'success'),
                            'service': resp.get('service_type', '')
                        }
                    ))
        
        # Check for connection aliveness
        if 'conn_state' in window_df.columns:
            alive = window_df[window_df['conn_state'] == 'established']
            if len(alive) > 1:  # Multiple packets = alive connection
                candidates.append(Condition(
                    type=ConditionType.CONN_ALIVE,
                    timestamp=alive.iloc[-1]['timestamp'],
                    details={'duration': (alive.iloc[-1]['timestamp'] - alive.iloc[0]['timestamp']).total_seconds()}
                ))
                
        return candidates
    
    def _extract_process_preconditions(self,
                                     event: FocalEvent,
                                     window_df: pd.DataFrame) -> List[Condition]:
        """Extract process-specific preconditions"""
        preconditions = []
        
        # Check for tag availability
        tag = event.semantics.get('tag')
        if tag and tag in window_df.columns:
            tag_data = window_df[window_df[tag].notna()]
            if not tag_data.empty:
                preconditions.append(Condition(
                    type=ConditionType.TAG_AVAILABLE,
                    timestamp=tag_data.iloc[-1]['timestamp'],
                    details={'tag': tag, 'value': tag_data.iloc[-1][tag]}
                ))
                
                # Check for stable baseline
                if len(tag_data) > 10:
                    values = pd.to_numeric(tag_data[tag], errors='coerce')
                    if values.std() < 0.1:  # Low variance = stable
                        preconditions.append(Condition(
                            type=ConditionType.STABLE_BASELINE,
                            timestamp=tag_data.iloc[-1]['timestamp'],
                            details={'tag': tag, 'std': values.std()}
                        ))
                        
        return preconditions
    
    def _extract_process_postconditions(self,
                                      event: FocalEvent,
                                      window_df: pd.DataFrame) -> List[Condition]:
        """Extract process-specific postcondition candidates"""
        candidates = []
        
        tag = event.semantics.get('tag')
        if not tag or tag not in window_df.columns:
            return candidates
            
        tag_data = window_df[window_df[tag].notna()].copy()
        if tag_data.empty:
            return candidates
            
        # Convert to numeric
        tag_data[tag] = pd.to_numeric(tag_data[tag], errors='coerce')
        
        # Detect state changes
        if len(tag_data) > 1:
            # Check for step change
            pre_value = tag_data.iloc[0][tag]
            for i in range(1, len(tag_data)):
                post_value = tag_data.iloc[i][tag]
                if abs(post_value - pre_value) > self.config.epsilon_step:
                    candidates.append(Condition(
                        type=ConditionType.STEP,
                        timestamp=tag_data.iloc[i]['timestamp'],
                        details={
                            'tag': tag,
                            'magnitude': post_value - pre_value,
                            'from': pre_value,
                            'to': post_value
                        }
                    ))
                    
            # Check for dwell (sustained value)
            if len(tag_data) > 5:
                last_values = tag_data.tail(5)[tag]
                if last_values.std() < 0.01:  # Very stable
                    duration = (tag_data.iloc[-1]['timestamp'] - tag_data.iloc[-5]['timestamp']).total_seconds()
                    if duration >= self.config.d_min.total_seconds():
                        candidates.append(Condition(
                            type=ConditionType.DWELL,
                            timestamp=tag_data.iloc[-1]['timestamp'],
                            details={
                                'tag': tag,
                                'value': last_values.mean(),
                                'duration': duration
                            }
                        ))
                        
        return candidates
    
    def _exclusive_matching(self,
                          event: FocalEvent,
                          candidates: List[Condition],
                          assigned: Set[int],
                          source: SourceType) -> Optional[Condition]:
        """
        Implement exclusive matching with decision rules.
        Returns best matching postcondition or None.
        """
        # Filter out already assigned candidates
        available = [c for c in candidates if id(c) not in assigned]
        
        if not available:
            return None
            
        # Score each candidate using decision rules
        scored = []
        for candidate in available:
            score = self._apply_decision_rules(event, candidate, source)
            if score > 0:  # Passes minimum requirements
                scored.append((score, candidate))
                
        if not scored:
            return None
            
        # Sort by score (descending), then by earliest onset
        scored.sort(key=lambda x: (-x[0], x[1].timestamp))
        
        return scored[0][1]  # Return best candidate
    
    def _apply_decision_rules(self,
                            event: FocalEvent,
                            candidate: Condition,
                            source: SourceType) -> float:
        """
        Apply 4 decision rules and return composite score.
        
        Rules:
        1. Semantic compatibility
        2. Temporal plausibility  
        3. Coherence/persistence
        4. Context sanity
        
        Returns score in [0, 1], where 0 means failed requirements.
        """
        scores = []
        
        # Rule 1: Semantic compatibility
        semantic_score = self._check_semantic_compatibility(event, candidate, source)
        if semantic_score == 0:
            return 0  # Hard fail
        scores.append(semantic_score)
        
        # Rule 2: Temporal plausibility
        temporal_score = self._check_temporal_plausibility(event, candidate)
        if temporal_score == 0:
            return 0  # Hard fail
        scores.append(temporal_score)
        
        # Rule 3: Coherence/persistence
        coherence_score = self._check_coherence_persistence(event, candidate, source)
        scores.append(coherence_score)
        
        # Rule 4: Context sanity (soft check - doesn't fail)
        context_score = self._check_context_sanity(event, candidate)
        scores.append(context_score)
        
        # Return weighted average
        return float(np.mean(scores))
    
    def _check_semantic_compatibility(self,
                                    event: FocalEvent,
                                    candidate: Condition,
                                    source: SourceType) -> float:
        """Check if semantics of event and condition are compatible"""
        if source == SourceType.NETWORK:
            # Network semantic rules
            operation = event.semantics.get('operation', '').lower()
            
            if 'write' in operation or 'fc6' in operation:
                # Write operations compatible with positive ack
                if candidate.type == ConditionType.SERVICE_ACK:
                    if candidate.details.get('status') == 'success':
                        return 1.0
                    else:
                        return 0.3  # Exception/error response
                        
            if 'read' in operation:
                # Read operations also need ack
                if candidate.type == ConditionType.SERVICE_ACK:
                    return 0.9
                    
            # Session management
            if candidate.type == ConditionType.CONN_ALIVE:
                return 0.8  # Most operations need live connection
                
        else:
            # Process semantic rules
            change_kind = event.semantics.get('change_kind', '')
            
            if change_kind == 'open' and candidate.type == ConditionType.STATE_CHANGE:
                # Open action matches state change
                if candidate.details.get('magnitude', 0) > 0:
                    return 1.0
                    
            if candidate.type == ConditionType.STEP:
                # Step changes match most control actions
                return 0.9
                
        return 0.2  # Low compatibility
    
    def _check_temporal_plausibility(self,
                                   event: FocalEvent,
                                   candidate: Condition) -> float:
        """Check temporal constraints"""
        lag = (candidate.timestamp - event.timestamp).total_seconds()
        
        if lag <= 0:
            return 0  # Effect before cause - fail
            
        if lag > self.config.delta_post.total_seconds():
            return 0  # Outside window - fail
            
        # Score based on expected lag
        protocol = event.semantics.get('protocol', 'default')
        if self.config.tau_lag is None:
            expected_sec = 0.5  # Default 500ms
        else:
            expected_lag = self.config.tau_lag.get(protocol, self.config.tau_lag.get('default', timedelta(milliseconds=500)))
            expected_sec = expected_lag.total_seconds()
        
        # Gaussian-like scoring around expected lag
        deviation = abs(lag - expected_sec) / expected_sec
        score = np.exp(-deviation)
        
        return float(score)
    
    def _check_coherence_persistence(self,
                                   event: FocalEvent,
                                   candidate: Condition,
                                   source: SourceType) -> float:
        """Check coherence and persistence requirements"""
        if source == SourceType.NETWORK:
            # Network: check ack and session survival
            if candidate.type == ConditionType.SERVICE_ACK:
                return 1.0 if candidate.details.get('status') == 'success' else 0.5
                
            if candidate.type == ConditionType.CONN_ALIVE:
                duration = candidate.details.get('duration', 0)
                min_duration = self.config.d_min.total_seconds()
                return min(1.0, duration / min_duration)
                
        else:
            # Process: check magnitude and dwell
            if candidate.type == ConditionType.STEP:
                magnitude = abs(candidate.details.get('magnitude', 0))
                if magnitude >= self.config.epsilon_step:
                    return min(1.0, magnitude / (10 * self.config.epsilon_step))
                return 0
                
            if candidate.type == ConditionType.DWELL:
                duration = candidate.details.get('duration', 0)
                min_duration = self.config.d_min.total_seconds()
                return min(1.0, duration / min_duration)
                
        return 0.5  # Default moderate coherence
    
    def _check_context_sanity(self,
                            event: FocalEvent,
                            candidate: Condition) -> float:
        """Soft check for context consistency"""
        # This is simplified - real implementation would check:
        # - Interlocks
        # - Manual mode
        # - Loss of connectivity
        # - Device state consistency
        
        # For now, return high score unless specific issues detected
        return 0.8
    
    def _create_pap_unit(self,
                       event: FocalEvent,
                       preconditions: List[Condition],
                       postcondition: Optional[Condition],
                       source: SourceType) -> Dict[str, Any]:
        """Create PAP unit with matched conditions"""
        # Convert conditions to paper format
        pre = [self._format_condition(c) for c in preconditions]
        post = [self._format_condition(postcondition)] if postcondition else []
        
        # Calculate confidence based on matching quality
        if postcondition:
            base_conf = self._apply_decision_rules(event, postcondition, source)
            # Add corroborating cues bonus
            if len(preconditions) > 1:
                base_conf = min(1.0, base_conf + 0.1)
        else:
            base_conf = 0.3  # Low confidence for unmatched events
            
        # Determine strength
        strength = "strong" if base_conf > 0.7 and postcondition else "tentative"
        
        unit = {
            "id": event.id,
            "source_type": source.value,
            "category": self._categorize_event(event),
            "pre": pre,
            "action": self._format_action(event),
            "post": post,
            "prov": {
                "sources": [source.value],
                "parser": "v2.1.0",
                "matched_at": datetime.utcnow().isoformat()
            },
            "conf": round(base_conf, 2),
            "strength": strength,
            "notes": "No postcondition matched" if not postcondition else ""
        }
        
        # Add raw event data if available
        if event.raw_data:
            unit["prov"][source.value] = event.raw_data
            
        return unit
    
    def _format_condition(self, condition: Condition) -> Dict[str, Any]:
        """Format condition for output"""
        return {
            "type": condition.type.value,
            "t": condition.timestamp.isoformat(),
            **condition.details
        }
    
    def _format_action(self, event: FocalEvent) -> Dict[str, Any]:
        """Format action from focal event"""
        action = {
            "t": event.timestamp.isoformat(),
            **event.semantics
        }
        return action
    
    def _categorize_event(self, event: FocalEvent) -> str:
        """Categorize event based on semantics"""
        if event.source == SourceType.NETWORK:
            op = event.semantics.get('operation', '').lower()
            if 'read' in op:
                return "reconnaissance"
            elif 'write' in op:
                return "state_change"
            else:
                return "session"
        else:
            change = event.semantics.get('change_kind', '').lower()
            if change in ['open', 'close', 'start', 'stop']:
                return "state_change"
            else:
                return "process_anomaly"
    
    def _is_matching_response(self, event_semantics: Dict, response: pd.Series) -> bool:
        """Check if response matches the event"""
        # Simple matching based on service type and endpoints
        event_service = event_semantics.get('operation', '').lower()
        resp_service = str(response.get('service_type', '')).lower()
        
        # Check if services match
        if event_service and resp_service:
            if event_service in resp_service or resp_service in event_service:
                return True
                
        # Check endpoint matching (response should have swapped src/dst)
        event_dst = event_semantics.get('dst')
        resp_src = response.get('src')
        if event_dst and resp_src:
            return event_dst == resp_src
            
        # Default to True for generic responses
        return True
