"""
Confidence Metrics and Analysis Module
Provides statistical analysis and reporting for CPAG confidence scores
"""

from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime
import json


class ConfidenceMetrics:
    """Analyze and report on CPAG confidence metrics"""
    
    def __init__(self):
        self.confidence_thresholds = {
            'very_high': 0.85,
            'high': 0.70,
            'medium': 0.55,
            'low': 0.40,
            'very_low': 0.0
        }
    
    def analyze_graph_confidence(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze confidence distribution across entire graph
        
        Args:
            graph_data: Graph data containing nodes and edges with confidence scores
            
        Returns:
            Comprehensive confidence analysis report
        """
        edges = graph_data.get('edges', [])
        nodes = graph_data.get('nodes', [])
        
        if not edges:
            return {'error': 'No edges found in graph data'}
        
        # Extract confidence scores
        confidences = []
        for edge in edges:
            conf = edge.get('confidence', edge.get('probability', 0.5))
            confidences.append(float(conf))
        
        # Basic statistics
        conf_array = np.array(confidences)
        basic_stats = {
            'total_edges': len(confidences),
            'mean_confidence': float(np.mean(conf_array)),
            'median_confidence': float(np.median(conf_array)),
            'std_confidence': float(np.std(conf_array)),
            'min_confidence': float(np.min(conf_array)),
            'max_confidence': float(np.max(conf_array))
        }
        
        # Confidence distribution
        distribution = self._calculate_confidence_distribution(confidences)
        
        # Quality assessment
        quality_assessment = self._assess_graph_quality(confidences)
        
        # Edge categorization
        edge_categories = self._categorize_edges_by_confidence(edges)
        
        # Relationship analysis
        relationship_analysis = self._analyze_relationships(edges)
        
        # Risk assessment
        risk_assessment = self._assess_attack_path_risks(graph_data, confidences)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'basic_statistics': basic_stats,
            'confidence_distribution': distribution,
            'quality_assessment': quality_assessment,
            'edge_categories': edge_categories,
            'relationship_analysis': relationship_analysis,
            'risk_assessment': risk_assessment,
            'recommendations': self._generate_recommendations(basic_stats, distribution, quality_assessment)
        }
    
    def _calculate_confidence_distribution(self, confidences: List[float]) -> Dict[str, Any]:
        """Calculate confidence score distribution"""
        
        # Histogram bins
        bins = [0.0, 0.4, 0.55, 0.7, 0.85, 1.0]
        bin_labels = ['very_low', 'low', 'medium', 'high', 'very_high']
        
        hist, _ = np.histogram(confidences, bins=bins)
        
        distribution = {}
        for i, label in enumerate(bin_labels):
            count = int(hist[i])
            percentage = (count / len(confidences)) * 100 if confidences else 0
            distribution[label] = {
                'count': count,
                'percentage': round(percentage, 2),
                'range': f"{bins[i]:.2f} - {bins[i+1]:.2f}"
            }
        
        return distribution
    
    def _assess_graph_quality(self, confidences: List[float]) -> Dict[str, Any]:
        """Assess overall graph quality based on confidence scores"""
        
        if not confidences:
            return {'quality_score': 0, 'assessment': 'No data available'}
        
        mean_conf = np.mean(confidences)
        std_conf = np.std(confidences)
        
        # Calculate quality score (0-100)
        # High mean confidence is good, low std deviation is good
        quality_score = (mean_conf * 80) + ((1 - min(std_conf, 1.0)) * 20)
        quality_score = max(0, min(100, quality_score))
        
        # Quality assessment
        if quality_score >= 85:
            assessment = "Excellent"
            description = "High confidence scores with consistent evidence"
        elif quality_score >= 70:
            assessment = "Good"
            description = "Generally reliable with some uncertainty"
        elif quality_score >= 55:
            assessment = "Fair"
            description = "Mixed confidence levels, needs validation"
        elif quality_score >= 40:
            assessment = "Poor"
            description = "Low confidence scores, high uncertainty"
        else:
            assessment = "Very Poor"
            description = "Unreliable analysis, requires manual review"
        
        return {
            'quality_score': round(quality_score, 2),
            'assessment': assessment,
            'description': description,
            'mean_confidence': round(mean_conf, 3),
            'confidence_consistency': round(1 - min(std_conf, 1.0), 3)  # Higher is better
        }
    
    def _categorize_edges_by_confidence(self, edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Categorize edges by confidence levels and properties"""
        
        categories = {
            'high_confidence': [],
            'medium_confidence': [],
            'low_confidence': [],
            'by_relation': defaultdict(list),
            'by_logic_type': defaultdict(list)
        }
        
        for edge in edges:
            conf = edge.get('confidence', edge.get('probability', 0.5))
            relation = edge.get('relation', 'unknown')
            logic_type = edge.get('logic_type', 'unknown')
            
            # Confidence level categorization
            if conf >= 0.7:
                categories['high_confidence'].append(edge)
            elif conf >= 0.5:
                categories['medium_confidence'].append(edge)
            else:
                categories['low_confidence'].append(edge)
            
            # Relation type categorization
            categories['by_relation'][relation].append(conf)
            
            # Logic type categorization
            categories['by_logic_type'][logic_type].append(conf)
        
        # Calculate statistics for each category
        result = {}
        for category, edge_list in categories.items():
            if category.startswith('by_'):
                continue
            result[category] = {
                'count': len(edge_list),
                'percentage': round((len(edge_list) / len(edges)) * 100, 2) if edges else 0
            }
        
        # Relation statistics
        result['relation_statistics'] = {}
        for relation, conf_list in categories['by_relation'].items():
            result['relation_statistics'][relation] = {
                'count': len(conf_list),
                'avg_confidence': round(np.mean(conf_list), 3),
                'min_confidence': round(np.min(conf_list), 3),
                'max_confidence': round(np.max(conf_list), 3)
            }
        
        # Logic type statistics
        result['logic_type_statistics'] = {}
        for logic_type, conf_list in categories['by_logic_type'].items():
            result['logic_type_statistics'][logic_type] = {
                'count': len(conf_list),
                'avg_confidence': round(np.mean(conf_list), 3),
                'min_confidence': round(np.min(conf_list), 3),
                'max_confidence': round(np.max(conf_list), 3)
            }
        
        return result
    
    def _analyze_relationships(self, edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze relationship types and their confidence patterns"""
        
        relation_types = Counter()
        logic_types = Counter() 
        
        for edge in edges:
            relation_types[edge.get('relation', 'unknown')] += 1
            logic_types[edge.get('logic_type', 'unknown')] += 1
        
        return {
            'relation_types': dict(relation_types),
            'logic_types': dict(logic_types),
            'most_common_relation': relation_types.most_common(1)[0] if relation_types else None,
            'most_common_logic': logic_types.most_common(1)[0] if logic_types else None
        }
    
    def _assess_attack_path_risks(self, graph_data: Dict[str, Any], confidences: List[float]) -> Dict[str, Any]:
        """Assess risks based on attack paths and confidence levels"""
        
        edges = graph_data.get('edges', [])
        nodes = graph_data.get('nodes', [])
        
        # Find critical paths (high-confidence chains)
        high_conf_edges = [e for e in edges if e.get('confidence', e.get('probability', 0.5)) >= 0.7]
        
        # Identify high-risk targets
        target_risk = defaultdict(float)
        for edge in edges:
            target = edge.get('target', '')
            conf = edge.get('confidence', edge.get('probability', 0.5))
            target_risk[target] += conf
        
        # Sort by risk level
        high_risk_targets = sorted(target_risk.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calculate path completeness
        path_completeness = len(high_conf_edges) / len(edges) if edges else 0
        
        return {
            'high_confidence_paths': len(high_conf_edges),
            'path_completeness': round(path_completeness, 3),
            'high_risk_targets': [{'target': target, 'risk_score': round(score, 3)} 
                                for target, score in high_risk_targets],
            'overall_risk_level': self._calculate_overall_risk(confidences, path_completeness)
        }
    
    def _calculate_overall_risk(self, confidences: List[float], path_completeness: float) -> str:
        """Calculate overall risk level of the attack graph"""
        
        if not confidences:
            return "Unknown"
        
        avg_conf = np.mean(confidences)
        
        # Risk calculation based on confidence and path completeness
        risk_score = (avg_conf * 0.7) + (path_completeness * 0.3)
        
        if risk_score >= 0.8:
            return "Very High"
        elif risk_score >= 0.65:
            return "High"
        elif risk_score >= 0.5:
            return "Medium"
        elif risk_score >= 0.35:
            return "Low"
        else:
            return "Very Low"
    
    def _generate_recommendations(self, basic_stats: Dict[str, Any], 
                                distribution: Dict[str, Any], 
                                quality: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        
        recommendations = []
        
        # Mean confidence recommendations
        mean_conf = basic_stats.get('mean_confidence', 0.5)
        if mean_conf < 0.5:
            recommendations.append("Consider collecting additional evidence to improve confidence scores")
        elif mean_conf > 0.9:
            recommendations.append("Confidence scores are very high - validate against potential false positives")
        
        # Distribution recommendations
        low_conf_pct = distribution.get('low', {}).get('percentage', 0)
        very_low_pct = distribution.get('very_low', {}).get('percentage', 0)
        
        if (low_conf_pct + very_low_pct) > 40:
            recommendations.append("High percentage of low-confidence edges - review evidence quality")
        
        # Quality recommendations
        quality_score = quality.get('quality_score', 50)
        if quality_score < 60:
            recommendations.append("Graph quality is below acceptable threshold - consider additional data sources")
        
        # Consistency recommendations
        std_conf = basic_stats.get('std_confidence', 0)
        if std_conf > 0.3:
            recommendations.append("High confidence variance detected - review edge calculation consistency")
        
        if not recommendations:
            recommendations.append("Confidence analysis looks good - no major issues detected")
        
        return recommendations
    
    def export_confidence_report(self, analysis: Dict[str, Any], 
                               output_path: str, 
                               format: str = 'json') -> str:
        """Export confidence analysis report"""
        
        if format.lower() == 'json':
            with open(output_path, 'w') as f:
                json.dump(analysis, f, indent=2)
        elif format.lower() == 'csv':
            # Create a simplified CSV for basic statistics
            df = pd.DataFrame([analysis['basic_statistics']])
            df.to_csv(output_path, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return output_path
    
    def compare_confidence_improvements(self, before_analysis: Dict[str, Any], 
                                      after_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Compare confidence metrics before and after improvements"""
        
        before_stats = before_analysis.get('basic_statistics', {})
        after_stats = after_analysis.get('basic_statistics', {})
        
        improvements = {}
        metrics = ['mean_confidence', 'median_confidence', 'min_confidence', 'max_confidence']
        
        for metric in metrics:
            before_val = before_stats.get(metric, 0)
            after_val = after_stats.get(metric, 0)
            improvement = after_val - before_val
            improvement_pct = (improvement / before_val * 100) if before_val > 0 else 0
            
            improvements[metric] = {
                'before': round(before_val, 3),
                'after': round(after_val, 3),
                'change': round(improvement, 3),
                'improvement_percent': round(improvement_pct, 2)
            }
        
        # Quality score comparison
        before_quality = before_analysis.get('quality_assessment', {}).get('quality_score', 0)
        after_quality = after_analysis.get('quality_assessment', {}).get('quality_score', 0)
        quality_improvement = after_quality - before_quality
        
        improvements['overall_quality'] = {
            'before': round(before_quality, 2),
            'after': round(after_quality, 2),
            'improvement': round(quality_improvement, 2)
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'improvements': improvements,
            'summary': self._summarize_improvements(improvements)
        }
    
    def _summarize_improvements(self, improvements: Dict[str, Any]) -> str:
        """Generate a summary of improvements"""
        
        quality_change = improvements.get('overall_quality', {}).get('improvement', 0)
        mean_change = improvements.get('mean_confidence', {}).get('improvement_percent', 0)
        
        if quality_change > 10 and mean_change > 10:
            return "Significant improvement in both quality and confidence scores"
        elif quality_change > 5 or mean_change > 5:
            return "Moderate improvement in confidence metrics"
        elif quality_change > 0 or mean_change > 0:
            return "Minor improvement in confidence scores"
        elif quality_change < -5 or mean_change < -5:
            return "Confidence metrics have declined"
        else:
            return "No significant change in confidence metrics"
