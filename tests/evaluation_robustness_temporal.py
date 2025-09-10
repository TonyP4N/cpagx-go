#!/usr/bin/env python3
"""
CPAG鲁棒性和时序稳定性评估框架
研究CPAG生成对数据扰动、噪声和时序变化的鲁棒性
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import asyncio
import aiohttp
import json
import time
from pathlib import Path
from collections import defaultdict
import logging
from scipy import stats
from sklearn.preprocessing import StandardScaler

# 导入评估函数
import sys
sys.path.append(str(Path(__file__).parent))
from evaluation_optimized import derive_gold_units_optimized
from evaluation_final import (
    unit_similarity, match_units, precision_recall_F1,
    build_graph_from_units
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class RobustnessTemporalEvaluator:
    """鲁棒性和时序稳定性评估器"""
    
    def __init__(self, service_url: str = "http://localhost:8002"):
        self.service_url = service_url
        self.results = {
            'noise_robustness': [],
            'temporal_stability': [],
            'data_perturbation': [],
            'concept_drift': []
        }
    
    def add_noise_to_data(self, df: pd.DataFrame, noise_level: float, 
                         noise_type: str = 'gaussian') -> pd.DataFrame:
        """向数据添加噪声"""
        df_noisy = df.copy()
        
        # 只对数值列添加噪声
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        device_cols = [col for col in numeric_cols 
                      if not any(exclude in col.lower() 
                                for exclude in ['timestamp', 'attack', 'id'])]
        
        for col in device_cols:
            values = df[col].values
            
            if noise_type == 'gaussian':
                # 高斯噪声
                std_val = np.std(values)
                if std_val == 0 or np.isnan(std_val) or np.isinf(std_val):
                    std_val = 1  # 使用默认值
                noise = np.random.normal(0, noise_level * std_val, len(values))
                df_noisy[col] = values + noise
                
            elif noise_type == 'uniform':
                # 均匀噪声
                value_range = values.max() - values.min()
                if value_range == 0 or np.isnan(value_range) or np.isinf(value_range):
                    # 如果范围为0或无效，使用标准差
                    noise_range = noise_level * (np.std(values) if np.std(values) > 0 else 1)
                else:
                    noise_range = noise_level * value_range
                
                # 限制噪声范围避免溢出
                noise_range = min(noise_range, 1e6)
                noise = np.random.uniform(-noise_range/2, noise_range/2, len(values))
                df_noisy[col] = values + noise
                
            elif noise_type == 'salt_pepper':
                # 椒盐噪声
                mask = np.random.random(len(values)) < noise_level
                min_val = values.min()
                max_val = values.max()
                if min_val == max_val:
                    # 如果所有值相同，使用微小扰动
                    min_val = min_val - 0.1
                    max_val = max_val + 0.1
                # 确保数据类型一致
                if df[col].dtype == np.int64:
                    df_noisy.loc[mask, col] = np.random.choice([int(min_val), int(max_val)], 
                                                              size=mask.sum())
                else:
                    df_noisy.loc[mask, col] = np.random.choice([min_val, max_val], 
                                                              size=mask.sum())
        
        return df_noisy
    
    def create_temporal_segments(self, df: pd.DataFrame, 
                               segment_size: int = 1000) -> List[pd.DataFrame]:
        """将数据分割成时间段"""
        segments = []
        n_segments = len(df) // segment_size
        
        for i in range(n_segments):
            start_idx = i * segment_size
            end_idx = (i + 1) * segment_size
            segment = df.iloc[start_idx:end_idx].copy()
            segments.append(segment)
        
        # 添加剩余数据
        if len(df) % segment_size > 0:
            segments.append(df.iloc[n_segments * segment_size:].copy())
        
        return segments
    
    def simulate_concept_drift(self, df: pd.DataFrame, 
                             drift_type: str = 'gradual',
                             drift_magnitude: float = 0.1) -> pd.DataFrame:
        """模拟概念漂移"""
        df_drift = df.copy()
        n_rows = len(df)
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        device_cols = [col for col in numeric_cols 
                      if not any(exclude in col.lower() 
                                for exclude in ['timestamp', 'attack', 'id'])]
        
        if drift_type == 'gradual':
            # 渐变漂移
            for col in device_cols:
                drift = np.linspace(0, drift_magnitude * df[col].std(), n_rows)
                df_drift[col] = df[col] + drift
                
        elif drift_type == 'sudden':
            # 突变漂移
            drift_point = n_rows // 2
            for col in device_cols:
                df_drift.loc[drift_point:, col] = df.loc[drift_point:, col] + \
                                                  drift_magnitude * df[col].std()
                
        elif drift_type == 'recurring':
            # 周期性漂移
            period = n_rows // 4
            for i in range(0, n_rows, period * 2):
                for col in device_cols:
                    df_drift.loc[i:i+period, col] = df.loc[i:i+period, col] + \
                                                    drift_magnitude * df[col].std()
        elif drift_type == 'seasonal':
            # 季节性漂移（正弦波动）
            for col in device_cols:
                seasonal_drift = drift_magnitude * df[col].std() * \
                               np.sin(2 * np.pi * np.arange(n_rows) / (n_rows / 4))
                df_drift[col] = df[col] + seasonal_drift
        
        return df_drift
    
    async def evaluate_noise_robustness(self, session: aiohttp.ClientSession,
                                      file_path: Path,
                                      noise_levels: List[float] = [0.0, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3]):
        """评估对噪声的鲁棒性"""
        logging.info(f"Evaluating noise robustness for {file_path.name}")
        
        # 读取原始数据
        df_original = pd.read_csv(file_path)
        
        # 获取原始CPAG作为基准
        baseline_units = await self._generate_cpag(session, file_path, df_original)
        if not baseline_units:
            logging.error("Failed to generate baseline CPAG")
            return
        
        results = []
        
        for noise_level in noise_levels:
            for noise_type in ['gaussian', 'uniform', 'salt_pepper']:
                logging.info(f"Testing {noise_type} noise at level {noise_level}")
                
                # 添加噪声
                df_noisy = self.add_noise_to_data(df_original, noise_level, noise_type)
                
                # 生成CPAG
                noisy_units = await self._generate_cpag(session, file_path, df_noisy)
                
                if noisy_units:
                    # 计算稳定性指标
                    stability_metrics = self._calculate_stability_metrics(
                        baseline_units, noisy_units
                    )
                    
                    results.append({
                        'file': file_path.name,
                        'noise_level': noise_level,
                        'noise_type': noise_type,
                        'num_units_original': len(baseline_units),
                        'num_units_noisy': len(noisy_units),
                        **stability_metrics
                    })
        
        self.results['noise_robustness'].extend(results)
    
    async def evaluate_temporal_stability(self, session: aiohttp.ClientSession,
                                        file_path: Path,
                                        segment_sizes: List[int] = [200, 500, 1000, 1500, 2000]):
        """评估时序稳定性"""
        logging.info(f"Evaluating temporal stability for {file_path.name}")
        
        df = pd.read_csv(file_path)
        results = []
        
        for segment_size in segment_sizes:
            segments = self.create_temporal_segments(df, segment_size)
            
            if len(segments) < 2:
                continue
            
            segment_units = []
            for i, segment in enumerate(segments):
                logging.info(f"Processing segment {i+1}/{len(segments)} (size={segment_size})")
                
                # 为每个片段生成CPAG
                units = await self._generate_cpag(session, file_path, segment)
                if units:
                    segment_units.append(units)
            
            if len(segment_units) >= 2:
                # 计算片段间的一致性
                consistency_scores = []
                for i in range(len(segment_units) - 1):
                    metrics = self._calculate_stability_metrics(
                        segment_units[i], segment_units[i+1]
                    )
                    consistency_scores.append(metrics['unit_similarity'])
                
                results.append({
                    'file': file_path.name,
                    'segment_size': segment_size,
                    'num_segments': len(segments),
                    'avg_consistency': np.mean(consistency_scores),
                    'std_consistency': np.std(consistency_scores),
                    'min_consistency': np.min(consistency_scores),
                    'max_consistency': np.max(consistency_scores)
                })
        
        self.results['temporal_stability'].extend(results)
    
    async def evaluate_concept_drift(self, session: aiohttp.ClientSession,
                                   file_path: Path):
        """评估对概念漂移的适应性"""
        logging.info(f"Evaluating concept drift adaptation for {file_path.name}")
        
        df = pd.read_csv(file_path)
        results = []
        
        # 获取原始CPAG
        baseline_units = await self._generate_cpag(session, file_path, df)
        if not baseline_units:
            return
        
        for drift_type in ['gradual', 'sudden', 'recurring', 'seasonal']:
            for drift_magnitude in [0.01, 0.05, 0.1, 0.15, 0.2]:
                logging.info(f"Testing {drift_type} drift with magnitude {drift_magnitude}")
                
                # 添加概念漂移
                df_drift = self.simulate_concept_drift(df, drift_type, drift_magnitude)
                
                # 生成CPAG
                drift_units = await self._generate_cpag(session, file_path, df_drift)
                
                if drift_units:
                    # 分析适应性
                    adaptation_metrics = self._analyze_drift_adaptation(
                        baseline_units, drift_units, drift_type
                    )
                    
                    results.append({
                        'file': file_path.name,
                        'drift_type': drift_type,
                        'drift_magnitude': drift_magnitude,
                        **adaptation_metrics
                    })
        
        self.results['concept_drift'].extend(results)
    
    async def _generate_cpag(self, session: aiohttp.ClientSession,
                           file_path: Path,
                           df: pd.DataFrame) -> List[Dict]:
        """生成CPAG单元"""
        try:
            # 保存临时文件
            temp_file = Path(f"temp_{time.time()}.csv")
            df.to_csv(temp_file, index=False)
            
            with open(temp_file, 'rb') as f:
                form_data = aiohttp.FormData()
                form_data.add_field('csv_file', f.read(),
                                  filename=file_path.name,
                                  content_type='text/csv')
                form_data.add_field('device_map', json.dumps({}))
                form_data.add_field('rules', json.dumps([]))
                form_data.add_field('output_format', 'json')
            
            # 删除临时文件
            temp_file.unlink()
            
            # 提交任务
            async with session.post(f"{self.service_url}/cpag/generate", data=form_data) as resp:
                if resp.status != 200:
                    return []
                
                result = await resp.json()
                task_id = result['id']
            
            # 等待完成
            for _ in range(30):
                await asyncio.sleep(2)
                
                async with session.get(f"{self.service_url}/cpag/status/{task_id}") as resp:
                    if resp.status == 200:
                        status_data = await resp.json()
                        if status_data['status'] == 'completed':
                            # 获取结果
                            async with session.get(f"{self.service_url}/cpag/result/{task_id}") as result_resp:
                                result_data = await result_resp.json()
                                return result_data.get('units', [])
                        elif status_data['status'] == 'failed':
                            return []
            
            return []
            
        except Exception as e:
            logging.error(f"Error generating CPAG: {e}")
            return []
    
    def _calculate_stability_metrics(self, units1: List[Dict], 
                                   units2: List[Dict]) -> Dict[str, float]:
        """计算稳定性指标"""
        if not units1 or not units2:
            return {
                'unit_similarity': 0.0,
                'category_stability': 0.0,
                'structural_similarity': 0.0
            }
        
        # 1. 单元相似度
        matches = match_units(units1, units2, similarity_threshold=0.3)
        unit_similarity = len(matches) / max(len(units1), len(units2))
        
        # 2. 类别分布稳定性
        dist1 = self._get_category_distribution(units1)
        dist2 = self._get_category_distribution(units2)
        
        # 使用JS散度衡量分布差异
        category_stability = 1 - self._js_divergence(dist1, dist2)
        
        # 3. 结构相似度
        graph1 = build_graph_from_units(units1)
        graph2 = build_graph_from_units(units2)
        
        # 基于节点和边的Jaccard相似度
        nodes1 = set(graph1.nodes())
        nodes2 = set(graph2.nodes())
        node_similarity = len(nodes1 & nodes2) / len(nodes1 | nodes2) if nodes1 | nodes2 else 0
        
        edges1 = set(graph1.edges())
        edges2 = set(graph2.edges())
        edge_similarity = len(edges1 & edges2) / len(edges1 | edges2) if edges1 | edges2 else 0
        
        structural_similarity = (node_similarity + edge_similarity) / 2
        
        return {
            'unit_similarity': unit_similarity,
            'category_stability': category_stability,
            'structural_similarity': structural_similarity
        }
    
    def _get_category_distribution(self, units: List[Dict]) -> Dict[str, float]:
        """获取类别分布"""
        counts = defaultdict(int)
        for unit in units:
            counts[unit.get('category', 'unknown')] += 1
        
        total = sum(counts.values())
        return {cat: count/total for cat, count in counts.items()}
    
    def _js_divergence(self, p: Dict[str, float], q: Dict[str, float]) -> float:
        """计算Jensen-Shannon散度"""
        # 获取所有类别
        categories = set(p.keys()) | set(q.keys())
        
        # 转换为数组
        p_array = np.array([p.get(cat, 0) for cat in categories])
        q_array = np.array([q.get(cat, 0) for cat in categories])
        
        # 计算平均分布
        m = (p_array + q_array) / 2
        
        # 计算KL散度
        def kl_divergence(a, b):
            return np.sum(a * np.log(a / b + 1e-10))
        
        # JS散度
        js = (kl_divergence(p_array, m) + kl_divergence(q_array, m)) / 2
        
        return min(js, 1.0)  # 归一化到[0,1]
    
    def _analyze_drift_adaptation(self, baseline_units: List[Dict],
                                drift_units: List[Dict],
                                drift_type: str) -> Dict[str, float]:
        """分析对漂移的适应性"""
        # 基本稳定性指标
        stability_metrics = self._calculate_stability_metrics(baseline_units, drift_units)
        
        # 漂移特定指标
        adaptation_metrics = {
            **stability_metrics,
            'unit_count_change': (len(drift_units) - len(baseline_units)) / len(baseline_units),
            'new_units_ratio': self._calculate_new_units_ratio(baseline_units, drift_units),
            'lost_units_ratio': self._calculate_lost_units_ratio(baseline_units, drift_units)
        }
        
        # 根据漂移类型计算适应性分数
        if drift_type == 'gradual':
            # 渐变漂移应该有平滑的变化
            adaptation_score = stability_metrics['unit_similarity'] * 0.6 + \
                             (1 - abs(adaptation_metrics['unit_count_change'])) * 0.4
        elif drift_type == 'sudden':
            # 突变漂移应该能检测到变化
            adaptation_score = adaptation_metrics['new_units_ratio'] * 0.5 + \
                             stability_metrics['category_stability'] * 0.5
        else:  # recurring
            # 周期性漂移应该保持稳定性
            adaptation_score = stability_metrics['structural_similarity'] * 0.7 + \
                             stability_metrics['category_stability'] * 0.3
        
        adaptation_metrics['adaptation_score'] = adaptation_score
        
        return adaptation_metrics
    
    def _calculate_new_units_ratio(self, baseline: List[Dict], 
                                 current: List[Dict]) -> float:
        """计算新单元比例"""
        baseline_ids = {unit['id'] for unit in baseline}
        current_ids = {unit['id'] for unit in current}
        
        new_ids = current_ids - baseline_ids
        return len(new_ids) / len(current_ids) if current_ids else 0
    
    def _calculate_lost_units_ratio(self, baseline: List[Dict], 
                                  current: List[Dict]) -> float:
        """计算丢失单元比例"""
        baseline_ids = {unit['id'] for unit in baseline}
        current_ids = {unit['id'] for unit in current}
        
        lost_ids = baseline_ids - current_ids
        return len(lost_ids) / len(baseline_ids) if baseline_ids else 0
    
    def generate_robustness_report(self):
        """生成鲁棒性报告"""
        print("\n" + "="*60)
        print("ROBUSTNESS AND TEMPORAL STABILITY EVALUATION REPORT")
        print("="*60)
        
        # 1. 噪声鲁棒性分析
        if self.results['noise_robustness']:
            print("\n1. Noise Robustness Analysis:")
            
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            
            # 按噪声类型分组
            for noise_type in noise_df['noise_type'].unique():
                type_df = noise_df[noise_df['noise_type'] == noise_type]
                
                print(f"\n   {noise_type.title()} Noise:")
                
                # 计算稳定性随噪声水平的变化
                stability_by_level = type_df.groupby('noise_level')['unit_similarity'].agg(['mean', 'std'])
                
                for level, row in stability_by_level.iterrows():
                    print(f"     Level {level}: Similarity = {row['mean']:.3f} ± {row['std']:.3f}")
                
                # 计算鲁棒性分数（噪声水平0.1时的相似度）
                robustness_score = type_df[type_df['noise_level'] == 0.1]['unit_similarity'].mean()
                print(f"     Robustness Score (at 0.1 noise): {robustness_score:.3f}")
        
        # 2. 时序稳定性分析
        if self.results['temporal_stability']:
            print("\n2. Temporal Stability Analysis:")
            
            temporal_df = pd.DataFrame(self.results['temporal_stability'])
            
            for _, row in temporal_df.iterrows():
                print(f"\n   Segment Size: {row['segment_size']}")
                print(f"     Average Consistency: {row['avg_consistency']:.3f} ± {row['std_consistency']:.3f}")
                print(f"     Range: [{row['min_consistency']:.3f}, {row['max_consistency']:.3f}]")
        
        # 3. 概念漂移适应性
        if self.results['concept_drift']:
            print("\n3. Concept Drift Adaptation:")
            
            drift_df = pd.DataFrame(self.results['concept_drift'])
            
            # 按漂移类型分组
            for drift_type in drift_df['drift_type'].unique():
                type_df = drift_df[drift_df['drift_type'] == drift_type]
                
                print(f"\n   {drift_type.title()} Drift:")
                
                # 按强度显示适应性
                for magnitude in sorted(type_df['drift_magnitude'].unique()):
                    mag_df = type_df[type_df['drift_magnitude'] == magnitude]
                    avg_score = mag_df['adaptation_score'].mean()
                    print(f"     Magnitude {magnitude}: Adaptation Score = {avg_score:.3f}")
    
    def generate_robustness_plots(self):
        """生成鲁棒性可视化"""
        fig = plt.figure(figsize=(18, 12))
        
        # 1. 噪声鲁棒性曲线
        ax1 = plt.subplot(2, 3, 1)
        if self.results['noise_robustness']:
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            
            for noise_type in noise_df['noise_type'].unique():
                type_df = noise_df[noise_df['noise_type'] == noise_type]
                grouped = type_df.groupby('noise_level')['unit_similarity'].agg(['mean', 'std'])
                
                ax1.errorbar(grouped.index, grouped['mean'], yerr=grouped['std'],
                           marker='o', label=noise_type, capsize=5)
            
            ax1.set_xlabel('Noise Level')
            ax1.set_ylabel('Unit Similarity')
            ax1.set_title('Robustness to Different Noise Types')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
        
        # 2. 类别稳定性热图
        ax2 = plt.subplot(2, 3, 2)
        if self.results['noise_robustness']:
            # 创建热图数据
            pivot_data = noise_df.pivot_table(
                values='category_stability',
                index='noise_type',
                columns='noise_level',
                aggfunc='mean'
            )
            
            sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap='YlOrRd_r', ax=ax2)
            ax2.set_title('Category Distribution Stability')
        
        # 3. 时序一致性
        ax3 = plt.subplot(2, 3, 3)
        if self.results['temporal_stability']:
            temporal_df = pd.DataFrame(self.results['temporal_stability'])
            
            x = temporal_df['segment_size']
            y = temporal_df['avg_consistency']
            yerr = temporal_df['std_consistency']
            
            ax3.errorbar(x, y, yerr=yerr, marker='s', markersize=8, capsize=5)
            ax3.set_xlabel('Segment Size')
            ax3.set_ylabel('Temporal Consistency')
            ax3.set_title('Stability Across Time Segments')
            ax3.grid(True, alpha=0.3)
        
        # 4. 概念漂移适应性
        ax4 = plt.subplot(2, 3, 4)
        if self.results['concept_drift']:
            drift_df = pd.DataFrame(self.results['concept_drift'])
            
            # 分组条形图
            drift_types = drift_df['drift_type'].unique()
            magnitudes = sorted(drift_df['drift_magnitude'].unique())
            
            x = np.arange(len(drift_types))
            width = 0.25
            
            for i, mag in enumerate(magnitudes):
                scores = [drift_df[(drift_df['drift_type'] == dt) & 
                                 (drift_df['drift_magnitude'] == mag)]['adaptation_score'].mean()
                         for dt in drift_types]
                
                ax4.bar(x + i * width, scores, width, label=f'Mag={mag}')
            
            ax4.set_xlabel('Drift Type')
            ax4.set_ylabel('Adaptation Score')
            ax4.set_title('Adaptation to Concept Drift')
            ax4.set_xticks(x + width)
            ax4.set_xticklabels(drift_types)
            ax4.legend()
        
        # 5. 综合鲁棒性评分
        ax5 = plt.subplot(2, 3, 5)
        
        robustness_scores = {}
        
        # 噪声鲁棒性评分
        if self.results['noise_robustness']:
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            # 使用噪声水平0.1的平均相似度作为评分
            noise_score = noise_df[noise_df['noise_level'] == 0.1]['unit_similarity'].mean()
            robustness_scores['Noise'] = noise_score
        
        # 时序稳定性评分
        if self.results['temporal_stability']:
            temporal_df = pd.DataFrame(self.results['temporal_stability'])
            temporal_score = temporal_df['avg_consistency'].mean()
            robustness_scores['Temporal'] = temporal_score
        
        # 漂移适应性评分
        if self.results['concept_drift']:
            drift_df = pd.DataFrame(self.results['concept_drift'])
            drift_score = drift_df['adaptation_score'].mean()
            robustness_scores['Drift'] = drift_score
        
        if robustness_scores:
            categories = list(robustness_scores.keys())
            scores = list(robustness_scores.values())
            
            bars = ax5.bar(categories, scores, color=['blue', 'green', 'orange'])
            ax5.set_ylim(0, 1.1)
            ax5.set_ylabel('Robustness Score')
            ax5.set_title('Overall Robustness Assessment')
            
            # 添加数值标签
            for bar, score in zip(bars, scores):
                height = bar.get_height()
                ax5.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                        f'{score:.3f}', ha='center', va='bottom')
            
            # 添加总体评分
            overall_score = np.mean(scores)
            ax5.axhline(y=overall_score, color='red', linestyle='--', 
                       label=f'Overall: {overall_score:.3f}')
            ax5.legend()
        
        # 6. 单元数量变化分析
        ax6 = plt.subplot(2, 3, 6)
        if self.results['noise_robustness']:
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            
            # 计算单元数量变化比例
            noise_df['unit_change_ratio'] = (noise_df['num_units_noisy'] - 
                                            noise_df['num_units_original']) / \
                                           noise_df['num_units_original']
            
            # 箱线图
            noise_df.boxplot(column='unit_change_ratio', by='noise_level', ax=ax6)
            ax6.set_xlabel('Noise Level')
            ax6.set_ylabel('Unit Count Change Ratio')
            ax6.set_title('Impact of Noise on Unit Generation')
            plt.suptitle('')  # 移除自动生成的标题
        
        plt.tight_layout()
        plt.savefig('robustness_temporal_evaluation.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        logging.info("Robustness plots saved to robustness_temporal_evaluation.png")


async def main():
    """主函数"""
    print("CPAG Robustness and Temporal Stability Evaluation")
    print("=" * 60)
    
    evaluator = RobustnessTemporalEvaluator()
    
    # 获取测试文件
    test_files = list(Path("data/csv").glob("*.csv"))[:5]  # 使用前5个文件进行测试
    
    if not test_files:
        print("No test files found!")
        return
    
    async with aiohttp.ClientSession() as session:
        # 检查服务健康
        async with session.get(f"{evaluator.service_url}/health") as resp:
            if resp.status != 200:
                print("Service is not healthy!")
                return
        
        print(f"Testing {len(test_files)} files...")
        
        for file_path in test_files:
            print(f"\n{'='*40}")
            print(f"Processing: {file_path.name}")
            print('='*40)
            
            # 1. 噪声鲁棒性测试
            await evaluator.evaluate_noise_robustness(session, file_path)
            
            # 2. 时序稳定性测试
            await evaluator.evaluate_temporal_stability(session, file_path)
            
            # 3. 概念漂移测试
            await evaluator.evaluate_concept_drift(session, file_path)
    
    # 生成报告
    evaluator.generate_robustness_report()
    
    # 生成可视化
    evaluator.generate_robustness_plots()
    
    print("\n\nEvaluation complete!")
    print("Results saved to: robustness_temporal_evaluation.png")


if __name__ == "__main__":
    asyncio.run(main())
