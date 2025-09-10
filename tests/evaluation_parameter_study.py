#!/usr/bin/env python3
"""
CPAG参数研究评估框架
研究不同参数配置对CPAG生成质量和数量的影响
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any
import asyncio
import aiohttp
import json
import time
from pathlib import Path
from itertools import product
import logging
from collections import defaultdict
from datetime import datetime

# 导入评估函数
import sys
sys.path.append(str(Path(__file__).parent))
from evaluation_optimized import derive_gold_units_optimized, calculate_weighted_metrics
from evaluation_final import (
    unit_similarity, match_units, precision_recall_F1,
    build_graph_from_units, compute_path_coverage,
    compute_graph_edit_distance
)
from evaluation_report_generator import EvaluationReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ParameterStudyEvaluator:
    """参数研究评估器"""
    
    def __init__(self, service_url: str = "http://localhost:8002"):
        self.service_url = service_url
        self.results = []
        
        # Create output directory
        self.output_dir = Path("evaluation_results/parameter_study")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_generator = EvaluationReportGenerator(str(self.output_dir))
        
    def get_parameter_grid(self) -> Dict[str, List[Any]]:
        """定义参数网格用于研究"""
        return {
            # 异常检测阈值参数
            'anomaly_threshold': [2.0, 2.5, 3.0, 3.5, 4.0],  # 标准差倍数
            
            # 状态转换阈值
            'state_transition_min_count': [5, 10, 15, 20, 30],  # 最小转换次数
            
            # 单元生成策略
            'unit_generation_strategy': ['conservative', 'balanced', 'aggressive'],
            
            # 置信度阈值
            'confidence_threshold': [0.5, 0.6, 0.7, 0.8, 0.9],
            
            # 时间窗口参数（用于时序分析）
            'time_window_size': [100, 300, 500, 700, 1000],  # 数据点数
            
            # 相关性阈值（用于设备交互）
            'correlation_threshold': [0.6, 0.7, 0.8, 0.85, 0.9]
        }
    
    async def evaluate_single_configuration(self, 
                                          session: aiohttp.ClientSession,
                                          file_path: Path,
                                          params: Dict[str, Any]) -> Dict[str, Any]:
        """评估单个参数配置"""
        start_time = time.time()
        
        try:
            # 准备请求
            with open(file_path, 'rb') as f:
                form_data = aiohttp.FormData()
                form_data.add_field('csv_file', f.read(),
                                  filename=file_path.name,
                                  content_type='text/csv')
                
                # 添加参数配置
                form_data.add_field('device_map', json.dumps({}))
                form_data.add_field('rules', json.dumps([]))
                form_data.add_field('output_format', 'json')
                
                # 添加研究参数（通过自定义字段传递）
                form_data.add_field('custom_params', json.dumps(params))
            
            # 提交任务
            async with session.post(f"{self.service_url}/cpag/generate", data=form_data) as resp:
                if resp.status != 200:
                    return {'error': f'Failed to submit: {resp.status}'}
                
                result = await resp.json()
                task_id = result['id']
            
            # 等待完成
            max_attempts = 30
            for attempt in range(max_attempts):
                await asyncio.sleep(2)
                
                async with session.get(f"{self.service_url}/cpag/status/{task_id}") as resp:
                    if resp.status == 404:
                        await asyncio.sleep(3)
                        continue
                    
                    status_data = await resp.json()
                    if status_data['status'] == 'completed':
                        # 获取结果
                        async with session.get(f"{self.service_url}/cpag/result/{task_id}") as result_resp:
                            result_data = await result_resp.json()
                            cpag_units = result_data.get('units', [])
                            
                            generation_time = time.time() - start_time
                            
                            # 评估质量
                            df = pd.read_csv(file_path)
                            gold_units = derive_gold_units_optimized(df, cpag_units)
                            
                            metrics = self._calculate_metrics(gold_units, cpag_units)
                            
                            return {
                                'params': params,
                                'num_units': len(cpag_units),
                                'num_gold_units': len(gold_units),
                                'generation_time': generation_time,
                                'metrics': metrics,
                                'unit_distribution': self._analyze_unit_distribution(cpag_units)
                            }
                    
                    elif status_data['status'] == 'failed':
                        return {'error': 'Task failed'}
            
            return {'error': 'Task timeout'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_metrics(self, gold_units: List[Dict], pred_units: List[Dict]) -> Dict[str, float]:
        """计算评估指标"""
        if not gold_units:
            return {}
        
        # 匹配单元
        matches = match_units(gold_units, pred_units, similarity_threshold=0.3)
        
        # 传统指标
        prec, rec, f1, tp, fp, fn = precision_recall_F1(gold_units, pred_units, matches)
        
        # 加权指标
        weighted_metrics = calculate_weighted_metrics(gold_units, pred_units, matches)
        
        # 构建图
        gold_graph = build_graph_from_units(gold_units)
        pred_graph = build_graph_from_units(pred_units)
        
        # 图编辑距离
        ged = compute_graph_edit_distance(gold_graph, pred_graph)
        
        return {
            'precision': prec,
            'recall': rec,
            'f1_score': f1,
            'weighted_f1': weighted_metrics['f1_score'],
            'true_positives': tp,
            'false_positives': fp,
            'false_negatives': fn,
            'graph_edit_distance': ged,
            'graph_nodes': pred_graph.number_of_nodes(),
            'graph_edges': pred_graph.number_of_edges()
        }
    
    def _analyze_unit_distribution(self, units: List[Dict]) -> Dict[str, int]:
        """分析单元类型分布"""
        distribution = defaultdict(int)
        for unit in units:
            category = unit.get('category', 'unknown')
            distribution[category] += 1
        return dict(distribution)
    
    async def run_parameter_study(self, test_files: List[Path], sample_size: int = 30):
        """运行参数研究"""
        param_grid = self.get_parameter_grid()
        
        # 生成参数组合（采样以减少计算量）
        all_params = list(self._generate_parameter_combinations(param_grid))
        
        # 随机采样
        import random
        random.seed(42)
        sampled_params = random.sample(all_params, min(sample_size, len(all_params)))
        
        logging.info(f"Testing {len(sampled_params)} parameter combinations on {len(test_files)} files")
        
        async with aiohttp.ClientSession() as session:
            # 检查服务健康
            async with session.get(f"{self.service_url}/health") as resp:
                if resp.status != 200:
                    logging.error("Service is not healthy!")
                    return
            
            # 运行实验
            total_experiments = len(sampled_params) * len(test_files)
            completed = 0
            
            for params in sampled_params:
                for file_path in test_files:
                    logging.info(f"Evaluating {file_path.name} with params: {params}")
                    
                    result = await self.evaluate_single_configuration(session, file_path, params)
                    
                    if 'error' not in result:
                        result['file'] = file_path.name
                        self.results.append(result)
                    
                    completed += 1
                    logging.info(f"Progress: {completed}/{total_experiments} ({completed/total_experiments*100:.1f}%)")
        
        # 分析结果
        self.analyze_results()
    
    def _generate_parameter_combinations(self, param_grid: Dict[str, List[Any]]):
        """生成参数组合"""
        keys = list(param_grid.keys())
        values = [param_grid[k] for k in keys]
        
        for combination in product(*values):
            yield dict(zip(keys, combination))
    
    def analyze_results(self):
        """分析实验结果"""
        if not self.results:
            logging.warning("No results to analyze")
            return
        
        # 转换为DataFrame
        df = pd.DataFrame(self.results)
        
        # 展开参数和指标
        params_df = pd.json_normalize(df['params'])
        metrics_df = pd.json_normalize(df['metrics'])
        
        analysis_df = pd.concat([df[['file', 'num_units', 'generation_time']], 
                                params_df, metrics_df], axis=1)
        
        # 保存原始数据
        csv_path = self.output_dir / 'parameter_study_results.csv'
        analysis_df.to_csv(csv_path, index=False)
        logging.info(f"Results saved to {csv_path}")
        
        # 生成分析报告
        self.generate_analysis_report(analysis_df)
        
        # 生成可视化
        self.generate_visualizations(analysis_df)
        
        # 生成增强的可视化
        try:
            from enhanced_visualization import create_enhanced_visualizations
            create_enhanced_visualizations(str(self.output_dir / 'parameter_study_results.csv'))
            logging.info("Enhanced visualization saved")
        except Exception as e:
            logging.warning(f"Could not generate enhanced visualization: {e}")
        
        # Generate comprehensive report
        self.generate_comprehensive_report(analysis_df)
    
    def generate_analysis_report(self, df: pd.DataFrame):
        """生成分析报告"""
        print("\n" + "="*60)
        print("PARAMETER STUDY ANALYSIS REPORT")
        print("="*60)
        
        # 1. 最佳参数配置（基于F1分数）
        best_config = df.loc[df['f1_score'].idxmax()]
        print("\n1. Best Configuration (by F1 Score):")
        print(f"   F1 Score: {best_config['f1_score']:.3f}")
        print(f"   Weighted F1: {best_config['weighted_f1']:.3f}")
        print(f"   Number of Units: {best_config['num_units']}")
        print(f"   Parameters:")
        for param in ['anomaly_threshold', 'state_transition_min_count', 
                     'unit_generation_strategy', 'confidence_threshold']:
            if param in best_config:
                print(f"     {param}: {best_config[param]}")
        
        # 2. 参数影响分析
        print("\n2. Parameter Impact Analysis:")
        
        # 对每个参数计算其对指标的影响
        param_cols = ['anomaly_threshold', 'state_transition_min_count', 
                     'confidence_threshold', 'correlation_threshold']
        
        for param in param_cols:
            if param in df.columns:
                # 计算相关性
                corr_f1 = df[param].corr(df['f1_score'])
                corr_units = df[param].corr(df['num_units'])
                
                print(f"\n   {param}:")
                print(f"     Correlation with F1 Score: {corr_f1:.3f}")
                print(f"     Correlation with Unit Count: {corr_units:.3f}")
                
                # 最优值
                optimal_df = df.groupby(param)['f1_score'].mean()
                optimal_value = optimal_df.idxmax()
                print(f"     Optimal Value: {optimal_value} (avg F1: {optimal_df[optimal_value]:.3f})")
        
        # 3. 质量-数量权衡分析
        print("\n3. Quality-Quantity Trade-off:")
        
        # 计算效率指标：F1分数 / 单元数量
        df['efficiency'] = df['f1_score'] / (df['num_units'] + 1)  # +1避免除零
        
        best_efficiency = df.loc[df['efficiency'].idxmax()]
        print(f"   Best Efficiency Configuration:")
        print(f"     F1 Score: {best_efficiency['f1_score']:.3f}")
        print(f"     Unit Count: {best_efficiency['num_units']}")
        print(f"     Efficiency: {best_efficiency['efficiency']:.4f}")
        
        # 4. 策略分析
        if 'unit_generation_strategy' in df.columns:
            print("\n4. Strategy Analysis:")
            strategy_stats = df.groupby('unit_generation_strategy').agg({
                'f1_score': ['mean', 'std'],
                'num_units': ['mean', 'std'],
                'generation_time': 'mean'
            })
            print(strategy_stats)
    
    def generate_visualizations(self, df: pd.DataFrame):
        """生成可视化图表"""
        # 设置样式
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
        
        # 创建图表
        fig = plt.figure(figsize=(20, 16))
        
        # 1. 参数对F1分数的影响
        ax1 = plt.subplot(3, 3, 1)
        if 'anomaly_threshold' in df.columns:
            df.boxplot(column='f1_score', by='anomaly_threshold', ax=ax1)
            ax1.set_title('F1 Score vs Anomaly Threshold')
            ax1.set_xlabel('Anomaly Threshold (σ)')
            ax1.set_ylabel('F1 Score')
        
        # 2. 参数对单元数量的影响
        ax2 = plt.subplot(3, 3, 2)
        if 'state_transition_min_count' in df.columns:
            df.boxplot(column='num_units', by='state_transition_min_count', ax=ax2)
            ax2.set_title('Unit Count vs State Transition Threshold')
            ax2.set_xlabel('Min Transition Count')
            ax2.set_ylabel('Number of Units')
        
        # 3. 质量-数量散点图
        ax3 = plt.subplot(3, 3, 3)
        scatter = ax3.scatter(df['num_units'], df['f1_score'], 
                             c=df['anomaly_threshold'] if 'anomaly_threshold' in df.columns else 'blue',
                             alpha=0.6, s=50)
        ax3.set_xlabel('Number of Units')
        ax3.set_ylabel('F1 Score')
        ax3.set_title('Quality vs Quantity Trade-off')
        if 'anomaly_threshold' in df.columns:
            plt.colorbar(scatter, ax=ax3, label='Anomaly Threshold')
        
        # 4. 策略比较
        ax4 = plt.subplot(3, 3, 4)
        if 'unit_generation_strategy' in df.columns:
            strategies = df['unit_generation_strategy'].unique()
            x_pos = np.arange(len(strategies))
            
            f1_means = [df[df['unit_generation_strategy'] == s]['f1_score'].mean() for s in strategies]
            f1_stds = [df[df['unit_generation_strategy'] == s]['f1_score'].std() for s in strategies]
            
            ax4.bar(x_pos, f1_means, yerr=f1_stds, capsize=10, alpha=0.7)
            ax4.set_xticks(x_pos)
            ax4.set_xticklabels(strategies)
            ax4.set_ylabel('F1 Score')
            ax4.set_title('Performance by Generation Strategy')
        
        # 5. 参数热图
        ax5 = plt.subplot(3, 3, 5)
        param_cols = ['anomaly_threshold', 'state_transition_min_count', 
                     'confidence_threshold', 'correlation_threshold']
        metric_cols = ['f1_score', 'weighted_f1', 'precision', 'recall']
        
        # 计算相关性矩阵
        corr_data = []
        for param in param_cols:
            if param in df.columns:
                row = []
                for metric in metric_cols:
                    if metric in df.columns:
                        corr = df[param].corr(df[metric])
                        row.append(corr)
                if row:
                    corr_data.append(row)
        
        if corr_data:
            sns.heatmap(corr_data, 
                       xticklabels=[m for m in metric_cols if m in df.columns],
                       yticklabels=[p for p in param_cols if p in df.columns],
                       annot=True, fmt='.3f', cmap='coolwarm', center=0,
                       ax=ax5)
            ax5.set_title('Parameter-Metric Correlation Heatmap')
        
        # 6. 时间效率分析
        ax6 = plt.subplot(3, 3, 6)
        ax6.scatter(df['num_units'], df['generation_time'], alpha=0.6)
        ax6.set_xlabel('Number of Units')
        ax6.set_ylabel('Generation Time (s)')
        ax6.set_title('Generation Time vs Unit Count')
        
        # 添加趋势线
        z = np.polyfit(df['num_units'], df['generation_time'], 1)
        p = np.poly1d(z)
        ax6.plot(sorted(df['num_units']), p(sorted(df['num_units'])), 
                "r--", alpha=0.8, label=f'Trend: {z[0]:.4f}s/unit')
        ax6.legend()
        
        # 7. 单元类型分布（聚合所有实验）
        ax7 = plt.subplot(3, 3, 7)
        all_distributions = defaultdict(int)
        for _, row in df.iterrows():
            if 'unit_distribution' in row and isinstance(row['unit_distribution'], dict):
                for cat, count in row['unit_distribution'].items():
                    all_distributions[cat] += count
        
        if all_distributions:
            categories = list(all_distributions.keys())
            counts = list(all_distributions.values())
            
            ax7.bar(categories, counts, alpha=0.7)
            ax7.set_xlabel('Unit Category')
            ax7.set_ylabel('Total Count')
            ax7.set_title('Overall Unit Type Distribution')
            ax7.tick_params(axis='x', rotation=45)
        
        # 8. 效率分析
        ax8 = plt.subplot(3, 3, 8)
        if 'efficiency' in df.columns:
            df['efficiency_rank'] = df['efficiency'].rank(ascending=False)
            top_10 = df.nsmallest(10, 'efficiency_rank')
            
            ax8.scatter(top_10['num_units'], top_10['f1_score'], s=100, alpha=0.8, c='red', label='Top 10')
            ax8.scatter(df['num_units'], df['f1_score'], alpha=0.3, s=30, c='blue', label='All')
            
            # 标注最佳点
            best = df.loc[df['efficiency'].idxmax()]
            ax8.annotate('Best\nEfficiency', 
                        xy=(best['num_units'], best['f1_score']),
                        xytext=(best['num_units'] + 10, best['f1_score'] - 0.05),
                        arrowprops=dict(arrowstyle='->'))
            
            ax8.set_xlabel('Number of Units')
            ax8.set_ylabel('F1 Score')
            ax8.set_title('Efficiency Analysis (F1/Units)')
            ax8.legend()
        
        # 9. 参数交互效应
        ax9 = plt.subplot(3, 3, 9)
        if 'anomaly_threshold' in df.columns and 'confidence_threshold' in df.columns:
            pivot_data = df.pivot_table(values='f1_score', 
                                       index='anomaly_threshold',
                                       columns='confidence_threshold',
                                       aggfunc='mean')
            
            sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap='viridis', ax=ax9)
            ax9.set_title('F1 Score: Anomaly vs Confidence Threshold')
        
        plt.tight_layout()
        output_path = self.output_dir / 'parameter_study_analysis.png'
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logging.info("Visualizations saved to parameter_study_analysis.png")
        
        # 生成额外的详细图表
        self.generate_detailed_plots(df)
        
        # 生成独立的图表
        self.generate_individual_plots(df)
    
    def generate_detailed_plots(self, df: pd.DataFrame):
        """生成更详细的分析图表"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. 参数重要性（基于随机森林）
        try:
            from sklearn.ensemble import RandomForestRegressor
            
            param_cols = [col for col in df.columns if col in 
                         ['anomaly_threshold', 'state_transition_min_count', 
                          'confidence_threshold', 'correlation_threshold']]
            
            if param_cols and 'f1_score' in df.columns:
                X = df[param_cols].fillna(0)
                y = df['f1_score']
                
                rf = RandomForestRegressor(n_estimators=100, random_state=42)
                rf.fit(X, y)
                
                importance = pd.DataFrame({
                    'parameter': param_cols,
                    'importance': rf.feature_importances_
                }).sort_values('importance', ascending=False)
                
                ax = axes[0, 0]
                ax.barh(importance['parameter'], importance['importance'])
                ax.set_xlabel('Feature Importance')
                ax.set_title('Parameter Importance for F1 Score')
        except ImportError:
            axes[0, 0].text(0.5, 0.5, 'sklearn not available', 
                           ha='center', va='center')
        
        # 2. 最优参数区域
        ax = axes[0, 1]
        if 'anomaly_threshold' in df.columns and 'state_transition_min_count' in df.columns:
            # 创建等高线图
            xi = np.linspace(df['anomaly_threshold'].min(), df['anomaly_threshold'].max(), 50)
            yi = np.linspace(df['state_transition_min_count'].min(), 
                           df['state_transition_min_count'].max(), 50)
            
            from scipy.interpolate import griddata
            # 使用linear插值避免边缘缺失，并设置填充值
            zi = griddata((df['anomaly_threshold'], df['state_transition_min_count']), 
                         df['f1_score'], (xi[None,:], yi[:,None]), 
                         method='linear', fill_value=df['f1_score'].mean())
            
            contour = ax.contourf(xi, yi, zi, levels=15, cmap='viridis', alpha=0.8)
            plt.colorbar(contour, ax=ax, label='F1 Score')
            
            # 标记实际数据点
            ax.scatter(df['anomaly_threshold'], df['state_transition_min_count'], 
                      c='red', s=30, alpha=0.5, edgecolors='white', linewidth=0.5)
            
            ax.set_xlabel('Anomaly Threshold')
            ax.set_ylabel('State Transition Min Count')
            ax.set_title('F1 Score Landscape')
            ax.grid(True, alpha=0.3)
        
        # 3. 收敛分析
        ax = axes[1, 0]
        if len(df) > 10:
            # 计算累计平均F1分数
            df_sorted = df.sort_index()
            cumulative_mean = df_sorted['f1_score'].expanding().mean()
            
            ax.plot(cumulative_mean.index, cumulative_mean.values, 'b-', linewidth=2)
            ax.fill_between(cumulative_mean.index, 
                          cumulative_mean - df_sorted['f1_score'].expanding().std(),
                          cumulative_mean + df_sorted['f1_score'].expanding().std(),
                          alpha=0.3)
            
            ax.set_xlabel('Experiment Number')
            ax.set_ylabel('Cumulative Mean F1 Score')
            ax.set_title('Convergence Analysis')
            ax.grid(True, alpha=0.3)
        
        # 4. 参数敏感性分析
        ax = axes[1, 1]
        sensitivity_data = []
        
        for param in ['anomaly_threshold', 'confidence_threshold', 'correlation_threshold']:
            if param in df.columns:
                # 计算参数变化对F1的影响
                param_range = df[param].max() - df[param].min()
                f1_range = df.groupby(param)['f1_score'].mean().max() - \
                          df.groupby(param)['f1_score'].mean().min()
                
                if param_range > 0:
                    sensitivity = f1_range / param_range
                    sensitivity_data.append({
                        'parameter': param,
                        'sensitivity': sensitivity,
                        'f1_range': f1_range
                    })
        
        if sensitivity_data:
            sens_df = pd.DataFrame(sensitivity_data)
            bars = ax.bar(sens_df['parameter'], sens_df['sensitivity'])
            ax.set_ylabel('Sensitivity (ΔF1/ΔParam)')
            ax.set_title('Parameter Sensitivity Analysis')
            ax.tick_params(axis='x', rotation=45)
            
            # 添加数值标签
            for bar, f1_range in zip(bars, sens_df['f1_range']):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'ΔF1={f1_range:.3f}',
                       ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        output_path = self.output_dir / 'parameter_study_detailed.png'
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logging.info("Detailed analysis saved to parameter_study_detailed.png")
    
    def generate_individual_plots(self, df: pd.DataFrame):
        """生成独立的参数研究图表"""
        # 创建独立图表目录
        individual_dir = self.output_dir / 'individual_plots'
        individual_dir.mkdir(exist_ok=True)
        
        # 1. 参数对F1分数的影响
        if 'anomaly_threshold' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='f1_score', by='anomaly_threshold')
            plt.title('F1 Score vs Anomaly Threshold')
            plt.xlabel('Anomaly Threshold (σ)')
            plt.ylabel('F1 Score')
            plt.suptitle('')  # Remove default suptitle
            plt.tight_layout()
            plt.savefig(individual_dir / 'f1_vs_anomaly_threshold.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 2. 参数对单元数量的影响
        if 'state_transition_min_count' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='num_units', by='state_transition_min_count')
            plt.title('Unit Count vs State Transition Threshold')
            plt.xlabel('Min Transition Count')
            plt.ylabel('Number of Units')
            plt.suptitle('')
            plt.tight_layout()
            plt.savefig(individual_dir / 'units_vs_transition_threshold.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 3. 质量-数量散点图
        plt.figure(figsize=(10, 8))
        scatter = plt.scatter(df['num_units'], df['f1_score'], 
                             c=df['anomaly_threshold'] if 'anomaly_threshold' in df.columns else 'blue',
                             alpha=0.6, s=50)
        plt.xlabel('Number of Units')
        plt.ylabel('F1 Score')
        plt.title('Quality vs Quantity Trade-off')
        if 'anomaly_threshold' in df.columns:
            plt.colorbar(scatter, label='Anomaly Threshold')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(individual_dir / 'quality_vs_quantity.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        # 4. 策略比较
        if 'unit_generation_strategy' in df.columns:
            plt.figure(figsize=(10, 6))
            strategies = df['unit_generation_strategy'].unique()
            x_pos = np.arange(len(strategies))
            
            f1_means = [df[df['unit_generation_strategy'] == s]['f1_score'].mean() for s in strategies]
            f1_stds = [df[df['unit_generation_strategy'] == s]['f1_score'].std() for s in strategies]
            
            plt.bar(x_pos, f1_means, yerr=f1_stds, capsize=5, alpha=0.8)
            plt.xticks(x_pos, strategies, rotation=45, ha='right')
            plt.ylabel('F1 Score')
            plt.title('Performance by Unit Generation Strategy')
            plt.grid(True, alpha=0.3, axis='y')
            plt.tight_layout()
            plt.savefig(individual_dir / 'strategy_comparison.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 5. 参数热图
        plt.figure(figsize=(10, 8))
        param_cols = ['anomaly_threshold', 'state_transition_min_count', 
                     'confidence_threshold', 'correlation_threshold']
        metric_cols = ['f1_score', 'weighted_f1', 'precision', 'recall']
        
        # 计算相关性矩阵
        available_params = [col for col in param_cols if col in df.columns]
        available_metrics = [col for col in metric_cols if col in df.columns]
        
        if available_params and available_metrics:
            subset_df = df[available_params + available_metrics].copy()
            for col in available_params:
                if subset_df[col].dtype == 'object':
                    subset_df[col] = pd.Categorical(subset_df[col]).codes
            
            corr_matrix = subset_df.corr()
            param_metric_corr = corr_matrix.loc[available_params, available_metrics]
            
            sns.heatmap(param_metric_corr, annot=True, fmt='.3f', cmap='coolwarm',
                       center=0, vmin=-1, vmax=1)
            plt.title('Parameter-Metric Correlation Heatmap')
            plt.tight_layout()
            plt.savefig(individual_dir / 'parameter_correlation_heatmap.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 6. 时间效率分析
        plt.figure(figsize=(10, 6))
        plt.scatter(df['num_units'], df['generation_time'], alpha=0.6)
        plt.xlabel('Number of Units')
        plt.ylabel('Generation Time (s)')
        plt.title('Generation Time vs Unit Count')
        
        # 添加趋势线
        z = np.polyfit(df['num_units'], df['generation_time'], 1)
        p = np.poly1d(z)
        plt.plot(df['num_units'].sort_values(), p(df['num_units'].sort_values()), 
                "r--", alpha=0.8, label=f'Trend: y={z[0]:.4f}x+{z[1]:.2f}')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(individual_dir / 'time_efficiency.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        # 7. 单元类型分布
        plt.figure(figsize=(12, 6))
        all_distributions = defaultdict(int)
        for _, row in df.iterrows():
            if 'unit_distribution' in row and isinstance(row['unit_distribution'], dict):
                for cat, count in row['unit_distribution'].items():
                    all_distributions[cat] += count
        
        if all_distributions:
            categories = list(all_distributions.keys())
            counts = list(all_distributions.values())
            
            plt.bar(categories, counts, alpha=0.8)
            plt.xlabel('Unit Category')
            plt.ylabel('Total Count')
            plt.title('Aggregated Unit Type Distribution')
            plt.xticks(rotation=45, ha='right')
            plt.grid(True, alpha=0.3, axis='y')
            plt.tight_layout()
            plt.savefig(individual_dir / 'unit_type_distribution.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 8. 效率分析
        if 'efficiency' in df.columns:
            plt.figure(figsize=(10, 8))
            df['efficiency_rank'] = df['efficiency'].rank(ascending=False)
            top_10 = df.nsmallest(10, 'efficiency_rank')
            
            plt.scatter(top_10['num_units'], top_10['f1_score'], s=100, alpha=0.8, c='red', label='Top 10')
            plt.scatter(df['num_units'], df['f1_score'], s=50, alpha=0.4, c='gray', label='All')
            
            for idx, row in top_10.iterrows():
                plt.annotate(f"Rank {int(row['efficiency_rank'])}", 
                           (row['num_units'], row['f1_score']),
                           xytext=(5, 5), textcoords='offset points', fontsize=8)
            
            plt.xlabel('Number of Units')
            plt.ylabel('F1 Score')
            plt.title('Top 10 Most Efficient Configurations')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(individual_dir / 'efficiency_analysis.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 9. 参数交互效应
        if 'anomaly_threshold' in df.columns and 'confidence_threshold' in df.columns:
            plt.figure(figsize=(10, 8))
            pivot_data = df.pivot_table(values='f1_score', 
                                       index='anomaly_threshold',
                                       columns='confidence_threshold',
                                       aggfunc='mean')
            
            if not pivot_data.empty:
                sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap='YlOrRd')
                plt.title('Parameter Interaction: Anomaly vs Confidence Threshold')
                plt.xlabel('Confidence Threshold')
                plt.ylabel('Anomaly Threshold')
                plt.tight_layout()
                plt.savefig(individual_dir / 'parameter_interaction.png', dpi=150, bbox_inches='tight')
                plt.close()
        
        logging.info(f"Individual plots saved to {individual_dir}")
    
    def generate_comprehensive_report(self, df: pd.DataFrame):
        """生成综合评估报告"""
        # Calculate summary statistics
        summary = {
            'total_experiments': len(df),
            'total_files': df['file'].nunique() if 'file' in df else 1,
            'parameter_combinations': len(df.groupby(['anomaly_threshold', 'state_transition_min_count', 
                                                     'unit_generation_strategy', 'confidence_threshold'])),
            'avg_f1_score': df['f1_score'].mean(),
            'best_f1_score': df['f1_score'].max(),
            'avg_generation_time': df['generation_time'].mean()
        }
        
        # Find best configuration
        best_idx = df['f1_score'].idxmax()
        best_config = df.iloc[best_idx]
        
        # Prepare detailed results
        detailed_results = {
            'key_metrics': [
                {'name': 'Average F1 Score', 'value': f"{summary['avg_f1_score']:.4f}", 
                 'description': 'Mean F1 score across all parameter combinations'},
                {'name': 'Best F1 Score', 'value': f"{summary['best_f1_score']:.4f}", 
                 'description': 'Highest F1 score achieved'},
                {'name': 'Total Experiments', 'value': str(summary['total_experiments']), 
                 'description': 'Number of parameter combinations tested'},
                {'name': 'Parameter Impact', 'value': f"{self._calculate_parameter_impact(df):.4f}", 
                 'description': 'Relative impact of parameters on performance'}
            ],
            'best_configuration': {
                'anomaly_threshold': float(best_config['anomaly_threshold']),
                'state_transition_min_count': int(best_config['state_transition_min_count']),
                'unit_generation_strategy': best_config['unit_generation_strategy'],
                'confidence_threshold': float(best_config['confidence_threshold']),
                'f1_score': float(best_config['f1_score'])
            },
            'parameter_correlations': self._calculate_correlations(df),
            'configuration': {
                'api_url': self.service_url,
                'evaluation_timestamp': datetime.now().isoformat(),
                'parameter_grid': self.get_parameter_grid()
            },
            'conclusions': self._generate_conclusions(df),
            'data_files': {
                'csv_results': str(self.output_dir / 'parameter_study_results.csv'),
                'visualization': str(self.output_dir / 'parameter_study_analysis.png'),
                'detailed_plot': str(self.output_dir / 'parameter_study_detailed.png')
            }
        }
        
        # Generate reports
        md_path = self.report_generator.generate_markdown_report(
            'parameter_study',
            detailed_results,
            summary
        )
        
        json_path = self.report_generator.generate_json_report(
            'parameter_study',
            detailed_results
        )
        
        logging.info(f"Reports generated:")
        logging.info(f"  - Markdown: {md_path}")
        logging.info(f"  - JSON: {json_path}")
    
    def _calculate_parameter_impact(self, df: pd.DataFrame) -> float:
        """计算参数对性能的影响程度"""
        # 简单的方差分析
        return df['f1_score'].std() / df['f1_score'].mean() if df['f1_score'].mean() > 0 else 0
    
    def _calculate_correlations(self, df: pd.DataFrame) -> dict:
        """计算参数与性能的相关性"""
        numeric_params = ['anomaly_threshold', 'state_transition_min_count', 'confidence_threshold']
        correlations = {}
        
        for param in numeric_params:
            if param in df.columns:
                corr = df[param].corr(df['f1_score'])
                correlations[param] = f"{corr:.4f}"
        
        return correlations
    
    def _generate_conclusions(self, df: pd.DataFrame) -> list:
        """生成结论"""
        conclusions = []
        
        # Best strategy
        if 'unit_generation_strategy' in df.columns:
            best_strategy = df.groupby('unit_generation_strategy')['f1_score'].mean().idxmax()
            conclusions.append(f"The '{best_strategy}' unit generation strategy performs best on average")
        
        # Threshold impact
        if 'anomaly_threshold' in df.columns:
            threshold_corr = df['anomaly_threshold'].corr(df['f1_score'])
            if abs(threshold_corr) > 0.3:
                direction = "higher" if threshold_corr > 0 else "lower"
                conclusions.append(f"Performance tends to be better with {direction} anomaly thresholds")
        
        # Processing time
        if 'generation_time' in df.columns:
            time_variation = df['generation_time'].std() / df['generation_time'].mean()
            if time_variation > 0.2:
                conclusions.append("Processing time varies significantly with parameter choices")
        
        # Optimal parameter range
        best_f1 = df['f1_score'].max()
        good_configs = df[df['f1_score'] >= best_f1 * 0.95]
        if len(good_configs) > 1:
            conclusions.append(f"{len(good_configs)} parameter combinations achieve within 5% of best performance")
        
        return conclusions


async def main():
    """主函数"""
    print("CPAG Parameter Study Evaluation")
    print("=" * 60)
    
    # 初始化评估器
    evaluator = ParameterStudyEvaluator()
    
    # 获取测试文件
    all_csv_files = list(Path("data/csv").glob("*.csv"))
    
    if not all_csv_files:
        print("No test files found!")
        return
    
    # 使用更多文件以获得更全面的评估
    num_files_to_use = min(20, len(all_csv_files))  # 使用最多20个文件
    test_files = all_csv_files[:num_files_to_use]
    
    print(f"Found {len(all_csv_files)} CSV files total")
    print(f"Using {len(test_files)} files for parameter study")
    
    # 增加参数采样数量以更好地覆盖参数空间
    sample_size = 50 if len(test_files) >= 10 else 30
    
    # 运行参数研究
    await evaluator.run_parameter_study(test_files, sample_size=sample_size)
    
    print("\nParameter study complete!")
    print("Results saved to:")
    print("- parameter_study_results.csv (raw data)")
    print("- parameter_study_analysis.png (main visualizations)")
    print("- parameter_study_detailed.png (detailed analysis)")


if __name__ == "__main__":
    asyncio.run(main())
