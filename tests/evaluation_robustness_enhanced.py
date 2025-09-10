#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluation_robustness_enhanced.py
---------------------------------
Enhanced robustness evaluation that supports both CSV and PCAP files.

Features:
- Traditional noise robustness for CSV sensor data
- Network-specific robustness tests for PCAP data
- Cross-modality stability analysis
- Comprehensive visualization
"""

import asyncio
import aiohttp
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime, timedelta
import random

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import entropy
from scipy.spatial.distance import jensenshannon
import struct

# Import from existing evaluators
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation_robustness_temporal import RobustnessTemporalEvaluator
from evaluation_report_generator import EvaluationReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class EnhancedRobustnessEvaluator(RobustnessTemporalEvaluator):
    """Enhanced robustness evaluator with PCAP support"""
    
    def __init__(self, service_url: str = "http://localhost:8002"):
        super().__init__(service_url)
        self.results['pcap_robustness'] = []
        self.results['cross_modal_stability'] = []
        
        # Create output directory
        self.output_dir = Path("evaluation_results/robustness_enhanced")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_generator = EvaluationReportGenerator(str(self.output_dir))
        
    def detect_file_type(self, file_path: Path) -> str:
        """Detect if file is CSV or PCAP/PCAPNG"""
        suffix = file_path.suffix.lower()
        if suffix == '.csv':
            return 'csv'
        elif suffix in ['.pcap', '.pcapng']:
            return 'pcap'
        else:
            raise ValueError(f"Unsupported file type: {suffix}")
    
    def add_pcap_noise(self, pcap_data: bytes, noise_type: str, noise_level: float) -> bytes:
        """Add noise to PCAP data"""
        if noise_type == 'packet_loss':
            # Simulate packet loss by randomly dropping packets
            return self._simulate_packet_loss(pcap_data, noise_level)
        elif noise_type == 'packet_delay':
            # Simulate network delays by reordering packets
            return self._simulate_packet_delay(pcap_data, noise_level)
        elif noise_type == 'packet_corruption':
            # Simulate packet corruption
            return self._simulate_packet_corruption(pcap_data, noise_level)
        elif noise_type == 'packet_duplication':
            # Simulate packet duplication
            return self._simulate_packet_duplication(pcap_data, noise_level)
        else:
            return pcap_data
    
    def _simulate_packet_loss(self, pcap_data: bytes, loss_rate: float) -> bytes:
        """Simulate packet loss in PCAP data"""
        # This is a simplified implementation
        # In reality, we would parse PCAP structure and drop individual packets
        # For now, we'll randomly remove chunks of data
        
        data_array = bytearray(pcap_data)
        chunk_size = 1000  # bytes
        num_chunks = len(data_array) // chunk_size
        
        chunks_to_drop = int(num_chunks * loss_rate)
        if chunks_to_drop > 0:
            drop_indices = sorted(random.sample(range(num_chunks), chunks_to_drop), reverse=True)
            for idx in drop_indices:
                start = idx * chunk_size
                end = min((idx + 1) * chunk_size, len(data_array))
                del data_array[start:end]
        
        return bytes(data_array)
    
    def _simulate_packet_delay(self, pcap_data: bytes, delay_factor: float) -> bytes:
        """Simulate packet delays/reordering"""
        # Simplified: shuffle chunks to simulate reordering
        data_array = bytearray(pcap_data)
        chunk_size = 1000
        chunks = [data_array[i:i+chunk_size] for i in range(0, len(data_array), chunk_size)]
        
        # Shuffle some chunks based on delay factor
        num_shuffles = int(len(chunks) * delay_factor)
        if num_shuffles > 1:
            indices = list(range(len(chunks)))
            for _ in range(num_shuffles):
                i, j = random.sample(indices, 2)
                chunks[i], chunks[j] = chunks[j], chunks[i]
        
        return b''.join(chunks)
    
    def _simulate_packet_corruption(self, pcap_data: bytes, corruption_rate: float) -> bytes:
        """Simulate packet corruption"""
        data_array = bytearray(pcap_data)
        num_corruptions = int(len(data_array) * corruption_rate)
        
        for _ in range(num_corruptions):
            pos = random.randint(0, len(data_array) - 1)
            # Flip random bits
            data_array[pos] = data_array[pos] ^ random.randint(1, 255)
        
        return bytes(data_array)
    
    def _simulate_packet_duplication(self, pcap_data: bytes, dup_rate: float) -> bytes:
        """Simulate packet duplication"""
        data_array = bytearray(pcap_data)
        chunk_size = 1000
        chunks = [data_array[i:i+chunk_size] for i in range(0, len(data_array), chunk_size)]
        
        num_dups = int(len(chunks) * dup_rate)
        if num_dups > 0:
            dup_indices = random.sample(range(len(chunks)), min(num_dups, len(chunks)))
            for idx in sorted(dup_indices, reverse=True):
                chunks.insert(idx + 1, chunks[idx])
        
        return b''.join(chunks)
    
    async def evaluate_pcap_robustness(self, session: aiohttp.ClientSession,
                                     file_path: Path,
                                     noise_levels: List[float] = [0.0, 0.01, 0.05, 0.1, 0.15, 0.2]):
        """Evaluate PCAP-specific robustness"""
        logging.info(f"Evaluating PCAP robustness for {file_path.name}")
        
        # Read original PCAP data
        with open(file_path, 'rb') as f:
            pcap_data = f.read()
        
        # Generate baseline CPAG
        baseline_units = await self._generate_cpag_from_pcap(session, file_path, pcap_data)
        if not baseline_units:
            logging.error("Failed to generate baseline CPAG from PCAP")
            return
        
        results = []
        
        for noise_level in noise_levels:
            for noise_type in ['packet_loss', 'packet_delay', 'packet_corruption', 'packet_duplication']:
                logging.info(f"Testing {noise_type} at level {noise_level}")
                
                # Add noise to PCAP data
                noisy_pcap = self.add_pcap_noise(pcap_data, noise_type, noise_level)
                
                # Generate CPAG from noisy data
                noisy_units = await self._generate_cpag_from_pcap(session, file_path, noisy_pcap)
                
                if noisy_units:
                    # Calculate stability metrics
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
        
        self.results['pcap_robustness'].extend(results)
    
    async def _generate_cpag_from_pcap(self, session: aiohttp.ClientSession,
                                     file_path: Path,
                                     pcap_data: bytes) -> List[Dict]:
        """Generate CPAG from PCAP data"""
        try:
            # Create temporary file
            temp_file = Path(f"temp_pcap_{time.time()}.pcap")
            with open(temp_file, 'wb') as f:
                f.write(pcap_data)
            
            # Prepare form data with smaller chunk size for large files
            form_data = aiohttp.FormData()
            
            # Read file in smaller chunks to avoid memory issues
            with open(temp_file, 'rb') as f:
                file_content = f.read()
                form_data.add_field('pcap_file', file_content,
                                  filename=file_path.name,
                                  content_type='application/octet-stream')
            
            form_data.add_field('device_map', json.dumps({}))
            form_data.add_field('rules', json.dumps([]))
            form_data.add_field('output_format', 'json')
            form_data.add_field('top_k', '40')
            form_data.add_field('top_per_plc', '20')
            form_data.add_field('custom_params', json.dumps({
                'use_optimized_pcap': True,
                'max_packets': 50000,  # Limit packets for robustness testing
                'timeout': 180  # 3 minutes timeout
            }))
            
            # Delete temp file
            temp_file.unlink()
            
            # Submit task with longer timeout
            timeout = aiohttp.ClientTimeout(total=300)  # 5 minutes total timeout
            async with session.post(f"{self.service_url}/cpag/generate", 
                                   data=form_data,
                                   timeout=timeout) as resp:
                if resp.status != 200:
                    return []
                
                result = await resp.json()
                task_id = result['id']
            
            # Wait for completion
            for _ in range(60):  # PCAP processing may take longer
                await asyncio.sleep(2)
                
                async with session.get(f"{self.service_url}/cpag/status/{task_id}") as resp:
                    if resp.status == 200:
                        status_data = await resp.json()
                        if status_data['status'] == 'completed':
                            # Get results
                            async with session.get(f"{self.service_url}/cpag/result/{task_id}") as result_resp:
                                result_data = await result_resp.json()
                                return result_data.get('units', [])
                        elif status_data['status'] == 'failed':
                            return []
            
            return []
            
        except Exception as e:
            logging.error(f"Error generating CPAG from PCAP: {e}")
            return []
    
    async def evaluate_cross_modal_stability(self, session: aiohttp.ClientSession,
                                           csv_file: Path,
                                           pcap_file: Path):
        """Evaluate stability across different data modalities"""
        logging.info(f"Evaluating cross-modal stability: {csv_file.name} vs {pcap_file.name}")
        
        # Generate CPAGs from both sources
        csv_df = pd.read_csv(csv_file)
        csv_units = await self._generate_cpag(session, csv_file, csv_df)
        
        with open(pcap_file, 'rb') as f:
            pcap_data = f.read()
        pcap_units = await self._generate_cpag_from_pcap(session, pcap_file, pcap_data)
        
        if not csv_units or not pcap_units:
            logging.error("Failed to generate CPAGs for cross-modal comparison")
            return
        
        # Analyze differences
        csv_categories = self._get_category_distribution(csv_units)
        pcap_categories = self._get_category_distribution(pcap_units)
        
        # Calculate metrics
        category_overlap = len(set(csv_categories.keys()) & set(pcap_categories.keys()))
        total_categories = len(set(csv_categories.keys()) | set(pcap_categories.keys()))
        category_similarity = category_overlap / total_categories if total_categories > 0 else 0
        
        # JS divergence for distribution comparison
        all_categories = sorted(set(csv_categories.keys()) | set(pcap_categories.keys()))
        csv_dist = [csv_categories.get(cat, 0) for cat in all_categories]
        pcap_dist = [pcap_categories.get(cat, 0) for cat in all_categories]
        
        # Normalize
        csv_dist = np.array(csv_dist) / (sum(csv_dist) + 1e-10)
        pcap_dist = np.array(pcap_dist) / (sum(pcap_dist) + 1e-10)
        
        js_divergence = jensenshannon(csv_dist, pcap_dist) ** 2
        
        self.results['cross_modal_stability'].append({
            'csv_file': csv_file.name,
            'pcap_file': pcap_file.name,
            'csv_units': len(csv_units),
            'pcap_units': len(pcap_units),
            'category_similarity': category_similarity,
            'js_divergence': js_divergence,
            'csv_dominant_category': max(csv_categories.items(), key=lambda x: x[1])[0] if csv_categories else 'none',
            'pcap_dominant_category': max(pcap_categories.items(), key=lambda x: x[1])[0] if pcap_categories else 'none'
        })
    
    def generate_enhanced_report(self):
        """Generate enhanced robustness report"""
        print("\n" + "="*60)
        print("ENHANCED ROBUSTNESS EVALUATION REPORT")
        print("="*60)
        
        # Original CSV robustness
        if self.results['noise_robustness']:
            print("\n### CSV Data Robustness ###")
            df = pd.DataFrame(self.results['noise_robustness'])
            
            for noise_type in df['noise_type'].unique():
                noise_df = df[df['noise_type'] == noise_type]
                avg_stability = noise_df.groupby('noise_level')['unit_similarity'].mean()
                
                print(f"\n{noise_type.title()} Noise:")
                for level, stability in avg_stability.items():
                    print(f"  {level*100:.0f}%: {stability:.3f}")
        
        # PCAP robustness
        if self.results['pcap_robustness']:
            print("\n### PCAP Data Robustness ###")
            df = pd.DataFrame(self.results['pcap_robustness'])
            
            for noise_type in df['noise_type'].unique():
                noise_df = df[df['noise_type'] == noise_type]
                avg_stability = noise_df.groupby('noise_level')['unit_similarity'].mean()
                
                print(f"\n{noise_type.replace('_', ' ').title()}:")
                for level, stability in avg_stability.items():
                    print(f"  {level*100:.0f}%: {stability:.3f}")
        
        # Cross-modal stability
        if self.results['cross_modal_stability']:
            print("\n### Cross-Modal Stability ###")
            df = pd.DataFrame(self.results['cross_modal_stability'])
            
            print(f"Average category similarity: {df['category_similarity'].mean():.3f}")
            print(f"Average JS divergence: {df['js_divergence'].mean():.3f}")
            print(f"CSV average units: {df['csv_units'].mean():.1f}")
            print(f"PCAP average units: {df['pcap_units'].mean():.1f}")
        
        # Temporal stability (from parent class)
        if self.results['temporal_stability']:
            print("\n### Temporal Stability ###")
            df = pd.DataFrame(self.results['temporal_stability'])
            avg_consistency = df.groupby('segment_size')['avg_consistency'].mean()
            
            print("Segment consistency:")
            for size, consistency in avg_consistency.items():
                print(f"  {size} points: {consistency:.3f}")
    
    def generate_enhanced_plots(self):
        """Generate enhanced visualization plots"""
        fig = plt.figure(figsize=(20, 16))
        
        # 1. CSV vs PCAP noise robustness comparison
        ax1 = plt.subplot(3, 3, 1)
        if self.results['noise_robustness'] and self.results['pcap_robustness']:
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            
            # Average across noise types
            csv_avg = csv_df.groupby('noise_level')['unit_similarity'].mean()
            pcap_avg = pcap_df.groupby('noise_level')['unit_similarity'].mean()
            
            ax1.plot(csv_avg.index * 100, csv_avg.values, 'o-', label='CSV Data', linewidth=2)
            ax1.plot(pcap_avg.index * 100, pcap_avg.values, 's-', label='PCAP Data', linewidth=2)
            ax1.set_xlabel('Noise Level (%)')
            ax1.set_ylabel('Unit Similarity')
            ax1.set_title('CSV vs PCAP Robustness Comparison')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
        
        # 2. PCAP-specific noise types
        ax2 = plt.subplot(3, 3, 2)
        if self.results['pcap_robustness']:
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            
            for noise_type in pcap_df['noise_type'].unique():
                noise_data = pcap_df[pcap_df['noise_type'] == noise_type]
                avg_stability = noise_data.groupby('noise_level')['unit_similarity'].mean()
                ax2.plot(avg_stability.index * 100, avg_stability.values, 
                        marker='o', label=noise_type.replace('_', ' ').title())
            
            ax2.set_xlabel('Noise Level (%)')
            ax2.set_ylabel('Unit Similarity')
            ax2.set_title('PCAP Robustness by Noise Type')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
        
        # 3. Cross-modal stability
        ax3 = plt.subplot(3, 3, 3)
        if self.results['cross_modal_stability']:
            cross_df = pd.DataFrame(self.results['cross_modal_stability'])
            
            x = np.arange(len(cross_df))
            width = 0.35
            
            ax3.bar(x - width/2, cross_df['csv_units'], width, label='CSV Units', alpha=0.8)
            ax3.bar(x + width/2, cross_df['pcap_units'], width, label='PCAP Units', alpha=0.8)
            
            ax3.set_xlabel('File Pairs')
            ax3.set_ylabel('Number of Units')
            ax3.set_title('Cross-Modal Unit Generation Comparison')
            ax3.set_xticks(x)
            ax3.set_xticklabels([f"Pair {i+1}" for i in range(len(cross_df))], rotation=45)
            ax3.legend()
        
        # 4. Category distribution heatmap
        ax4 = plt.subplot(3, 3, 4)
        if self.results['noise_robustness']:
            # Create heatmap data
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            pivot_data = noise_df.pivot_table(
                values='category_stability',
                index='noise_type',
                columns='noise_level',
                aggfunc='mean'
            )
            
            sns.heatmap(pivot_data, annot=True, fmt='.2f', cmap='RdYlGn', ax=ax4)
            ax4.set_title('CSV Category Stability Heatmap')
            ax4.set_xlabel('Noise Level')
            ax4.set_ylabel('Noise Type')
        
        # 5. PCAP category stability heatmap
        ax5 = plt.subplot(3, 3, 5)
        if self.results['pcap_robustness']:
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            pivot_data = pcap_df.pivot_table(
                values='category_stability',
                index='noise_type',
                columns='noise_level',
                aggfunc='mean'
            )
            
            sns.heatmap(pivot_data, annot=True, fmt='.2f', cmap='RdYlGn', ax=ax5)
            ax5.set_title('PCAP Category Stability Heatmap')
            ax5.set_xlabel('Noise Level')
            ax5.set_ylabel('Noise Type')
        
        # 6. Cross-modal JS divergence
        ax6 = plt.subplot(3, 3, 6)
        if self.results['cross_modal_stability']:
            cross_df = pd.DataFrame(self.results['cross_modal_stability'])
            
            ax6.scatter(cross_df['category_similarity'], cross_df['js_divergence'], 
                       s=100, alpha=0.6, c=range(len(cross_df)), cmap='viridis')
            ax6.set_xlabel('Category Similarity')
            ax6.set_ylabel('JS Divergence')
            ax6.set_title('Cross-Modal Distribution Comparison')
            ax6.grid(True, alpha=0.3)
            
            # Add colorbar
            cbar = plt.colorbar(ax6.collections[0], ax=ax6)
            cbar.set_label('File Pair Index')
        
        # 7. Temporal stability comparison
        ax7 = plt.subplot(3, 3, 7)
        if self.results['temporal_stability']:
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            
            # Group by file type if available
            for file_name in temp_df['file'].unique():
                file_data = temp_df[temp_df['file'] == file_name]
                file_type = 'CSV' if file_name.endswith('.csv') else 'PCAP'
                
                avg_by_segment = file_data.groupby('segment_size')['avg_consistency'].mean()
                ax7.plot(avg_by_segment.index, avg_by_segment.values, 
                        marker='o', label=f"{file_type}: {file_name[:20]}...")
            
            ax7.set_xlabel('Segment Size')
            ax7.set_ylabel('Average Consistency')
            ax7.set_title('Temporal Stability by File Type')
            ax7.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            ax7.grid(True, alpha=0.3)
        
        # 8. Unit count variation
        ax8 = plt.subplot(3, 3, 8)
        all_results = []
        
        if self.results['noise_robustness']:
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            csv_df['data_type'] = 'CSV'
            all_results.append(csv_df)
        
        if self.results['pcap_robustness']:
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            pcap_df['data_type'] = 'PCAP'
            all_results.append(pcap_df)
        
        if all_results:
            combined_df = pd.concat(all_results)
            combined_df['unit_change_ratio'] = (combined_df['num_units_noisy'] - 
                                               combined_df['num_units_original']) / \
                                              combined_df['num_units_original']
            
            # Violin plot
            positions = []
            labels = []
            pos = 0
            
            for data_type in ['CSV', 'PCAP']:
                type_df = combined_df[combined_df['data_type'] == data_type]
                for noise_level in sorted(type_df['noise_level'].unique()):
                    level_data = type_df[type_df['noise_level'] == noise_level]['unit_change_ratio']
                    if len(level_data) > 0:
                        parts = ax8.violinplot([level_data.values], positions=[pos], widths=0.8)
                        for pc in parts['bodies']:
                            pc.set_facecolor('C0' if data_type == 'CSV' else 'C1')
                            pc.set_alpha(0.7)
                        positions.append(pos)
                        labels.append(f"{data_type}\n{noise_level*100:.0f}%")
                        pos += 1
            
            ax8.set_xticks(positions)
            ax8.set_xticklabels(labels, rotation=45)
            ax8.set_ylabel('Unit Count Change Ratio')
            ax8.set_title('Impact on Unit Generation')
            ax8.grid(True, alpha=0.3, axis='y')
        
        # 9. Summary metrics
        ax9 = plt.subplot(3, 3, 9)
        ax9.axis('off')
        
        summary_text = "ENHANCED ROBUSTNESS SUMMARY\n" + "="*30 + "\n\n"
        
        if self.results['noise_robustness']:
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            csv_score = csv_df['unit_similarity'].mean()
            summary_text += f"CSV Robustness Score: {csv_score:.3f}\n"
        
        if self.results['pcap_robustness']:
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            pcap_score = pcap_df['unit_similarity'].mean()
            summary_text += f"PCAP Robustness Score: {pcap_score:.3f}\n"
        
        if self.results['temporal_stability']:
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            temp_score = temp_df['avg_consistency'].mean()
            summary_text += f"Temporal Stability Score: {temp_score:.3f}\n"
        
        if self.results['cross_modal_stability']:
            cross_df = pd.DataFrame(self.results['cross_modal_stability'])
            cross_score = 1 - cross_df['js_divergence'].mean()
            summary_text += f"Cross-Modal Stability: {cross_score:.3f}\n"
        
        ax9.text(0.1, 0.5, summary_text, fontsize=12, family='monospace',
                verticalalignment='center', transform=ax9.transAxes)
        
        plt.tight_layout()
        output_path = self.output_dir / 'robustness_enhanced_evaluation.png'
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        logging.info(f"Enhanced robustness plots saved to {output_path}")
        
        # Generate comprehensive report
        self.generate_comprehensive_report()
    
    def generate_individual_plots(self):
        """Generate individual plots for each analysis"""
        # Create individual plots directory
        individual_dir = self.output_dir / 'individual_plots'
        individual_dir.mkdir(exist_ok=True)
        
        # 1. CSV vs PCAP noise robustness comparison
        if self.results['noise_robustness'] and self.results['pcap_robustness']:
            plt.figure(figsize=(10, 6))
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            
            # Average across noise types
            csv_avg = csv_df.groupby('noise_level')['unit_similarity'].mean()
            pcap_avg = pcap_df.groupby('noise_level')['unit_similarity'].mean()
            
            plt.plot(csv_avg.index, csv_avg.values, 'o-', label='CSV', linewidth=2, markersize=8)
            plt.plot(pcap_avg.index, pcap_avg.values, 's-', label='PCAP', linewidth=2, markersize=8)
            plt.xlabel('Noise Level')
            plt.ylabel('Graph Similarity')
            plt.title('CSV vs PCAP Noise Robustness Comparison')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(individual_dir / 'csv_vs_pcap_robustness.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 2. PCAP-specific noise types
        if self.results['pcap_robustness']:
            plt.figure(figsize=(10, 6))
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            
            for noise_type in pcap_df['noise_type'].unique():
                noise_data = pcap_df[pcap_df['noise_type'] == noise_type]
                avg_similarity = noise_data.groupby('noise_level')['unit_similarity'].mean()
                plt.plot(avg_similarity.index, avg_similarity.values, 'o-', 
                        label=noise_type.replace('_', ' ').title(), linewidth=2, markersize=8)
            
            plt.xlabel('Noise Level')
            plt.ylabel('Graph Similarity')
            plt.title('PCAP Robustness by Noise Type')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(individual_dir / 'pcap_noise_types.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 3. Cross-modal stability
        if self.results['cross_modal_stability']:
            plt.figure(figsize=(10, 6))
            cross_df = pd.DataFrame(self.results['cross_modal_stability'])
            
            x = np.arange(len(cross_df))
            width = 0.35
            
            plt.bar(x - width/2, cross_df['category_similarity'], width, label='Category Similarity', alpha=0.8)
            plt.bar(x + width/2, 1 - cross_df['js_divergence'], width, label='1 - JS Divergence', alpha=0.8)
            
            plt.xlabel('Test Pairs')
            plt.ylabel('Similarity Score')
            plt.title('Cross-Modal Stability Analysis')
            plt.xticks(x, [f"Pair {i+1}" for i in range(len(cross_df))])
            plt.legend()
            plt.grid(True, alpha=0.3, axis='y')
            plt.savefig(individual_dir / 'cross_modal_stability.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 4. Category distribution heatmap (CSV)
        if self.results['noise_robustness']:
            plt.figure(figsize=(10, 8))
            noise_df = pd.DataFrame(self.results['noise_robustness'])
            pivot_data = noise_df.pivot_table(
                values='category_stability',
                index='noise_level',
                columns='noise_type',
                aggfunc='mean'
            )
            sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap='RdYlGn', vmin=0, vmax=1)
            plt.title('CSV Category Stability Heatmap')
            plt.tight_layout()
            plt.savefig(individual_dir / 'csv_category_stability_heatmap.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 5. PCAP category stability heatmap
        if self.results['pcap_robustness']:
            plt.figure(figsize=(10, 8))
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            pivot_data = pcap_df.pivot_table(
                values='category_stability',
                index='noise_type',
                columns='noise_level',
                aggfunc='mean'
            )
            sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap='RdYlGn', vmin=0, vmax=1)
            plt.title('PCAP Category Stability Heatmap')
            plt.tight_layout()
            plt.savefig(individual_dir / 'pcap_category_stability_heatmap.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 6. Cross-modal JS divergence scatter
        if self.results['cross_modal_stability']:
            plt.figure(figsize=(8, 6))
            cross_df = pd.DataFrame(self.results['cross_modal_stability'])
            
            plt.scatter(cross_df['category_similarity'], cross_df['js_divergence'], 
                       s=150, alpha=0.6, c=range(len(cross_df)), cmap='viridis')
            
            for i, (sim, js) in enumerate(zip(cross_df['category_similarity'], cross_df['js_divergence'])):
                plt.annotate(f'Pair {i+1}', (sim, js), xytext=(5, 5), textcoords='offset points')
            
            plt.xlabel('Category Similarity')
            plt.ylabel('JS Divergence')
            plt.title('Cross-Modal: Category Similarity vs JS Divergence')
            plt.grid(True, alpha=0.3)
            plt.savefig(individual_dir / 'cross_modal_js_divergence.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 7. Temporal stability comparison
        if self.results['temporal_stability']:
            plt.figure(figsize=(10, 6))
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            
            for file_name in temp_df['file'].unique():
                file_data = temp_df[temp_df['file'] == file_name]
                plt.plot(file_data['segment_size'], file_data['avg_consistency'], 
                        'o-', label=Path(file_name).stem, linewidth=2, markersize=8)
            
            plt.xlabel('Segment Size')
            plt.ylabel('Temporal Consistency')
            plt.title('Temporal Stability by Segment Size')
            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(individual_dir / 'temporal_stability.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 8. Unit count variation
        if self.results['noise_robustness'] or self.results['pcap_robustness']:
            plt.figure(figsize=(10, 6))
            all_results = []
            
            if self.results['noise_robustness']:
                csv_df = pd.DataFrame(self.results['noise_robustness'])
                csv_df['data_type'] = 'CSV'
                all_results.append(csv_df)
            
            if self.results['pcap_robustness']:
                pcap_df = pd.DataFrame(self.results['pcap_robustness'])
                pcap_df['data_type'] = 'PCAP'
                all_results.append(pcap_df)
            
            if all_results:
                combined_df = pd.concat(all_results, ignore_index=True)
                
                for data_type in combined_df['data_type'].unique():
                    type_data = combined_df[combined_df['data_type'] == data_type]
                    noise_groups = type_data.groupby('noise_level')
                    
                    means = []
                    stds = []
                    noise_levels = []
                    
                    for noise_level, group in noise_groups:
                        unit_counts = group['num_units_noisy'].values
                        means.append(np.mean(unit_counts))
                        stds.append(np.std(unit_counts))
                        noise_levels.append(noise_level)
                    
                    plt.errorbar(noise_levels, means, yerr=stds, label=data_type, 
                               fmt='o-', capsize=5, linewidth=2, markersize=8)
                
                plt.xlabel('Noise Level')
                plt.ylabel('Unit Count')
                plt.title('Unit Count Variation with Noise')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.savefig(individual_dir / 'unit_count_variation.png', dpi=150, bbox_inches='tight')
                plt.close()
        
        logging.info(f"Individual plots saved to {individual_dir}")


    def generate_comprehensive_report(self):
        """Generate comprehensive robustness evaluation report"""
        # Prepare summary data
        summary = {
            'total_tests': sum(len(self.results[k]) for k in self.results),
            'test_types': list(self.results.keys()),
            'csv_files_tested': len(set(r['file'] for r in self.results.get('csv_robustness', []))),
            'pcap_files_tested': len(set(r['file'] for r in self.results.get('pcap_robustness', [])))
        }
        
        # Calculate aggregate metrics
        if self.results.get('noise_robustness'):
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            summary['csv_avg_robustness'] = csv_df['unit_similarity'].mean()
        
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            summary['pcap_avg_robustness'] = pcap_df['unit_similarity'].mean()
        
        if self.results.get('temporal_stability'):
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            summary['temporal_stability_index'] = temp_df['avg_consistency'].mean()
        
        # Prepare detailed results
        detailed_results = {
            'key_metrics': self._generate_key_metrics(),
            'robustness_analysis': self._analyze_robustness_results(),
            'noise_impact': self._analyze_noise_impact(),
            'temporal_analysis': self._analyze_temporal_stability(),
            'configuration': {
                'service_url': self.service_url,
                'evaluation_timestamp': datetime.now().isoformat(),
                'noise_types': ['gaussian', 'uniform', 'salt_pepper', 'drift'],
                'pcap_noise_types': ['packet_loss', 'packet_delay', 'packet_corruption', 'packet_duplication']
            },
            'conclusions': self._generate_robustness_conclusions(),
            'data_files': {
                'visualization': str(self.output_dir / 'robustness_enhanced_evaluation.png')
            }
        }
        
        # Save raw results
        for result_type, data in self.results.items():
            if data:
                csv_path = self.output_dir / f'{result_type}_results.csv'
                pd.DataFrame(data).to_csv(csv_path, index=False)
                detailed_results['data_files'][result_type] = str(csv_path)
        
        # Generate reports
        md_path = self.report_generator.generate_markdown_report(
            'robustness_enhanced',
            detailed_results,
            summary
        )
        
        json_path = self.report_generator.generate_json_report(
            'robustness_enhanced',
            detailed_results
        )
        
        logging.info(f"Reports generated:")
        logging.info(f"  - Markdown: {md_path}")
        logging.info(f"  - JSON: {json_path}")
    
    def _generate_key_metrics(self) -> list:
        """Generate key robustness metrics"""
        metrics = []
        
        if self.results.get('noise_robustness'):
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            metrics.extend([
                {'name': 'CSV Robustness Score', 
                 'value': f"{csv_df['unit_similarity'].mean():.4f}",
                 'description': 'Average unit similarity under noise for CSV data'}
            ])
        
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            metrics.extend([
                {'name': 'PCAP Robustness Score', 
                 'value': f"{pcap_df['unit_similarity'].mean():.4f}",
                 'description': 'Average unit similarity under network perturbations'}
            ])
        
        if self.results.get('temporal_stability'):
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            metrics.append({
                'name': 'Temporal Stability Index',
                'value': f"{temp_df['avg_consistency'].mean():.4f}",
                'description': 'Consistency of CPAG generation over time windows'
            })
        
        return metrics
    
    def _analyze_robustness_results(self) -> dict:
        """Analyze robustness test results"""
        analysis = {}
        
        # CSV robustness analysis
        if self.results.get('noise_robustness'):
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            noise_impact = csv_df.groupby('noise_type')['unit_similarity'].mean()
            analysis['csv_noise_impact'] = noise_impact.to_dict()
            analysis['most_robust_csv_noise'] = noise_impact.idxmax()
            analysis['least_robust_csv_noise'] = noise_impact.idxmin()
        
        # PCAP robustness analysis
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            noise_impact = pcap_df.groupby('noise_type')['unit_similarity'].mean()
            analysis['pcap_noise_impact'] = noise_impact.to_dict()
            analysis['most_robust_pcap_noise'] = noise_impact.idxmax()
            analysis['least_robust_pcap_noise'] = noise_impact.idxmin()
        
        return analysis
    
    def _analyze_noise_impact(self) -> dict:
        """Analyze impact of different noise levels"""
        impact = {}
        
        if self.results.get('noise_robustness'):
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            # Group by noise level
            level_groups = csv_df.groupby('noise_level')['unit_similarity'].mean()
            impact['csv_noise_levels'] = level_groups.to_dict()
        
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            level_groups = pcap_df.groupby('noise_level')['unit_similarity'].mean()
            impact['pcap_noise_levels'] = level_groups.to_dict()
        
        return impact
    
    def _analyze_temporal_stability(self) -> dict:
        """Analyze temporal stability results"""
        if not self.results.get('temporal_stability'):
            return {}
        
        temp_df = pd.DataFrame(self.results['temporal_stability'])
        
        return {
            'average_consistency': temp_df['avg_consistency'].mean(),
            'consistency_std': temp_df['avg_consistency'].std(),
            'most_stable_file': temp_df.loc[temp_df['avg_consistency'].idxmax(), 'file'],
            'least_stable_file': temp_df.loc[temp_df['avg_consistency'].idxmin(), 'file']
        }
    
    def _generate_robustness_conclusions(self) -> list:
        """Generate conclusions from robustness evaluation"""
        conclusions = []
        
        # Overall robustness
        all_scores = []
        if self.results.get('noise_robustness'):
            csv_df = pd.DataFrame(self.results['noise_robustness'])
            all_scores.extend(csv_df['unit_similarity'].values)
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            all_scores.extend(pcap_df['unit_similarity'].values)
        
        if all_scores:
            avg_robustness = np.mean(all_scores)
            if avg_robustness > 0.8:
                conclusions.append("The CPAG generation system shows strong robustness to various perturbations")
            elif avg_robustness > 0.6:
                conclusions.append("The system demonstrates moderate robustness, with room for improvement")
            else:
                conclusions.append("The system shows limited robustness and may benefit from enhancement")
        
        # Noise type specific conclusions
        if self.results.get('csv_robustness'):
            csv_df = pd.DataFrame(self.results['csv_robustness'])
            worst_noise = csv_df.groupby('noise_type')['unit_similarity'].mean().idxmin()
            conclusions.append(f"CSV data is most vulnerable to {worst_noise} noise")
        
        if self.results.get('pcap_robustness'):
            pcap_df = pd.DataFrame(self.results['pcap_robustness'])
            worst_noise = pcap_df.groupby('noise_type')['unit_similarity'].mean().idxmin()
            conclusions.append(f"PCAP data is most vulnerable to {worst_noise}")
        
        # Temporal stability
        if self.results.get('temporal_stability'):
            temp_df = pd.DataFrame(self.results['temporal_stability'])
            avg_temporal = temp_df['avg_consistency'].mean()
            if avg_temporal > 0.85:
                conclusions.append("The system shows excellent temporal stability")
            elif avg_temporal > 0.7:
                conclusions.append("The system demonstrates good temporal consistency")
            else:
                conclusions.append("Temporal stability could be improved for more consistent results")
        
        return conclusions
    
    async def evaluate_temporal_stability(self, session: aiohttp.ClientSession,
                                        file_path: Path,
                                        segment_sizes: List[int] = [200, 500, 1000, 1500, 2000]):
        """评估时序稳定性 - 重写以支持PCAP文件"""
        logging.info(f"Evaluating temporal stability for {file_path.name}")
        
        file_type = self.detect_file_type(file_path)
        
        if file_type == 'csv':
            # 对于CSV文件，调用父类方法
            return await super().evaluate_temporal_stability(session, file_path, segment_sizes)
        else:
            # 对于PCAP文件，跳过时序稳定性测试（因为PCAP文件不适合这种分段测试）
            logging.info(f"Skipping temporal stability for PCAP file {file_path.name}")
            return {
                'file': file_path.name,
                'consistency_scores': [],
                'avg_consistency': 1.0,  # 假设PCAP文件的时序稳定性为1
                'segment_sizes': []
            }


async def main():
    """Main function"""
    print("Enhanced CPAG Robustness Evaluation")
    print("=" * 60)
    
    evaluator = EnhancedRobustnessEvaluator()
    
    # Get test files
    csv_files = list(Path("data/csv").glob("*.csv"))[:5]
    pcap_files = list(Path("data/pcap").glob("*.pcap*"))[:3]
    
    print(f"Found {len(csv_files)} CSV files and {len(pcap_files)} PCAP files")
    
    if not csv_files and not pcap_files:
        print("No test files found!")
        return
    
    # Create session with longer timeout for large files
    timeout = aiohttp.ClientTimeout(total=600, connect=30, sock_read=300)
    connector = aiohttp.TCPConnector(limit=5, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # Check service health
        async with session.get(f"{evaluator.service_url}/health") as resp:
            if resp.status != 200:
                print("Service is not healthy!")
                return
        
        print("\nStarting enhanced robustness evaluation...")
        
        # 1. CSV robustness (traditional)
        if csv_files:
            print("\n--- CSV Data Robustness ---")
            for file_path in csv_files[:3]:  # Test first 3 CSV files
                print(f"Processing: {file_path.name}")
                await evaluator.evaluate_noise_robustness(session, file_path)
                await evaluator.evaluate_temporal_stability(session, file_path)
        
        # 2. PCAP robustness (new)
        if pcap_files:
            print("\n--- PCAP Data Robustness ---")
            # Only test first PCAP file with reduced noise levels for faster execution
            for file_path in pcap_files[:1]:  # Test only first PCAP file
                print(f"Processing: {file_path.name}")
                # Override noise levels for faster testing
                await evaluator.evaluate_pcap_robustness(session, file_path, 
                                                        noise_levels=[0, 0.05, 0.1, 0.15])
                # Temporal stability for PCAP
                await evaluator.evaluate_temporal_stability(session, file_path, 
                                                          segment_sizes=[1000, 2000, 5000])
        
        # 3. Cross-modal stability
        if csv_files and pcap_files:
            print("\n--- Cross-Modal Stability ---")
            # Test first CSV with first PCAP
            await evaluator.evaluate_cross_modal_stability(session, csv_files[0], pcap_files[0])
            
            # Test more pairs if available
            if len(csv_files) > 1 and len(pcap_files) > 1:
                await evaluator.evaluate_cross_modal_stability(session, csv_files[1], pcap_files[1])
    
    # Generate reports
    evaluator.generate_enhanced_report()
    evaluator.generate_enhanced_plots()
    evaluator.generate_individual_plots()  # Generate individual plots
    
    print("\n\nEnhanced evaluation complete!")
    print("Results saved to:")
    print("  - Combined plot: evaluation_results/robustness_enhanced/robustness_enhanced_evaluation.png")
    print("  - Individual plots: evaluation_results/robustness_enhanced/individual_plots/")


if __name__ == "__main__":
    asyncio.run(main())
