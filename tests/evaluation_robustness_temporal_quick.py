#!/usr/bin/env python3
"""
CPAG鲁棒性和时序稳定性评估框架 - 快速测试版本
用于快速验证功能，减少测试时间
"""

import asyncio
from pathlib import Path
import sys

# 导入主评估器
sys.path.append(str(Path(__file__).parent))
from evaluation_robustness_temporal import RobustnessTemporalEvaluator


async def main():
    """主函数 - 快速测试版本"""
    print("CPAG Robustness Evaluation - Quick Test")
    print("=" * 60)
    
    # 创建评估器
    evaluator = RobustnessTemporalEvaluator()
    
    # 只使用1个文件进行快速测试
    test_files = list(Path("data/csv").glob("*.csv"))[:1]
    
    if not test_files:
        print("No test files found!")
        return
    
    print(f"Quick test with: {test_files[0].name}")
    
    import aiohttp
    async with aiohttp.ClientSession() as session:
        # 检查服务健康
        try:
            async with session.get(f"{evaluator.service_url}/health") as resp:
                if resp.status != 200:
                    print("⚠️ Service is not healthy! Status:", resp.status)
                else:
                    print("✅ Service is healthy")
        except Exception as e:
            print(f"❌ Cannot connect to service: {e}")
            return
        
        # 1. 快速噪声测试（只测试少量噪声级别）
        print("\n1. Testing noise robustness (simplified)...")
        try:
            await evaluator.evaluate_noise_robustness(
                session, test_files[0], 
                noise_levels=[0.0, 0.1, 0.2]  # 只测试3个级别
            )
            print("✅ Noise robustness test completed")
        except Exception as e:
            print(f"❌ Noise test failed: {e}")
            import traceback
            traceback.print_exc()
        
        # 2. 快速时序稳定性测试
        print("\n2. Testing temporal stability (simplified)...")
        try:
            await evaluator.evaluate_temporal_stability(
                session, test_files[0],
                segment_sizes=[500, 1000]  # 只测试2个分段大小
            )
            print("✅ Temporal stability test completed")
        except Exception as e:
            print(f"❌ Temporal test failed: {e}")
            import traceback
            traceback.print_exc()
        
        # 3. 快速概念漂移测试（可选）
        print("\n3. Testing concept drift (optional)...")
        try:
            # 只测试一种漂移类型
            evaluator.results['concept_drift'] = []  # 清空之前的结果
            
            import pandas as pd
            df = pd.read_csv(test_files[0])
            
            # 获取基准CPAG
            baseline_units = await evaluator._generate_cpag(session, test_files[0], df)
            if baseline_units:
                # 只测试渐变漂移
                df_drift = evaluator.simulate_concept_drift(df, 'gradual', 0.1)
                drift_units = await evaluator._generate_cpag(session, test_files[0], df_drift)
                
                if drift_units:
                    adaptation_metrics = evaluator._analyze_drift_adaptation(
                        baseline_units, drift_units, 'gradual'
                    )
                    
                    evaluator.results['concept_drift'].append({
                        'file': test_files[0].name,
                        'drift_type': 'gradual',
                        'drift_magnitude': 0.1,
                        **adaptation_metrics
                    })
                    print("✅ Concept drift test completed")
        except Exception as e:
            print(f"⚠️ Concept drift test skipped: {e}")
    
    # 生成简化报告
    print("\n" + "="*60)
    print("Quick Test Summary")
    print("="*60)
    
    # 噪声鲁棒性
    if evaluator.results['noise_robustness']:
        noise_results = evaluator.results['noise_robustness']
        print(f"\nNoise Robustness: {len(noise_results)} tests completed")
        
        # 计算平均相似度
        avg_similarity = sum(r.get('unit_similarity', 0) for r in noise_results) / len(noise_results)
        print(f"  Average unit similarity: {avg_similarity:.3f}")
    
    # 时序稳定性
    if evaluator.results['temporal_stability']:
        temporal_results = evaluator.results['temporal_stability']
        print(f"\nTemporal Stability: {len(temporal_results)} tests completed")
        
        for result in temporal_results:
            print(f"  Segment size {result['segment_size']}: "
                  f"consistency = {result['avg_consistency']:.3f}")
    
    # 概念漂移
    if evaluator.results['concept_drift']:
        drift_results = evaluator.results['concept_drift']
        print(f"\nConcept Drift: {len(drift_results)} tests completed")
        
        for result in drift_results:
            print(f"  {result['drift_type']} drift: "
                  f"adaptation score = {result.get('adaptation_score', 0):.3f}")
    
    print("\n✅ Quick test complete!")
    print("\nFor full evaluation, run: python evaluation_robustness_temporal.py")


if __name__ == "__main__":
    asyncio.run(main())

