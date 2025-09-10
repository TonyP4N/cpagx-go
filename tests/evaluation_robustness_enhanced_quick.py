#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluation_robustness_enhanced_quick.py
---------------------------------------
Quick version of enhanced robustness evaluation for faster testing.
"""

import asyncio
from pathlib import Path
from evaluation_robustness_enhanced import EnhancedRobustnessEvaluator


async def main():
    """Quick test with limited files and parameters"""
    print("Enhanced CPAG Robustness Evaluation (Quick Test)")
    print("=" * 60)
    
    evaluator = EnhancedRobustnessEvaluator()
    
    # Use only 1-2 files for quick testing
    csv_files = list(Path("data/csv").glob("*.csv"))[:1]
    pcap_files = list(Path("data/pcap").glob("*.pcap*"))[:1]
    
    print(f"Quick test with {len(csv_files)} CSV and {len(pcap_files)} PCAP files")
    
    if not csv_files and not pcap_files:
        print("No test files found!")
        return
    
    # Create aiohttp session
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=300)
    connector = aiohttp.TCPConnector(limit=5, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # Quick noise levels
        quick_noise_levels = [0.0, 0.1, 0.2]
        
        # CSV robustness
        if csv_files:
            print(f"\nTesting CSV: {csv_files[0].name}")
            await evaluator.evaluate_noise_robustness(
                session, csv_files[0], 
                noise_levels=quick_noise_levels
            )
        
        # PCAP robustness
        if pcap_files:
            print(f"\nTesting PCAP: {pcap_files[0].name}")
            await evaluator.evaluate_pcap_robustness(
                session, pcap_files[0],
                noise_levels=quick_noise_levels
            )
        
        # Cross-modal if both available
        if csv_files and pcap_files:
            print("\nTesting cross-modal stability...")
            await evaluator.evaluate_cross_modal_stability(
                session, csv_files[0], pcap_files[0]
            )
    
    # Generate reports
    evaluator.generate_enhanced_report()
    evaluator.generate_enhanced_plots()
    evaluator.generate_individual_plots()  # Generate individual plots
    
    print("\nQuick test complete!")
    print("Results saved to:")
    print("  - Combined plot: evaluation_results/robustness_enhanced/robustness_enhanced_evaluation.png")
    print("  - Individual plots: evaluation_results/robustness_enhanced/individual_plots/")


if __name__ == "__main__":
    asyncio.run(main())
