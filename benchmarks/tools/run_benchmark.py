#!/usr/bin/env python3
"""
Circomspect 隐私泄露检测基准测试评估脚本

用途：
  对 benchmarks 目录下的 Circom 项目进行批量隐私泄露检测分析
  支持 'all' 和 'main' 两种分析模式
  生成多维度统计报告（项目、文件、问题类型等）

运行方法：
  python run_benchmark.py [--mode all|main|both] [--output report.csv]
  
  --mode: 分析模式，默认为 both（同时运行两种模式）
  --output: 输出文件路径，默认为 benchmark_results.csv
  --verbose: 详细输出
"""

import argparse
import subprocess
import json
import csv
import os
import sys
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from collections import defaultdict
import re

@dataclass
class AnalysisResult:
    """单个文件的分析结果"""
    project_name: str
    file_path: str
    mode: str  # 'all' 或 'main'
    has_privacy_leak: bool  # 是否存在隐私泄露（output signal被污染）
    has_quantified_leak: bool  # 是否存在量化泄露
    analysis_time: float  # 秒
    success: bool
    error_message: Optional[str] = None


class CircomspectBenchmark:
    """Circomspect 基准测试执行器"""
    
    def __init__(self, circomspect_path: Optional[str] = None, verbose: bool = False):
        """
        初始化基准测试执行器
        
        Args:
            circomspect_path: circomspect 可执行文件路径，默认使用 cargo run
            verbose: 是否输出详细信息
        """
        self.verbose = verbose
        
        # 确定 circomspect 可执行文件路径
        if circomspect_path:
            self.circomspect_cmd = [circomspect_path]
        else:
            # 使用 cargo run
            self.circomspect_cmd = ["cargo", "run", "--release", "--"]
        
        # 项目根目录
        self.root_dir = Path(__file__).parent.parent.parent
        self.benchmark_dir = self.root_dir / "benchmarks" / "projects"
        
    def find_circom_files(self, project_path: Path) -> List[Path]:
        """
        查找项目中的所有 .circom 文件
        
        Args:
            project_path: 项目目录路径
            
        Returns:
            .circom 文件路径列表
        """
        circom_files = []
        for file in project_path.rglob("*.circom"):
            # 排除 node_modules 和其他常见的排除目录
            if any(part.startswith('.') or part in ['node_modules', 'build', 'dist'] 
                   for part in file.parts):
                continue
            circom_files.append(file)
        return circom_files
    
    def parse_circomspect_output(self, output: str) -> Dict[str, bool]:
        """
        解析 circomspect 输出，检测是否存在隐私泄露
        
        Args:
            output: circomspect 的标准输出
            
        Returns:
            检测结果字典，包含是否有隐私泄露、是否有量化泄露等
        """
        # 检测是否存在隐私污点输出泄露（output signal被污染）
        privacy_leak_patterns = [
            r'Output signal.*tainted by private',
            r'output.*nullifierHash.*tainted',  # 特定匹配输出信号
            r'signal output.*tainted'
        ]
        has_privacy_leak = any(re.search(pattern, output, re.IGNORECASE) for pattern in privacy_leak_patterns)
        
        # 检测是否存在量化泄露
        quantified_leak_patterns = [
            r'QuantifiedLeakage',
            r'quantified-leakage',
            r'leaked.*bits'
        ]
        has_quantified_leak = any(re.search(pattern, output, re.IGNORECASE) for pattern in quantified_leak_patterns)
        
        return {
            'has_privacy_leak': has_privacy_leak,
            'has_quantified_leak': has_quantified_leak
        }
    
    def run_analysis(self, file_path: Path, mode: str, project_name: str) -> AnalysisResult:
        """
        对单个文件运行隐私泄露分析
        
        Args:
            file_path: .circom 文件路径
            mode: 分析模式 ('all' 或 'main')
            project_name: 项目名称
            
        Returns:
            分析结果对象
        """
        if self.verbose:
            print(f"  分析文件: {file_path.name} (模式: {mode})")
        
        # 构建命令
        cmd = self.circomspect_cmd + [str(file_path), "--mode", mode]
        
        start_time = time.time()
        
        try:
            # 运行 circomspect
            result = subprocess.run(
                cmd,
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            analysis_time = time.time() - start_time
            
            # 合并 stdout 和 stderr
            output = result.stdout + result.stderr
            
            # 解析输出
            detection_result = self.parse_circomspect_output(output)
            
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_privacy_leak=detection_result['has_privacy_leak'],
                has_quantified_leak=detection_result['has_quantified_leak'],
                analysis_time=analysis_time,
                success=True
            )
            
        except subprocess.TimeoutExpired:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_privacy_leak=False,
                has_quantified_leak=False,
                analysis_time=300.0,
                success=False,
                error_message="分析超时（>5分钟）"
            )
        except Exception as e:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_privacy_leak=False,
                has_quantified_leak=False,
                analysis_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def run_benchmark(self, modes: List[str] = ['all', 'main']) -> List[AnalysisResult]:
        """
        运行基准测试
        
        Args:
            modes: 要运行的分析模式列表
            
        Returns:
            所有分析结果列表
        """
        results = []
        
        # 查找所有项目目录
        project_dirs = [d for d in self.benchmark_dir.iterdir() 
                       if d.is_dir() and not d.name.startswith('.')]
        
        if not project_dirs:
            print("警告：benchmarks 目录下没有找到任何项目")
            return results
        
        print(f"找到 {len(project_dirs)} 个项目")
        
        for project_dir in project_dirs:
            project_name = project_dir.name
            print(f"\n{'='*60}")
            print(f"项目: {project_name}")
            print(f"{'='*60}")
            
            # 查找所有 .circom 文件
            circom_files = self.find_circom_files(project_dir)
            print(f"找到 {len(circom_files)} 个 .circom 文件")
            
            if not circom_files:
                print(f"  跳过项目 {project_name}：没有找到 .circom 文件")
                continue
            
            # 对每个文件运行分析
            for circom_file in circom_files:
                for mode in modes:
                    result = self.run_analysis(circom_file, mode, project_name)
                    results.append(result)
                    
                    if self.verbose and result.success:
                        leak_status = "有隐私泄露" if result.has_privacy_leak else "无隐私泄露"
                        print(f"    {leak_status} (用时: {result.analysis_time:.2f}秒)")
        
        return results
    
    def save_results(self, results: List[AnalysisResult], output_file: Path):
        """
        保存结果到 CSV 文件
        
        Args:
            results: 分析结果列表
            output_file: 输出文件路径
        """
        if not results:
            print("没有结果可保存")
            return
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=asdict(results[0]).keys())
            writer.writeheader()
            for result in results:
                writer.writerow(asdict(result))
        
        print(f"\n结果已保存到: {output_file}")
    
    def generate_summary_report(self, results: List[AnalysisResult]) -> str:
        """
        生成汇总报告（按模式分开统计）
        
        Args:
            results: 分析结果列表
            
        Returns:
            报告文本
        """
        if not results:
            return "没有分析结果"
        
        report_lines = []
        report_lines.append("\n" + "="*80)
        report_lines.append("Circomspect 隐私泄露检测基准测试报告")
        report_lines.append("="*80)
        
        # 按模式分组
        all_mode_results = [r for r in results if r.mode == 'all']
        main_mode_results = [r for r in results if r.mode == 'main']
        
        # 生成 ALL 模式报告
        if all_mode_results:
            report_lines.append("\n" + "="*80)
            report_lines.append("【ALL 模式分析结果】")
            report_lines.append("="*80)
            report_lines.extend(self._generate_mode_report(all_mode_results, 'ALL'))
        
        # 生成 MAIN 模式报告
        if main_mode_results:
            report_lines.append("\n" + "="*80)
            report_lines.append("【MAIN 模式分析结果】")
            report_lines.append("="*80)
            report_lines.extend(self._generate_mode_report(main_mode_results, 'MAIN'))
        
        # 模式对比
        if all_mode_results and main_mode_results:
            report_lines.append("\n" + "="*80)
            report_lines.append("【模式对比分析】")
            report_lines.append("="*80)
            report_lines.extend(self._generate_comparison_report(results))
        
        report_lines.append("\n" + "="*80)
        
        return "\n".join(report_lines)
    
    def _generate_mode_report(self, mode_results: List[AnalysisResult], mode_name: str) -> List[str]:
        """生成单个模式的报告"""
        lines = []
        
        # 总体统计
        total_files = len(set((r.project_name, r.file_path) for r in mode_results))
        total_analyses = len(mode_results)
        successful = sum(1 for r in mode_results if r.success)
        failed = total_analyses - successful
        total_time = sum(r.analysis_time for r in mode_results)
        
        # 隐私泄露统计
        files_with_privacy_leak = sum(1 for r in mode_results if r.has_privacy_leak)
        files_with_quantified_leak = sum(1 for r in mode_results if r.has_quantified_leak)
        
        lines.append("\n【总体统计】")
        lines.append(f"  分析文件数: {total_files}")
        lines.append(f"  分析次数: {total_analyses}")
        lines.append(f"  成功: {successful}, 失败: {failed}")
        lines.append(f"  总用时: {total_time:.2f} 秒")
        lines.append(f"  存在隐私泄露的文件数: {files_with_privacy_leak}")
        lines.append(f"  存在量化泄露的文件数: {files_with_quantified_leak}")
        
        # 按项目统计
        lines.append("\n【按项目统计】")
        project_stats: Dict[str, Dict] = {}
        
        for result in mode_results:
            if result.project_name not in project_stats:
                project_stats[result.project_name] = {
                    'files': set(),
                    'privacy_leak_count': 0,
                    'quantified_leak_count': 0,
                    'analysis_time': 0.0
                }
            
            stats = project_stats[result.project_name]
            stats['files'].add(result.file_path)
            if result.has_privacy_leak:
                stats['privacy_leak_count'] += 1
            if result.has_quantified_leak:
                stats['quantified_leak_count'] += 1
            stats['analysis_time'] += result.analysis_time
        
        # 按隐私泄露文件数排序
        sorted_projects = sorted(project_stats.items(), 
                                key=lambda x: x[1]['privacy_leak_count'], 
                                reverse=True)
        
        for project_name, stats in sorted_projects:
            lines.append(f"\n  项目: {project_name}")
            lines.append(f"    文件数: {len(stats['files'])}")
            lines.append(f"    存在隐私泄露的文件: {stats['privacy_leak_count']}")
            lines.append(f"    存在量化泄露的文件: {stats['quantified_leak_count']}")
            lines.append(f"    分析用时: {stats['analysis_time']:.2f} 秒")
        
        # 隐私泄露文件列表 (TOP 20)
        lines.append("\n【存在隐私泄露的文件 TOP 20】")
        leak_files = [(r.project_name, r.file_path) for r in mode_results if r.has_privacy_leak]
        
        if leak_files:
            for i, (proj, file) in enumerate(leak_files[:20], 1):
                lines.append(f"  {i}. {file}")
                lines.append(f"     项目: {proj}")
        else:
            lines.append("  未检测到隐私泄露")
        
        return lines
    
    def _generate_comparison_report(self, results: List[AnalysisResult]) -> List[str]:
        """生成模式对比报告"""
        lines = []
        
        # 按文件对比
        file_comparison = {}
        for result in results:
            key = (result.project_name, result.file_path)
            if key not in file_comparison:
                file_comparison[key] = {'all': False, 'main': False}
            file_comparison[key][result.mode] = result.has_privacy_leak
        
        # 统计差异
        only_all = sum(1 for v in file_comparison.values() if v['all'] and not v['main'])
        only_main = sum(1 for v in file_comparison.values() if not v['all'] and v['main'])
        both = sum(1 for v in file_comparison.values() if v['all'] and v['main'])
        neither = sum(1 for v in file_comparison.values() if not v['all'] and not v['main'])
        
        lines.append("\n【隐私泄露检测对比】")
        lines.append(f"  仅 ALL 模式检测到隐私泄露: {only_all} 个文件")
        lines.append(f"  仅 MAIN 模式检测到隐私泄露: {only_main} 个文件")
        lines.append(f"  两种模式都检测到: {both} 个文件")
        lines.append(f"  两种模式都未检测到: {neither} 个文件")
        
        # 列出差异文件
        if only_all > 0:
            lines.append("\n【仅 ALL 模式检测到的文件】")
            count = 0
            for (proj, file), modes in file_comparison.items():
                if modes['all'] and not modes['main']:
                    lines.append(f"  - {file} (项目: {proj})")
                    count += 1
                    if count >= 10:  # 最多显示10个
                        break
        
        if only_main > 0:
            lines.append("\n【仅 MAIN 模式检测到的文件】")
            count = 0
            for (proj, file), modes in file_comparison.items():
                if not modes['all'] and modes['main']:
                    lines.append(f"  - {file} (项目: {proj})")
                    count += 1
                    if count >= 10:
                        break
        
        return lines


def main():
    parser = argparse.ArgumentParser(
        description='Circomspect 隐私泄露检测基准测试',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--mode',
        choices=['all', 'main', 'both'],
        default='both',
        help='分析模式：all（全量），main（从main开始），both（两种都运行）'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='benchmark_results.csv',
        help='输出文件路径（CSV格式）'
    )
    
    parser.add_argument(
        '--circomspect',
        type=str,
        default=None,
        help='circomspect 可执行文件路径（默认使用 cargo run）'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='详细输出'
    )
    
    args = parser.parse_args()
    
    # 确定要运行的模式
    if args.mode == 'both':
        modes = ['all', 'main']
    else:
        modes = [args.mode]
    
    # 创建基准测试执行器
    benchmark = CircomspectBenchmark(
        circomspect_path=args.circomspect,
        verbose=args.verbose
    )
    
    print("开始基准测试...")
    print(f"分析模式: {', '.join(modes)}")
    
    # 运行基准测试
    results = benchmark.run_benchmark(modes)
    
    # 保存结果
    output_path = Path(args.output)
    benchmark.save_results(results, output_path)
    
    # 生成并显示报告
    report = benchmark.generate_summary_report(results)
    print(report)
    
    # 保存报告到文本文件
    report_path = output_path.with_suffix('.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\n报告已保存到: {report_path}")


if __name__ == '__main__':
    main()
