#!/usr/bin/env python3
"""
Circomspect 隐私泄露检测基准测试评估脚本

用途：
  对 benchmarks 目录下的 Circom 项目进行批量隐私泄露检测分析
  支持 'auto' (默认)、'main' 和 'library' 三种分析模式
  'auto' 模式会自动检测文件内容决定使用 main 还是 library 模式
  生成统一的统计报告

运行方法：
  python run_benchmark.py [--mode auto|main|library] [--output report.csv]
  
  --mode: 分析模式，默认为 auto
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

# ==========================================
# Configuration / 配置
# ==========================================
# 量化泄露阈值 (bits)：低于此值的泄露将不会被报告为 CS0021
# 设置为 1 以进行最严格的检测
LEAK_THRESHOLD = 8  
DEFAULT_MIN_SEVERITY = "Low" # 默认最小严重程度 (Low, Medium, High, Critical)
# ==========================================

class ProgressBar:
    """简单的命令行进度条"""
    def __init__(self, total: int, prefix: str = '', suffix: str = '', decimals: int = 1, length: int = 50, fill: str = '█', printEnd: str = "\r"):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.printEnd = printEnd
        self.iteration = 0
        
    def print_progress(self, iteration):
        """调用此方法以更新进度条"""
        self.iteration = iteration
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.iteration / float(self.total)))
        filledLength = int(self.length * self.iteration // self.total)
        bar = self.fill * filledLength + '-' * (self.length - filledLength)
        # 使用 \r 回到行首，而不是换行
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end=self.printEnd)
        # 如果完成，打印换行
        if self.iteration == self.total:
            print()

@dataclass
class AnalysisResult:
    """单个文件的分析结果"""
    project_name: str
    file_path: str
    mode: str  # 'main' 或 'library' (对应 rust 的 'all')
    has_privacy_leak: bool  # 是否存在隐私泄露（output signal被污染）
    has_quantified_partial_leak: bool  # 是否存在可量化的部分隐私泄露 (Quantified Partial Leak)
    leak_count: int  # 泄露发生的总次数（基于警告数量）
    severity_low: int
    severity_medium: int
    severity_high: int
    severity_critical: int
    analysis_time: float  # 秒
    success: bool
    error_message: Optional[str] = None


class CircomspectBenchmark:
    """Circomspect 基准测试执行器"""
    
    def __init__(self, circomspect_path: Optional[str] = None, verbose: bool = False, threshold: int = 8, min_severity: str = DEFAULT_MIN_SEVERITY):
        """
        初始化基准测试执行器
        
        Args:
            circomspect_path: circomspect 可执行文件路径，默认使用 cargo run
            verbose: 是否输出详细信息
        """
        self.verbose = verbose
        self.threshold = threshold
        self.min_severity = min_severity
        
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
    
    def detect_mode(self, file_path: Path) -> str:
        """
        检测文件的最佳分析模式
        
        Args:
            file_path: 文件路径
            
        Returns:
            'main' 如果检测到 main component, 否则 'library'
        """
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            # 查找 component main = ... 或 component main {...} = ...
            # 简单匹配：component\s+main\s*=
            if re.search(r'component\s+main\s*=', content):
                return 'main'
            return 'library'
        except Exception as e:
            if self.verbose:
                print(f"  无法读取文件 {file_path.name}: {e}")
            return 'library' # 默认回退到 library

    def parse_circomspect_output(self, output: str) -> Dict[str, bool]:
        """
        解析 circomspect 输出，检测是否存在隐私泄露
        
        Args:
            output: circomspect 的标准输出
            
        Returns:
            检测结果字典，包含是否有隐私泄露、是否有量化泄露等
        """
        # 去除 ANSI 颜色代码干扰
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_output = ansi_escape.sub('', output)

        # 检测是否存在隐私污点输出泄露（output signal被污染）
        privacy_leak_patterns = [
            r'Output signal.*tainted by private',
            r'output.*nullifierHash.*tainted',  # 特定匹配输出信号
            r'signal output.*tainted'
        ]
        has_privacy_leak = any(re.search(pattern, clean_output, re.IGNORECASE) for pattern in privacy_leak_patterns)
        
        # 检测是否存在量化泄露 (Quantified Partial Leak)
        quantified_leak_patterns = [
            r'quantified information leakage',
            # r'QuantifiedLeakage', # deprecated (avoids matching hint in CS0019)
            # r'leaked.*bits' # deprecated
        ]
        has_quantified_partial_leak = any(re.search(pattern, clean_output, re.IGNORECASE) for pattern in quantified_leak_patterns)
        
        # 提取严重程度统计
        # Pattern: warning[CS0021]: ... (Severity: High, ...)
        severity_pattern = r'Severity:\s*(High|Medium|Low|Critical)'
        severities = re.findall(severity_pattern, clean_output, re.IGNORECASE)
        quantified_partial_leak_severity_counts = {
            'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0
        }
        for s in severities:
            s_cap = s.capitalize()
            if s_cap in quantified_partial_leak_severity_counts:
                quantified_partial_leak_severity_counts[s_cap] += 1

        # 统计具体的泄露警告数量
        # 注意：某些情况下（如 main 模式）输出可能不带 [CSxxxx]，所以使用内容匹配更稳健
        warning_patterns = [
            r'warning(?:\[CS0019\])?: Output signal',  # Output signal is tainted
            r'warning(?:\[CS0021\])?: Private signal', # Quantified information leakage
            # r'warning(?:\[CS0020\])?: Constraint contains tainted', # Deprecated: Too noisy (internal constraints)
        ]
        
        # 统计具体的泄露警告数量
        # 为避免双重统计 (例如: 1个Input发生PartialLeak导致1个Output变脏，会同时触发CS0019和CS0021)，
        # 我们采用 max(CS0019数量, CS0021数量) 的策略来估算"风险信号总数"。
        # - Fan-in (多Input -> 单Output): CS0021 > CS0019 -> 取 CS0021 (多个秘密被泄露)
        # - Fan-out (单Input -> 多Output): CS0019 > CS0021 -> 取 CS0019 (多个出口在泄露)
        # - 1-to-1 Partial: CS0019 == CS0021 == 1 -> 取 1 (去重)
        
        count_cs0019 = len(re.findall(warning_patterns[0], clean_output, re.IGNORECASE))
        count_cs0021 = len(re.findall(warning_patterns[1], clean_output, re.IGNORECASE))
        
        total_leak_count = max(count_cs0019, count_cs0021)
        
        # 兼容性兜底：如果 regex 检测到泄露但 count 为 0
        if (has_privacy_leak or has_quantified_partial_leak) and total_leak_count == 0:
            total_leak_count = 1

        return {
            'has_privacy_leak': has_privacy_leak,
            'has_quantified_partial_leak': has_quantified_partial_leak,
            'leak_count': total_leak_count,
            'severity_low': quantified_partial_leak_severity_counts['Low'],
            'severity_medium': quantified_partial_leak_severity_counts['Medium'],
            'severity_high': quantified_partial_leak_severity_counts['High'],
            'severity_critical': quantified_partial_leak_severity_counts['Critical']
        }
    
    def run_analysis(self, file_path: Path, mode: str, project_name: str) -> AnalysisResult:
        """
        对单个文件运行隐私泄露分析
        
        Args:
            file_path: .circom 文件路径
            mode: 分析模式 ('main' 或 'library')
            project_name: 项目名称
            
        Returns:
            分析结果对象
        """
        # 将 'library' 映射为 circomspect 的 'all' 参数
        rust_mode = 'all' if mode == 'library' else mode
        
        if self.verbose:
            print(f"  分析文件: {file_path.name} (模式: {mode} -> {rust_mode})")
        
        # 构建命令 (使用 min-leak-severity 控制报告严格程度)
        cmd = self.circomspect_cmd + [
            str(file_path), 
            "--mode", rust_mode, 
            "--leak-threshold", str(self.threshold),
            "--min-leak-severity", self.min_severity
        ]
        
        start_time = time.time()
        
        try:
            # 运行 circomspect
            result = subprocess.run(
                cmd,
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                timeout=60  # 1分钟超时
            )
            
            analysis_time = time.time() - start_time
            
            # 合并 stdout 和 stderr
            output = result.stdout + result.stderr
            
            # 解析输出
            detection_result = self.parse_circomspect_output(output)
            
            is_success = (result.returncode == 0)
            error_msg = None
            if not is_success:
                # 尝试提取最后几行作为错误信息
                lines = output.strip().split('\n')
                error_msg = "\n".join(lines[-3:]) if lines else "Unknown error (non-zero exit code)"
            
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_privacy_leak=detection_result['has_privacy_leak'],
                has_quantified_partial_leak=detection_result['has_quantified_partial_leak'],
                leak_count=detection_result['leak_count'],
                severity_low=detection_result['severity_low'],
                severity_medium=detection_result['severity_medium'],
                severity_high=detection_result['severity_high'],
                severity_critical=detection_result['severity_critical'],
                analysis_time=analysis_time,
                success=is_success,
                error_message=error_msg
            )
            
        except subprocess.TimeoutExpired:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_privacy_leak=False,
                has_quantified_partial_leak=False,
                leak_count=0,
                severity_low=0,
                severity_medium=0,
                severity_high=0,
                severity_critical=0,
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
                has_quantified_partial_leak=False,
                leak_count=0,
                severity_low=0,
                severity_medium=0,
                severity_high=0,
                severity_critical=0,
                analysis_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def run_benchmark(self, specified_mode: str = 'auto') -> List[AnalysisResult]:
        """
        运行基准测试
        
        Args:
            specified_mode: 指定的分析模式 ('auto', 'main', 'library')
            
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
            
            # 准备进度条
            total_tasks = len(circom_files)
            if not self.verbose:
                progress_bar = ProgressBar(total_tasks, prefix='进度:', suffix='完成', length=40)
                progress_bar.print_progress(0)
            
            # 对每个文件运行分析
            for i, circom_file in enumerate(circom_files):
                # 确定当前文件的分析模式
                current_mode = specified_mode
                if current_mode == 'auto':
                    current_mode = self.detect_mode(circom_file)
                
                result = self.run_analysis(circom_file, current_mode, project_name)
                results.append(result)
                
                if self.verbose:
                    if result.success:
                        leak_status = "有隐私泄露" if result.has_privacy_leak else "无隐私泄露"
                        print(f"    [{current_mode}] {leak_status} (用时: {result.analysis_time:.2f}秒)")
                else:
                    # 更新进度条
                    leaking_files_count = sum(1 for r in results if r.project_name == project_name and r.has_privacy_leak)
                    total_leak_instances = sum(r.leak_count for r in results if r.project_name == project_name)
                    progress_bar.suffix = f"完成 (风险文件: {leaking_files_count}, 风险信号: {total_leak_instances})"
                    progress_bar.print_progress(i + 1)
        
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
        
        # Prepare data for CSV writing
        fieldnames = asdict(results[0]).keys()
        csv_data = [asdict(result) for result in results]

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for data in csv_data:
                    writer.writerow(data)
            print(f"\n结果已保存至: {output_file}")
        except PermissionError:
            # 如果文件被占用（如被 Excel 打开），尝试保存到带有时间戳的新文件
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fallback_file = Path(output_file).parent / f"benchmark_results_{timestamp}.csv"
            print(f"\n[错误] 无法写入 {output_file}，文件可能被占用。")
            print(f"尝试保存至新文件: {fallback_file}")
            
            with open(fallback_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for data in csv_data:
                    writer.writerow(data)
            print(f"结果已成功保存至: {fallback_file}")
        except Exception as e:
            print(f"\n[错误] 保存结果时发生错误: {e}")
    
    def generate_summary_report(self, results: List[AnalysisResult]) -> str:
        """
        生成统一的汇总报告
        
        Args:
            results: 分析结果列表
            
        Returns:
            报告文本
        """
        if not results:
            return "没有分析结果"
        
        lines = []
        lines.append("\n" + "="*80)
        lines.append("Circomspect 隐私泄露检测基准测试报告")
        lines.append("="*80)
        
        # 总体统计
        total_files = len(results)
        main_mode_count = sum(1 for r in results if r.mode == 'main')
        library_mode_count = sum(1 for r in results if r.mode == 'library')
        
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        total_time = sum(r.analysis_time for r in results)
        
        # 隐私泄露统计
        privacy_leaks = [r for r in results if r.has_privacy_leak]
        quantified_partial_leaks = [r for r in results if r.has_quantified_partial_leak]
        
        files_with_privacy_leak = len(privacy_leaks)
        files_with_quantified_partial_leak = len(quantified_partial_leaks)
        
        lines.append("\n【总体统计】")
        lines.append(f"  总分析文件数: {total_files}")
        lines.append(f"  模式分布: Main={main_mode_count}, Library={library_mode_count}")
        lines.append(f"  运行状况: 成功={successful}, 失败={failed}")
        lines.append(f"  总用时: {total_time:.2f} 秒")
        lines.append(f"  有隐私泄露风险的文件数: {files_with_privacy_leak} ({files_with_privacy_leak/total_files*100:.1f}%)")
        lines.append(f"  含可量化部分泄露问题(Quantified Partial Leak)的文件数: {files_with_quantified_partial_leak}")
        
        total_leak_instances = sum(r.leak_count for r in results)
        total_severity = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for r in results:
            total_severity['Low'] += r.severity_low
            total_severity['Medium'] += r.severity_medium
            total_severity['High'] += r.severity_high
            total_severity['Critical'] += r.severity_critical

        lines.append(f"  有隐私泄露风险的信号总数: {total_leak_instances} ( 可量化的部分泄露按级别计数——Low: {total_severity['Low']}, Medium: {total_severity['Medium']}, High: {total_severity['High']}, Critical: {total_severity['Critical']})")
            
        # 按项目统计
        lines.append("\n【按项目统计】")
        project_stats: Dict[str, Dict] = {}
        
        for result in results:
            if result.project_name not in project_stats:
                project_stats[result.project_name] = {
                    'files': 0,
                    'privacy_leak_files': 0,
                    'total_leak_count': 0,
                    'quantified_partial_leak_files': 0,
                    'last_mode': result.mode
                }
            
            stats = project_stats[result.project_name]
            stats['files'] += 1
            stats['total_leak_count'] += result.leak_count
            if result.has_privacy_leak:
                stats['privacy_leak_files'] += 1
            if result.has_quantified_partial_leak:
                stats['quantified_partial_leak_files'] += 1
        
        # 按隐私泄露文件数排序
        sorted_projects = sorted(project_stats.items(), 
                                key=lambda x: x[1]['privacy_leak_files'], 
                                reverse=True)
        
        for project_name, stats in sorted_projects:
            # 只显示有问题或者文件数>0的项目
            if stats['files'] > 0:
                sev_low = sum(r.severity_low for r in results if r.project_name == project_name)
                sev_medium = sum(r.severity_medium for r in results if r.project_name == project_name)
                sev_high = sum(r.severity_high for r in results if r.project_name == project_name)
                sev_critical = sum(r.severity_critical for r in results if r.project_name == project_name)
                
                leak_info = f"有隐私泄露风险的文件数: {stats['privacy_leak_files']}"
                if stats['quantified_partial_leak_files'] > 0:
                    leak_info += f"（含可量化部分泄露问题的文件: {stats['quantified_partial_leak_files']}）"

                leak_info += f", 有隐私泄露风险的信号总数: {stats['total_leak_count']} ( 可量化的部分泄露按级别计数——Low: {sev_low}, Medium: {sev_medium}, High: {sev_high}, Critical: {sev_critical})"
                
                lines.append(f"  - {project_name}: {stats['files']} 文件, {leak_info}")
        
        # 隐私泄露文件列表 (TOP 20)
        lines.append("\n【存在隐私泄露的文件详情 (前30)】")
        
        if privacy_leaks:
            for i, r in enumerate(privacy_leaks[:30], 1):
                lines.append(f"  {i}. {r.file_path}")
                lines.append(f"     项目: {r.project_name} | 模式: {r.mode}")
        else:
            lines.append("  未检测到隐私泄露")
        
        lines.append("\n" + "="*80)
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Circomspect 隐私泄露检测基准测试',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--mode',
        choices=['auto', 'main', 'library'],
        default='auto',
        help='分析模式：auto（自动检测，默认），main（强制Main模式），library（强制Library模式）'
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=LEAK_THRESHOLD,
        help=f'量化泄露阈值（默认：{LEAK_THRESHOLD}，配置于脚本头部）'
    )
    parser.add_argument(
        '--min-severity',
        default=DEFAULT_MIN_SEVERITY,
        choices=["Low", "Medium", "High", "Critical"],
        help=f"最小报告严重程度 (默认: {DEFAULT_MIN_SEVERITY})"
    )
    
    # 默认输出路径：tools 目录的上级目录 (benchmarks/)
    script_dir = Path(__file__).resolve().parent
    default_output = script_dir.parent / 'benchmark_results.csv'
    
    parser.add_argument(
        '--output',
        type=str,
        default=str(default_output),
        help=f'输出文件路径（CSV格式），默认为: {default_output}'
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
    
    parser.add_argument(
        '--projects-dir',
        type=str,
        default=None,
        help='指定要测试的项目集所在路径 (默认: benchmarks/projects)'
    )
    
    args = parser.parse_args()
    
    # 创建基准测试执行器
    benchmark = CircomspectBenchmark(
        circomspect_path=args.circomspect,
        verbose=args.verbose,
        threshold=args.threshold,
        min_severity=args.min_severity
    )

    # 如果指定了 --projects-dir, 覆盖默认的 benchmark_dir
    if args.projects_dir:
        benchmark.benchmark_dir = Path(args.projects_dir).resolve()
        if not benchmark.benchmark_dir.exists():
            print(f"错误: 指定的项目目录不存在: {benchmark.benchmark_dir}")
            sys.exit(1)
    
    print("开始基准测试...")
    print(f"设定模式: {args.mode}")
    print(f"项目目录: {benchmark.benchmark_dir}")
    
    # 运行基准测试
    results = benchmark.run_benchmark(args.mode)
    
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
