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
    has_output_taint: bool  # 是否存在隐私泄露（output signal被污染）
    has_quantified_leak: bool  # 是否存在可量化的部分隐私泄露 (Quantified Partial Leak)
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
        
            
        # ==========================================================
        # 统计逻辑：基于输入信号的最严重泄露 (Signal-Based Max Severity)
        # ==========================================================
        # 设计原则：一个信号可能通过多条路径泄露（如bitify.circom的in信号
        # 同时有Low/High/Critical三种泄露），我们只记录该信号的最严重泄露级别。
        # 这样统计的是"有多少个信号泄露到了X级别"，而不是"发生了多少次X级别泄露"。
        #
        # 例如: signal `in` 有 Low(1 bit) + High(253 bits) + Critical(254 bits)
        # 统计结果: Critical=1 (而不是 Low=1, High=1, Critical=1)
        # ==========================================================
        
        # 定义严重程度权重
        severity_weight = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4
        }
        
        # 存储每个输入信号的最大严重程度权重 (signal_name -> max_weight)
        input_severities: Dict[str, int] = defaultdict(int)
        
        # 1. 解析 CS0021 (Quantified Leakage)
        # 格式: Private signal `name` has quantified information leakage (Severity: High, ...)
        cs0021_pattern = r"Private signal `(.*?)` has quantified information leakage \(Severity: (.*?),"
        for match in re.finditer(cs0021_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            sev_str = match.group(2).strip().capitalize()
            weight = severity_weight.get(sev_str, 0)
            
            # 只保留该信号的最大严重程度
            if weight > input_severities[name]:
                input_severities[name] = weight
                
        # 2. 解析 CS0019 (Output Taint Provenance)
        # 格式: warning: Output signal `out` is tainted by private inputs (leak level: Critical), ...
        #       Tainted by: a, b
        # 只处理 Critical 级别，因为其他级别应该已经在 CS0021 中统计
        
        cs0019_block_pattern = r"Output signal `.*?` is tainted by private inputs \(leak level: (.*?)\).*?\n.*?Tainted by:\s*([^\n]*)"
        for match in re.finditer(cs0019_block_pattern, clean_output, re.IGNORECASE | re.DOTALL):
            level_str = match.group(1).strip()
            sources_str = match.group(2).strip()
            
            # 只处理 Critical 级别的 Output Taint
            # PartialLeak 级别的 Output Taint 不应该覆盖 CS0021 计算出的 High/Medium/Low
            if level_str.lower() == "critical":
                sources = [s.strip() for s in sources_str.split(',')]
                for src in sources:
                    if src:
                        # Critical (weight=4) 会覆盖任何较低级别
                        input_severities[src] = 4
                        
        # 3. 统计最终结果：按严重程度分类计数
        severity_low = 0
        severity_medium = 0
        severity_high = 0
        severity_critical = 0
        
        for weight in input_severities.values():
            if weight == 1:
                severity_low += 1
            elif weight == 2:
                severity_medium += 1
            elif weight == 3:
                severity_high += 1
            elif weight >= 4:
                severity_critical += 1
                
        # 总泄露计数 (唯一信号数)
        total_leak_count = len(input_severities)
        
        # 兼容旧字段
        has_privacy_leak = severity_critical > 0
        has_quantified_partial_leak = total_leak_count > 0

        # 兼容性兜底：如果没有解析到任何量化信息，但检测到旧式泄露警告
        if total_leak_count == 0:
            old_privacy_leak = any(re.search(pattern, clean_output, re.IGNORECASE) for pattern in privacy_leak_patterns)
            if old_privacy_leak:
                has_privacy_leak = True
                severity_critical = 1
                total_leak_count = 1
                
        return {
            'has_output_taint': has_privacy_leak,
            'has_quantified_leak': has_quantified_partial_leak,
            'leak_count': total_leak_count,
            'severity_low': severity_low,
            'severity_medium': severity_medium,
            'severity_high': severity_high,
            'severity_critical': severity_critical
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
            
            # 判定运行是否成功：
            # 1. 退出码为 0 (无问题)
            # 2. 退出码非 0 但检测到了泄露 (因为工具发现问题时会返回非0)
            # 3. 输出中包含 "issues found." 总结 (表示分析已完成)
            
            issues_found_msg = re.search(r'\d+ issues? found\.', output)
            is_success = (result.returncode == 0) or (detection_result['leak_count'] > 0) or (issues_found_msg is not None)
            
            error_msg = None
            if not is_success:
                # 尝试提取最后几行作为错误信息
                lines = output.strip().split('\n')
                error_msg = "\n".join(lines[-3:]) if lines else "Unknown error (non-zero exit code)"
            
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                has_output_taint=detection_result['has_output_taint'],
                has_quantified_leak=detection_result['has_quantified_leak'],
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
                has_output_taint=False,
                has_quantified_leak=False,
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
                has_output_taint=False,
                has_quantified_leak=False,
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
        
        for i, project_dir in enumerate(project_dirs, 1):
            project_name = project_dir.name
            print(f"\n{'='*60}")
            print(f"项目 ({i}/{len(project_dirs)}): {project_name}")
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
                        leak_status = "有隐私泄露" if result.has_output_taint else "无隐私泄露"
                        print(f"    [{current_mode}] {leak_status} (用时: {result.analysis_time:.2f}秒)")
                else:
                    # 更新进度条
                    leaking_files_count = sum(1 for r in results if r.project_name == project_name and (r.has_output_taint or r.has_quantified_leak))
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
        privacy_leaks = [r for r in results if r.has_output_taint]
        quantified_partial_leaks = [r for r in results if r.has_quantified_leak]
        
        files_with_privacy_leak = len(privacy_leaks)
        files_with_quantified_partial_leak = len(quantified_partial_leaks)
        
        lines.append("\n【总体统计】")
        lines.append(f"  总分析文件数: {total_files}")
        lines.append(f"  模式分布: Main={main_mode_count}, Library={library_mode_count}")
        lines.append(f"  运行状况: 成功={successful}, 失败={failed}")
        lines.append(f"  总用时: {total_time:.2f} 秒")
        
        unique_issues_total = sum(1 for r in results if r.has_output_taint or r.has_quantified_leak)
        lines.append(f"  存在隐私泄露的文件数: {unique_issues_total} ({unique_issues_total/total_files*100:.1f}%)")
        
        total_leak_instances = sum(r.leak_count for r in results)
        total_severity = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for r in results:
            total_severity['Low'] += r.severity_low
            total_severity['Medium'] += r.severity_medium
            total_severity['High'] += r.severity_high
            total_severity['Critical'] += r.severity_critical

        lines.append(f"  风险信号总数: {total_leak_instances} (Low: {total_severity['Low']}, Medium: {total_severity['Medium']}, High: {total_severity['High']}, Critical(Tainted): {total_severity['Critical']})")
            
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
            if result.has_output_taint:
                stats['privacy_leak_files'] += 1
            if result.has_quantified_leak:
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
                
                # 计算两者的并集（去重后的风险文件数）
                # 注意：由于 project_stats 只是简单的计数器，没有保存文件集合，这里只能展示独立统计
                # 若要准确计算并集，需要在遍历 results 时记录
                unique_issues_count = sum(1 for r in results if r.project_name == project_name and (r.has_output_taint or r.has_quantified_leak))
                
                leak_info = f"存在隐私泄露的文件数: {unique_issues_count}"
                leak_info += f", 风险信号总数: {stats['total_leak_count']} (Low: {sev_low}, Medium: {sev_medium}, High: {sev_high}, Critical: {sev_critical})"
                
                lines.append(f"  - {project_name}: {stats['files']} 文件, {leak_info}")
        
        # 隐私泄露文件列表 (风险最高 TOP 30)
        lines.append("\n【存在隐私泄露的文件详情 (风险最高前30)】")
        
        # 筛选出所有有问题的文件
        all_leaking_files = [r for r in results if r.has_output_taint or r.has_quantified_leak]
        
        # 排序：按严重程度 Crit > High > Medium > Low > 总数 降序排列
        all_leaking_files.sort(
            key=lambda r: (r.severity_critical, r.severity_high, r.severity_medium, r.severity_low, r.leak_count), 
            reverse=True
        )
        
        if all_leaking_files:
            for i, r in enumerate(all_leaking_files[:30], 1):
                lines.append(f"  {i}. {r.file_path}")
                lines.append(f"     项目: {r.project_name} | 模式: {r.mode}")
                lines.append(f"     严重程度: Crit={r.severity_critical}, High={r.severity_high}, Med={r.severity_medium}, Low={r.severity_low} (总信号: {r.leak_count})")
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
