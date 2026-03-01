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
    full_leak_count: int   # FULL LEAK 的信号数
    partial_leak_count: int  # PARTIAL LEAK 的信号数
    leak_count: int  # 总泄露信号数 (full + partial)
    analysis_time: float  # 秒
    success: bool
    error_message: Optional[str] = None


class CircomspectBenchmark:
    """Circomspect 基准测试执行器"""
    
    def __init__(self, circomspect_path: Optional[str] = None, verbose: bool = False, outputs_dir: Optional[str] = None):
        """
        初始化基准测试执行器
        
        Args:
            circomspect_path: circomspect 可执行文件路径，默认使用 cargo run
            verbose: 是否输出详细信息
            outputs_dir: 用于保存每个文件具体分析输出的目录路径
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
        self.outputs_dir = Path(outputs_dir).resolve() if outputs_dir else None
        
        if self.outputs_dir:
            self.outputs_dir.mkdir(parents=True, exist_ok=True)

        
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

    def parse_circomspect_output(self, output: str) -> Dict:
        """
        解析 circomspect 输出，检测是否存在隐私泄露
        
        输出格式：
          warning[CS0022]: Private Input `name` has a FULL LEAK risk mapped to public outputs.
          warning[CS0022]: Private Input `name` has a PARTIAL LEAK risk mapped to public outputs.
        
        Args:
            output: circomspect 的标准输出
            
        Returns:
            检测结果字典: full_leak_count, partial_leak_count, leak_count
        """
        # 去除 ANSI 颜色代码干扰
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_output = ansi_escape.sub('', output)

        # ==========================================================
        # 统计逻辑：基于输入信号的最严重泄露 (Signal-Based Max Level)
        # ==========================================================
        # 一个信号可能同时出现 FULL LEAK 和 PARTIAL LEAK 报告，
        # 我们只记录该信号的最严重泄露级别 (FULL > PARTIAL)。
        # ==========================================================
        
        LEVEL_PARTIAL = 1
        LEVEL_FULL = 2
        
        # signal_name -> max_level
        input_levels: Dict[str, int] = defaultdict(int)
        
        # 解析 CS0022 (PrivacyGraphLeak)
        cs0022_full_pattern = r"Private Input `(.*?)` has a FULL LEAK risk"
        for match in re.finditer(cs0022_full_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            if LEVEL_FULL > input_levels[name]:
                input_levels[name] = LEVEL_FULL
        
        cs0022_partial_pattern = r"Private Input `(.*?)` has a PARTIAL LEAK risk"
        for match in re.finditer(cs0022_partial_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            if LEVEL_PARTIAL > input_levels[name]:
                input_levels[name] = LEVEL_PARTIAL
        
        # 统计
        full_leak_count = sum(1 for v in input_levels.values() if v == LEVEL_FULL)
        partial_leak_count = sum(1 for v in input_levels.values() if v == LEVEL_PARTIAL)
        total_leak_count = len(input_levels)
                
        return {
            'full_leak_count': full_leak_count,
            'partial_leak_count': partial_leak_count,
            'leak_count': total_leak_count,
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
        
        # 构建命令
        cmd = self.circomspect_cmd + [
            str(file_path), 
            "--mode", rust_mode
        ]
        
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
            
            # 如果指定了输出目录，则将详情写入日志文件
            if self.outputs_dir:
                log_dir = self.outputs_dir / project_name
                log_dir.mkdir(parents=True, exist_ok=True)
                log_file = log_dir / f"{file_path.stem}.log"
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(output)
            
            
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
                full_leak_count=detection_result['full_leak_count'],
                partial_leak_count=detection_result['partial_leak_count'],
                leak_count=detection_result['leak_count'],
                analysis_time=analysis_time,
                success=is_success,
                error_message=error_msg
            )
            
        except subprocess.TimeoutExpired:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                full_leak_count=0,
                partial_leak_count=0,
                leak_count=0,
                analysis_time=300.0,
                success=False,
                error_message="分析超时（>5分钟）"
            )
        except Exception as e:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.benchmark_dir)),
                mode=mode,
                full_leak_count=0,
                partial_leak_count=0,
                leak_count=0,
                analysis_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def run_benchmark(self, specified_mode: str = 'auto') -> List[AnalysisResult]:
        """
        运行基准测试
        
        Args:
            specified_mode: 指定的分析模式 ('auto', 'main-only', 'library-all')
            
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
                detected_mode = self.detect_mode(circom_file)
                
                # 模式1: 仅仅从 main 入口开始处理，没 main 的跳过
                if specified_mode == 'main-only' and detected_mode != 'main':
                    if not self.verbose:
                        # 更新进度条
                        leaking_files_count = sum(1 for r in results if r.project_name == project_name and r.leak_count > 0)
                        total_leak_instances = sum(r.leak_count for r in results if r.project_name == project_name)
                        progress_bar.suffix = f"完成 (风险文件: {leaking_files_count}, 风险信号: {total_leak_instances})"
                        progress_bar.print_progress(i + 1)
                    continue
                
                # 确定传递给底层引擎的具体模式
                if specified_mode == 'library-all':
                    # 模式2: 不管 main 与否都将其视为 library 进行检测
                    current_mode = 'library'
                elif specified_mode == 'main-only':
                    # 既然没被跳过，说明有 main，作为 main 传递
                    current_mode = 'main'
                else:
                    # 模式3: auto - 有 main 即 main，没有即 library
                    current_mode = detected_mode
                
                result = self.run_analysis(circom_file, current_mode, project_name)
                results.append(result)
                
                if self.verbose:
                    if result.success:
                        leak_status = "有隐私泄露" if result.leak_count > 0 else "无隐私泄露"
                        detail = f"FULL={result.full_leak_count}, PARTIAL={result.partial_leak_count}" if result.leak_count > 0 else ""
                        print(f"    [{current_mode}] {leak_status} {detail} (用时: {result.analysis_time:.2f}秒)")
                else:
                    # 更新进度条
                    leaking_files_count = sum(1 for r in results if r.project_name == project_name and r.leak_count > 0)
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
        main_mode_count = sum(1 for r in results if r.mode == 'main' or r.mode == 'main-only')
        library_mode_count = sum(1 for r in results if r.mode == 'library' or r.mode == 'library-all')
        
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        total_time = sum(r.analysis_time for r in results)
        
        lines.append("\n【总体统计】")
        lines.append(f"  总分析文件数: {total_files}")
        lines.append(f"  模式分布: Main={main_mode_count}, Library={library_mode_count}")
        lines.append(f"  运行状况: 成功={successful}, 失败={failed}")
        lines.append(f"  总用时: {total_time:.2f} 秒")
        
        files_with_leak = sum(1 for r in results if r.leak_count > 0)
        lines.append(f"  存在隐私泄露的文件数: {files_with_leak} ({files_with_leak/total_files*100:.1f}%)")
        
        total_leak_count = sum(r.leak_count for r in results)
        total_full = sum(r.full_leak_count for r in results)
        total_partial = sum(r.partial_leak_count for r in results)
        lines.append(f"  风险信号总数: {total_leak_count} (FULL LEAK: {total_full}, PARTIAL LEAK: {total_partial})")
            
        # 按项目统计
        lines.append("\n【按项目统计】")
        project_stats: Dict[str, Dict] = {}
        
        for result in results:
            if result.project_name not in project_stats:
                project_stats[result.project_name] = {
                    'files': 0,
                    'leak_files': 0,
                    'total_leak_count': 0,
                }
            
            stats = project_stats[result.project_name]
            stats['files'] += 1
            stats['total_leak_count'] += result.leak_count
            if result.leak_count > 0:
                stats['leak_files'] += 1
        
        # 按泄露文件数排序
        sorted_projects = sorted(project_stats.items(), 
                                key=lambda x: x[1]['leak_files'], 
                                reverse=True)
        
        for project_name, stats in sorted_projects:
            if stats['files'] > 0:
                proj_full = sum(r.full_leak_count for r in results if r.project_name == project_name)
                proj_partial = sum(r.partial_leak_count for r in results if r.project_name == project_name)
                
                leak_info = f"泄露文件: {stats['leak_files']}"
                leak_info += f", 风险信号: {stats['total_leak_count']} (FULL LEAK: {proj_full}, PARTIAL LEAK: {proj_partial})"
                
                lines.append(f"  - {project_name}: {stats['files']} 文件, {leak_info}")
        
        # 隐私泄露文件列表 (风险最高 TOP 30)
        lines.append("\n【存在隐私泄露的文件详情 (风险最高前30)】")
        
        # 筛选出所有有泄露的文件
        all_leaking_files = [r for r in results if r.leak_count > 0]
        
        # 排序：按 FULL LEAK > PARTIAL LEAK > 总数 降序
        all_leaking_files.sort(
            key=lambda r: (r.full_leak_count, r.partial_leak_count, r.leak_count), 
            reverse=True
        )
        
        if all_leaking_files:
            for i, r in enumerate(all_leaking_files[:30], 1):
                lines.append(f"  {i}. {r.file_path}")
                lines.append(f"     项目: {r.project_name} | 模式: {r.mode}")
                lines.append(f"     FULL LEAK: {r.full_leak_count}, PARTIAL LEAK: {r.partial_leak_count} (总信号: {r.leak_count})")
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
        choices=['auto', 'main-only', 'library-all'],
        default='auto',
        help='分析模式：\\n'
             '  auto:        (默认) 有 main 的从 main 进入，其余的视作 library 处理\\n'
             '  main-only:   仅仅从 main 入口开始处理，没 main 的不考虑也不检测\\n'
             '  library-all: 不管有无 main，强行将所有文件视为 library（检查每个中间组件）'
    )

    
    # 默认输出路径：tools 目录的上级目录 (benchmarks/)
    script_dir = Path(__file__).resolve().parent
    default_output = script_dir.parent / 'benchmark_results.csv'
    default_outputs_dir = script_dir.parent / 'benchmark_logs'
    
    parser.add_argument(
        '--output',
        type=str,
        default=str(default_output),
        help=f'输出文件路径（CSV格式），默认为: {default_output}'
    )
    
    parser.add_argument(
        '--outputs-dir',
        type=str,
        default=str(default_outputs_dir),
        help=f'保存单个 circom 文件详细输出报告的目录，默认为: {default_outputs_dir}'
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
        outputs_dir=args.outputs_dir
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
