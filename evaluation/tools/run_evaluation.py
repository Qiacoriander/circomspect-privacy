#!/usr/bin/env python3
"""
3: Circomspect 隐私泄露评估脚本
4: 
5: 用途：
6:   对 evaluation_projects 目录下的 Circom 项目进行批量隐私泄露检测分析
7:   支持 'auto'、'main-only' (默认) 和 'library-all' 三种分析模式
8:   生成统一的统计报告
9: 
10: 运行方法：
11:   python run_evaluation.py [--mode auto|main-only|library-all]
12:   
13:   --mode: 分析模式，默认为 main-only
  --output: 输出文件路径，默认为 evaluation_results.csv
  --verbose: 详细输出
"""

import argparse
import subprocess
import json
import csv
import os
import sys
import signal
import time
from pathlib import Path
from dataclasses import dataclass, asdict, fields
from typing import List, Dict, Optional, Set
from collections import defaultdict
import re
import datetime

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
    has_main: bool # 测试文件内部是否包含可作为入口的 component main
    public_inputs_count: int # 该入口显式声明的 public 信号数量，-1表示无main
    full_leak_count: int   # FULL LEAK 的信号数
    partial_leak_count: int  # PARTIAL LEAK 的信号数
    cascade_leak_count: int # 级联泄露 (Relational De-blinding) 的信号数
    leak_count: int  # 总泄露信号数 (full + partial)
    analysis_time: float  # 秒
    success: bool
    error_message: Optional[str] = None


class CircomspectEvaluation:
    """Circomspect 评估测试执行器"""
    
    def __init__(self, circomspect_path: Optional[str] = None, verbose: bool = False, outputs_dir: Optional[str] = None, save_logs: bool = False,
                 csv_output_path: Optional[Path] = None, resumed_projects: Optional[Set[str]] = None, max_files_per_project: int = 0):
        """
        初始化评估测试执行器
        
        Args:
            circomspect_path: circomspect 可执行文件路径，默认使用 cargo run
            verbose: 是否输出详细信息
            outputs_dir: 用于保存每个文件具体分析输出的目录路径
            save_logs: 是否保存分析过程详细日志到 outputs_dir 中
            csv_output_path: CSV 结果文件路径，用于增量写入
            resumed_projects: 已完成的项目名称集合（断点续传时跳过）
            max_files_per_project: 每个项目最多检测的文件数（0=不限制）
        """
        self.verbose = verbose
        self.save_logs = save_logs
        self.csv_output_path = csv_output_path
        self.resumed_projects = resumed_projects or set()
        self.max_files_per_project = max_files_per_project
        
        # 优雅中断标志
        self._interrupted = False
        self._interrupt_count = 0
        self._current_process = None  # 当前正在运行的子进程引用
        self._original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_sigint)
        
        # 确定 circomspect 可执行文件路径
        if circomspect_path:
            self.circomspect_cmd = [circomspect_path]
        else:
            # 使用 cargo run
            self.circomspect_cmd = ["cargo", "run", "--release", "--"]
        
        # 项目根目录
        self.root_dir = Path(__file__).parent.parent.parent
        self.evaluation_dir = self.root_dir / "evaluation" / "evaluation_projects"
        self.outputs_dir = Path(outputs_dir).resolve() if outputs_dir else None
        
        if self.outputs_dir:
            self.outputs_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化 CSV 增量写入（写入 header）
        self._csv_header_written = False
        if self.csv_output_path and not self.resumed_projects:
            # 全新运行：创建文件并写入 header
            self._init_csv_header()
    
    def _handle_sigint(self, signum, frame):
        """处理 Ctrl+C 信号：立即终止当前子进程，丢弃当前项目数据，保留已完成项目"""
        self._interrupt_count += 1
        if self._interrupt_count == 1:
            self._interrupted = True
            print("\n\n⚠️  收到中断信号，正在终止当前检测进程...")
            print("   当前项目的数据将被丢弃，已完成项目的数据不受影响。")
            print("   （再次按 Ctrl+C 可强制退出）")
            # 立即杀死正在运行的子进程
            if self._current_process and self._current_process.poll() is None:
                try:
                    self._current_process.kill()
                except Exception:
                    pass
        else:
            print("\n强制退出。")
            signal.signal(signal.SIGINT, self._original_sigint)
            sys.exit(1)
    
    def _init_csv_header(self):
        """创建 CSV 文件并写入表头"""
        if self.csv_output_path:
            self.csv_output_path.parent.mkdir(parents=True, exist_ok=True)
            fieldnames = [f.name for f in fields(AnalysisResult)]
            with open(self.csv_output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
            self._csv_header_written = True
    
    def _flush_project_results(self, project_results: List[AnalysisResult]):
        """将一个项目的结果增量追加到 CSV 文件"""
        if not self.csv_output_path or not project_results:
            return
        
        fieldnames = [f.name for f in fields(AnalysisResult)]
        
        # 如果是 resume 模式且 header 尚未写入，检查文件是否已有内容
        if not self._csv_header_written:
            if not self.csv_output_path.exists() or self.csv_output_path.stat().st_size == 0:
                with open(self.csv_output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
            self._csv_header_written = True
        
        try:
            with open(self.csv_output_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                for result in project_results:
                    writer.writerow(asdict(result))
        except Exception as e:
            print(f"\n[警告] 增量写入 CSV 失败: {e}")

        
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
            # 排除 node_modules, circomlib 和其他常见的排除目录
            if any(part.startswith('.') or part in ['node_modules', 'circomlib', 'build', 'dist'] 
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

        # 解析主入口信息：circomspect: 从 main component 'XXX' 开始分析，公开输入：[YYY]
        has_main = False
        public_inputs_count = -1
        
        main_info_pattern = r"从 main component '.*?' 开始分析，公开输入：\[(.*?)\]"
        main_match = re.search(main_info_pattern, clean_output)
        if main_match:
            has_main = True
            pub_str = main_match.group(1).strip()
            if not pub_str:
                public_inputs_count = 0
            else:
                # 统计逗号分隔的数量
                public_inputs_count = len(pub_str.split(','))

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
        
        cs0022_full_pattern = r"Private Input `(.*?)` has a FULL LEAK"
        for match in re.finditer(cs0022_full_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            # 排除带有 de-blinding 的，以免重复被计算两次到全泄漏逻辑里，我们会单独统计
            if "(Relational De-blinding)" not in match.group(0):
                if LEVEL_FULL > input_levels[name]:
                    input_levels[name] = LEVEL_FULL
        
        # 统计级联泄漏 (Relational De-blinding)
        cascade_levels: Dict[str, int] = defaultdict(int)
        cs0022_cascade_pattern = r"Private Input `(.*?)` has a FULL LEAK \(Relational De-blinding\)"
        for match in re.finditer(cs0022_cascade_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            # 级联泄漏同样属于严重泄漏
            input_levels[name] = LEVEL_FULL
            cascade_levels[name] = 1
        
        cs0022_partial_pattern = r"Private Input `(.*?)` has a PARTIAL LEAK risk"
        for match in re.finditer(cs0022_partial_pattern, clean_output, re.IGNORECASE):
            name = match.group(1)
            if LEVEL_PARTIAL > input_levels[name]:
                input_levels[name] = LEVEL_PARTIAL
        
        # 统计
        # Cascade本质上是FULL LEAK的一种，因此 FULL LEAK 的总数应当包含 cascade_levels
        # 我们把它们加总，使得 FULL LEAK = 直接 FULL + 级联 FULL
        full_leak_count = sum(1 for v in input_levels.values() if v == LEVEL_FULL)
        partial_leak_count = sum(1 for v in input_levels.values() if v == LEVEL_PARTIAL)
        cascade_leak_count = len(cascade_levels)
        total_leak_count = len(input_levels)
                
        
        return {
            'has_main': has_main,
            'public_inputs_count': public_inputs_count,
            'full_leak_count': full_leak_count,
            'partial_leak_count': partial_leak_count,
            'cascade_leak_count': cascade_leak_count,
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
            # 运行 circomspect（使用 Popen 以便支持中断时立即杀死）
            proc = subprocess.Popen(
                cmd,
                cwd=self.root_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._current_process = proc
            try:
                stdout, stderr = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            finally:
                self._current_process = None
            
            # 如果在等待过程中被中断了，直接抛出异常
            if self._interrupted:
                raise InterruptedError("用户中断")
            
            result = subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
            
            analysis_time = time.time() - start_time
            
            # 合并 stdout 和 stderr
            output = result.stdout + result.stderr
            
            # 如果指定了输出目录且开启了保存日志，则将详情写入日志文件
            if self.outputs_dir and self.save_logs:
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
                file_path=str(file_path.relative_to(self.evaluation_dir)),
                mode=mode,
                has_main=detection_result['has_main'],
                public_inputs_count=detection_result['public_inputs_count'],
                full_leak_count=detection_result['full_leak_count'],
                partial_leak_count=detection_result['partial_leak_count'],
                cascade_leak_count=detection_result['cascade_leak_count'],
                leak_count=detection_result['leak_count'],
                analysis_time=analysis_time,
                success=is_success,
                error_message=error_msg
            )
            
        except subprocess.TimeoutExpired:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.evaluation_dir)),
                mode=mode,
                has_main=False,
                public_inputs_count=-1,
                full_leak_count=0,
                partial_leak_count=0,
                cascade_leak_count=0,
                leak_count=0,
                analysis_time=120.0,
                success=False,
                error_message="分析超时（>2分钟）"
            )
        except Exception as e:
            return AnalysisResult(
                project_name=project_name,
                file_path=str(file_path.relative_to(self.evaluation_dir)),
                mode=mode,
                has_main=False,
                public_inputs_count=-1,
                full_leak_count=0,
                partial_leak_count=0,
                cascade_leak_count=0,
                leak_count=0,
                analysis_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def run_evaluation(self, specified_mode: str = 'auto') -> List[AnalysisResult]:
        """
        运行基准测试（支持增量持久化、优雅中断、断点续传）
        
        Args:
            specified_mode: 指定的分析模式 ('auto', 'main-only', 'library-all')
            
        Returns:
            所有分析结果列表
        """
        results = []
        
        # 查找所有项目目录
        project_dirs = sorted([d for d in self.evaluation_dir.iterdir() 
                       if d.is_dir() and not d.name.startswith('.')])
        
        if not project_dirs:
            print("警告：benchmarks 目录下没有找到任何项目")
            return results
        
        skipped_resume = len(self.resumed_projects)
        total_projects = len(project_dirs)
        if skipped_resume > 0:
            print(f"找到 {total_projects} 个项目（其中 {skipped_resume} 个已有结果，将跳过）")
        else:
            print(f"找到 {total_projects} 个项目")
        
        completed_count = 0
        for i, project_dir in enumerate(project_dirs, 1):
            # 检查中断标志
            if self._interrupted:
                print(f"\n🛑 中断信号已接收，停止处理后续项目（已完成 {completed_count} 个项目）")
                break
            
            project_name = project_dir.name
            
            # 断点续传：跳过已完成的项目
            if project_name in self.resumed_projects:
                if self.verbose:
                    print(f"  ⏭️  跳过已完成项目: {project_name}")
                continue
            
            print(f"\n{'='*60}")
            print(f"项目 ({i}/{total_projects}): {project_name}")
            print(f"{'='*60}")
            
            # 查找所有 .circom 文件
            circom_files = self.find_circom_files(project_dir)
            original_count = len(circom_files)
            print(f"找到 {original_count} 个 .circom 文件")
            
            if not circom_files:
                print(f"  跳过项目 {project_name}：没有找到 .circom 文件")
                continue
            
            # 准备进度条
            total_tasks = len(circom_files)
            if not self.verbose:
                progress_bar = ProgressBar(total_tasks, prefix='进度:', suffix='完成', length=40)
                progress_bar.print_progress(0)
            
            # 当前项目的结果
            project_results = []
            
            # 对每个文件运行分析
            for j, circom_file in enumerate(circom_files):
                # 检查中断标志：立即停止，丢弃当前项目数据
                if self._interrupted:
                    print(f"\n  🛑 中断信号：丢弃项目 {project_name} 的未完成数据")
                    project_results.clear()
                    break
                
                detected_mode = self.detect_mode(circom_file)
                
                # 模式1: 仅仅从 main 入口开始处理，没 main 的跳过
                if specified_mode == 'main-only' and detected_mode != 'main':
                    if not self.verbose:
                        # 更新进度条
                        leaking_files_count = sum(1 for r in project_results if r.leak_count > 0)
                        total_leak_instances = sum(r.leak_count for r in project_results)
                        progress_bar.suffix = f"完成 (风险文件: {leaking_files_count}, 风险信号: {total_leak_instances})"
                        progress_bar.print_progress(j + 1)
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
                
                try:
                    result = self.run_analysis(circom_file, current_mode, project_name)
                except (InterruptedError, KeyboardInterrupt):
                    # 被中断：丢弃当前项目所有数据
                    print(f"\n  🛑 检测中断：丢弃项目 {project_name} 的全部数据")
                    # 从全局 results 中移除该项目已有的结果
                    results = [r for r in results if r.project_name != project_name]
                    project_results.clear()
                    break
                
                project_results.append(result)
                results.append(result)
                
                if self.verbose:
                    if result.success:
                        leak_status = "有隐私泄露" if result.leak_count > 0 else "无隐私泄露"
                        # 格式优化：由于 CASCADE 属于 FULL 的一种特殊情况，因此在括号内注明即可
                        cascade_info = f" (含 CASCADE={result.cascade_leak_count})" if result.cascade_leak_count > 0 else ""
                        detail = f"FULL={result.full_leak_count}{cascade_info}, PARTIAL={result.partial_leak_count}" if result.leak_count > 0 else ""
                        print(f"    [{current_mode}] {leak_status} {detail} (用时: {result.analysis_time:.2f}秒)")
                else:
                    # 更新进度条
                    leaking_files_count = sum(1 for r in project_results if r.leak_count > 0)
                    total_leak_instances = sum(r.leak_count for r in project_results)
                    progress_bar.suffix = f"完成 (风险文件: {leaking_files_count}, 风险信号: {total_leak_instances})"
                    progress_bar.print_progress(j + 1)
            
            # ✅ 每完成一个项目，立即增量写入 CSV
            if project_results:
                self._flush_project_results(project_results)
                completed_count += 1
                print(f"  💾 项目 {project_name} 的 {len(project_results)} 条结果已保存")
        
        if self._interrupted:
            print(f"\n📊 评估因中断而提前结束，共完成 {completed_count} 个项目的分析")
        
        return results
    
    def save_results(self, results: List[AnalysisResult], output_file: Path):
        """
        保存结果到 CSV 文件（注意：增量模式下结果已经在 run_evaluation 中逐项目写入了）
        
        Args:
            results: 分析结果列表
            output_file: 输出文件路径
        """
        if not results:
            print("没有结果可保存")
            return
        
        # 如果已经通过增量模式写入了，只需确认
        if self.csv_output_path and self.csv_output_path == output_file:
            print(f"\n结果已增量保存至: {output_file}")
            return
        
        # 兜底：非增量模式下的完整写入
        fieldnames = [f.name for f in fields(AnalysisResult)]
        csv_data = [asdict(result) for result in results]

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for data in csv_data:
                    writer.writerow(data)
            print(f"\n结果已保存至: {output_file}")
        except PermissionError:
            import datetime
            timestamp = datetime.datetime.now().strftime("%m%d_%H%M")
            fallback_file = Path(output_file).parent / f"evaluation_results_{timestamp}.csv"
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
        lines.append("Circomspect 隐私泄露评估测试报告")
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
        
        # main入口及公开输入分析
        actual_mains = sum(1 for r in results if r.has_main)
        mains_with_public_inputs = sum(1 for r in results if r.has_main and r.public_inputs_count > 0)
        lines.append(f"  实际被作为 main 入口分析的文件数: {actual_mains}")
        if actual_mains > 0:
            lines.append(f"    其中显式指定了 public 信号的占比: {mains_with_public_inputs}/{actual_mains} ({mains_with_public_inputs/actual_mains*100:.1f}%)")
        
        files_with_leak = sum(1 for r in results if r.leak_count > 0)
        lines.append(f"  存在隐私泄露的文件数: {files_with_leak} ({files_with_leak/total_files*100:.1f}%)")
        
        total_leak_count = sum(r.leak_count for r in results)
        total_full = sum(r.full_leak_count for r in results)
        total_partial = sum(r.partial_leak_count for r in results)
        total_cascade = sum(r.cascade_leak_count for r in results)
        
        cascade_summary = f" (其中包含 CASCADE 级联泄露: {total_cascade})" if total_cascade > 0 else ""
        lines.append(f"  风险信号总数: {total_leak_count} (FULL LEAK: {total_full}{cascade_summary}, PARTIAL LEAK: {total_partial})")
            
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
                proj_cascade = sum(r.cascade_leak_count for r in results if r.project_name == project_name)
                
                cascade_str = f" [含 CASCADE: {proj_cascade}]" if proj_cascade > 0 else ""
                leak_info = f"泄露文件: {stats['leak_files']}"
                leak_info += f", 风险信号: {stats['total_leak_count']} (FULL: {proj_full}{cascade_str}, PARTIAL: {proj_partial})"
                
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
                cascade_str = f" (含 CASCADE: {r.cascade_leak_count})" if r.cascade_leak_count > 0 else ""
                lines.append(f"     FULL: {r.full_leak_count}{cascade_str}, PARTIAL: {r.partial_leak_count} (总信号: {r.leak_count})")
        else:
            lines.append("  未检测到隐私泄露")
        
        lines.append("\n" + "="*80)
        
        return "\n".join(lines)


def _load_resumed_projects(csv_path: Path) -> Set[str]:
    """从已有的 CSV 文件中读取已完成的项目名称集合"""
    completed = set()
    if csv_path.exists() and csv_path.stat().st_size > 0:
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'project_name' in row:
                        completed.add(row['project_name'])
        except Exception as e:
            print(f"[警告] 读取已有 CSV 文件失败: {e}，将从头开始")
    return completed


def main():
    parser = argparse.ArgumentParser(
        description='Circomspect 隐私泄露检测基准测试',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--mode',
        choices=['auto', 'main-only', 'library-all'],
        default='main-only',
        help='分析模式：\\n'
             '  main-only:   (默认) 仅仅从 main 入口开始处理，没 main 的不考虑也不检测\\n'
             '  auto:        有 main 的从 main 进入，其余的视作 library 处理\\n'
             '  library-all: 不管有无 main，强行将所有文件视为 library（检查每个中间组件）'
    )
    
    timestamp_str = datetime.datetime.now().strftime("%m%d_%H%M")

    # 默认输出路径：tools 目录的上级目录 
    script_dir = Path(__file__).resolve().parent
    default_output = script_dir.parent / 'evaluation_results' / f'evaluation_results_{timestamp_str}.csv'
    default_outputs_dir = script_dir.parent / 'evaluation_logs' / f'evaluation_logs_{timestamp_str}'
    
    parser.add_argument(
        '--save-logs',
        action='store_true',
        help='是否保存具体的单个文件分析日志到 outputs-dir 中'
    )
    
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
        help='指定要评估的项目集所在路径 (默认: evaluation/evaluation_projects)'
    )
    
    parser.add_argument(
        '--resume',
        action='store_true',
        help='断点续传：跳过 CSV 中已有结果的项目，从上次中断处继续'
    )
    
    parser.add_argument(
        '--max-files',
        type=int,
        default=200,
        help='每个项目最多检测的 .circom 文件数量（默认 200，设为 0 表示不限制）'
    )
    
    args = parser.parse_args()
    
    # Ensure results directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 断点续传：读取已有结果
    resumed_projects = set()
    if args.resume:
        if output_path.exists():
            resumed_projects = _load_resumed_projects(output_path)
            if resumed_projects:
                print(f"🔄 断点续传模式：检测到 {len(resumed_projects)} 个已完成的项目，将跳过")
            else:
                print("🔄 断点续传模式：未找到已有结果，将从头开始")
        else:
            print("🔄 断点续传模式：指定的 CSV 文件不存在，将从头开始")
    
    # 创建 evaluation executor
    benchmark = CircomspectEvaluation(
        circomspect_path=args.circomspect,
        verbose=args.verbose,
        outputs_dir=args.outputs_dir,
        save_logs=args.save_logs,
        csv_output_path=output_path,
        resumed_projects=resumed_projects,
        max_files_per_project=args.max_files
    )

    # 如果指定了 --projects-dir, 覆盖默认的 evaluation_dir
    if args.projects_dir:
        benchmark.evaluation_dir = Path(args.projects_dir).resolve()
        if not benchmark.evaluation_dir.exists():
            print(f"错误: 指定的项目目录不存在: {benchmark.evaluation_dir}")
            sys.exit(1)
    
    print("开始隐私评估测试...")
    print(f"设定模式: {args.mode}")
    print(f"项目目录: {benchmark.evaluation_dir}")
    if args.max_files > 0:
        print(f"每项目文件上限: {args.max_files}")
    
    # 运行评估测试
    results = benchmark.run_evaluation(args.mode)
    
    # 保存结果（增量模式下此处仅确认）
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
