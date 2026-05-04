import os
import subprocess
from pathlib import Path

README_PATH = 'evaluation/audit/README.md'
LOGS_DIR = Path('evaluation/evaluation_logs')
PROJECTS_DIR = Path('evaluation/evaluation_projects')

def get_projects_from_readme():
    projects = []
    with open(README_PATH, 'r', encoding='utf-8') as f:
        in_table = False
        for line in f:
            line = line.strip()
            if line.startswith('|---|---|'):
                in_table = True
                continue
            if in_table and line.startswith('|'):
                parts = [p.strip() for p in line.split('|')]
                if len(parts) > 3:
                    project_name = parts[1]
                    circuit_file = parts[2].strip('`').strip()
                    if project_name and circuit_file:
                        projects.append((project_name, circuit_file))
    return projects

def main():
    projects = get_projects_from_readme()
    print(f"从 README 中读取到了 {len(projects)} 个需要检测的电路文件。")
    
    executable = Path('target/release/circomspect.exe')
    if not executable.exists():
        print(f"错误: 找不到 circomspect 可执行文件: {executable}")
        return

    success_count = 0
    fail_count = 0

    for project_name, circuit_file in projects:
        print(f"\n[+] 处理项目: {project_name}")
        
        circuit_filename = os.path.basename(circuit_file.replace('\\', '/'))
        log_dir = LOGS_DIR / project_name
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{circuit_filename}.log"
        
        # 如果你希望跳过已经存在且不为空的日志，可以解开下方注释
        # if log_file.exists() and log_file.stat().st_size > 0:
        #     print(f"    日志已存在，跳过: {log_file}")
        #     continue

        full_circuit_path = PROJECTS_DIR / circuit_file
        
        if not full_circuit_path.exists():
            print(f"    [警告] 找不到电路文件: {full_circuit_path}")
            fail_count += 1
            continue
            
        cmd = [
            str(executable),
            "eval",
            "--mode", "main",
            str(full_circuit_path)
        ]
        
        print(f"    -> 生成日志: {log_file}")
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                # 设置超时时间为 60 秒，防止某些复杂电路卡死
                subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=60)
            success_count += 1
        except subprocess.TimeoutExpired:
            print(f"    [错误] 执行超时 (60s)")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write("\n\n[CIRCOMSPECT EXECUTION TIMEOUT]\n")
            fail_count += 1
        except Exception as e:
            print(f"    [错误] 执行异常: {e}")
            fail_count += 1

    print(f"\n批量执行完毕！成功处理: {success_count} 个，失败/跳过: {fail_count} 个。日志已保存在 {LOGS_DIR} 目录下。")

if __name__ == '__main__':
    main()
