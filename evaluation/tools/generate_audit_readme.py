import csv
import sys
from pathlib import Path

def generate_audit_readme(csv_path: Path, readme_path: Path):
    if not csv_path.exists():
        print(f"Error: CSV file not found at {csv_path}")
        sys.exit(1)

    # Read the CSV and filter for leaks
    leaks = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['success'] == 'True' and int(row['leak_count']) > 0:
                leaks.append(row)

    # Sort leaks by total count descending, then full leaks descending
    leaks.sort(key=lambda x: (int(x['leak_count']), int(x['full_leak_count'])), reverse=True)

    rows_str = ""
    for row in leaks:
        project_name = row['project_name']
        file_path = row['file_path']
        l_total = row['leak_count']
        l_full = row['full_leak_count']
        l_partial = row['partial_leak_count']
        leak_str = f"{l_total}({l_full}/{l_partial})"
        
        # Escape pipe characters in file paths just in case, though rare
        file_path_clean = file_path.replace('|', '\\|')
        
        rows_str += f"| {project_name} | `{file_path_clean}` | {leak_str} | 待审计 | | |\n"

    readme_content = f"""# 隐私泄露审计记录 (Privacy Leakage Audit Tracker)

本文档用于记录对 `circomspect` 检测出的隐私泄露潜在风险点进行人工审计的过程与结果。

## 各列说明 (Column Definitions)
- **项目**: 隐私泄露风险所在的 GitHub 项目名称。
- **电路文件**: 发生泄露风险的具体 `.circom` 文件路径。
- **泄露情况**: 格式为 `总数(Full/Partial)`，例如 `3(2/1)` 表示共检测到 3 处风险信号，其中 2 处为 Full Leak，1 处为 Partial Leak。
- **审计情况**: 当前审计的状态，初始均为“待审计”。在审核后应更新为“确认为有效泄露”、“误报”、“其他”等状态。
- **审计概述**: 审计完成后填写的简短说明。如果是误报，说明误报原因；如果是有效泄露，简述泄露的原因或利用方法。
- **审计报告文件**: 若该例子比较典型、复杂，或适合在论文中作为案例展示，则在此列链接存放在 `audit_details` 文件夹下的详细分析文档。不是每次都需要生成。

---

## 待审计与有效泄露清单 (True Positives & Pending)

| 项目 | 电路文件 | 泄露情况 | 审计情况 | 审计概述 | 审计报告文件 |
|---|---|---|---|---|---|
{rows_str.strip()}

---

## 已消除的误报记录 (Resolved False Positives)

| 项目 | 电路文件 | 泄露情况 | 误报原因简述 |
|---|---|---|---|
*(暂无记录)*
"""

    readme_path.parent.mkdir(parents=True, exist_ok=True)
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"Successfully generated Audit README at: {readme_path}")
    print(f"Total files with leaks to audit: {len(leaks)}")

if __name__ == '__main__':
    csv_file = Path(r"d:\dev\circomspect\evaluation\evaluation_results\evaluation_results_0309_0050.csv")
    readme_file = Path(r"d:\dev\circomspect\evaluation\audit\README.md")
    generate_audit_readme(csv_file, readme_file)
