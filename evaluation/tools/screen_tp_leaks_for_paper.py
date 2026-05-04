import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


PROJECT_EXCLUDE_PATTERNS = [
    r"test",
    r"tests",
    r"learning",
    r"learn",
    r"tutorial",
    r"playground",
    r"puzzle",
    r"notes",
    r"benchmark",
    r"example",
    r"examples",
    r"resources",
    r"extractor",
    r"circomlib",
    r"opencircom",
    r"fuzz",
    r"demo",
    r"sandbox",
    r"kaggle",
    r"arithc",
]

PROJECT_EXCLUDE_EXACT = {
    "zkmopro_benchmark-app",
    "Sindri-Labs_sindri-resources",
    "Cryamor_Circom-AST-Extractor",
    "costa-group_circom_tests",
    "jose-blockchain_opencircom",
}

FILE_EXCLUDE_PATTERNS = [
    r"(^|[\\/])test(s)?([\\/]|$)",
    r"(^|[\\/])benchmark(s)?([\\/]|$)",
    r"(^|[\\/])example(s)?([\\/]|$)",
    r"(^|[\\/])tutorial(s)?([\\/]|$)",
    r"(^|[\\/])sample(s)?([\\/]|$)",
    r"(^|[\\/])playground([\\/]|$)",
    r"(^|[\\/])puzzle(s)?([\\/]|$)",
    r"(^|[\\/])fuzz([\\/]|$)",
    r"(^|[\\/])demo([\\/]|$)",
]

README_EDU_PATTERNS = [
    r"tutorial",
    r"learning",
    r"workshop",
    r"course",
    r"exercise",
    r"benchmark",
    r"playground",
    r"example project",
    r"teaching",
]


def norm(s: str) -> str:
    return (s or "").strip().lower()


def match_any(patterns: list[str], text: str) -> str | None:
    t = norm(text)
    for p in patterns:
        if re.search(p, t):
            return p
    return None


def read_readme_text(project_dir: Path) -> str:
    candidates = []
    for name in ["README.md", "Readme.md", "README.MD", "README", "readme.md"]:
        p = project_dir / name
        if p.exists():
            candidates.append(p)
    if not candidates:
        return ""
    try:
        return candidates[0].read_text(encoding="utf-8", errors="ignore")[:20000]
    except Exception:
        return ""


def decide_project(project_name: str, project_dir: Path, use_readme_rules: bool) -> tuple[str, str]:
    pn = norm(project_name)
    if project_name in PROJECT_EXCLUDE_EXACT:
        return "exclude", "project_exact_rule"
    p = match_any(PROJECT_EXCLUDE_PATTERNS, pn)
    if p:
        return "exclude", f"project_name_pattern:{p}"
    if use_readme_rules:
        readme = read_readme_text(project_dir)
        rp = match_any(README_EDU_PATTERNS, readme)
        if rp:
            return "exclude", f"readme_pattern:{rp}"
    return "keep", "project_pass"


def decide_row(project_decision: str, file_path: str) -> tuple[str, str]:
    if project_decision == "exclude":
        return "exclude", "project_excluded"
    fp = norm(file_path.replace("\\", "/"))
    p = match_any(FILE_EXCLUDE_PATTERNS, fp)
    if p:
        return "exclude", f"file_path_pattern:{p}"
    return "keep", "row_pass"


def to_int(v: str) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects")
    parser.add_argument("--output-csv", default="evaluation/evaluation_results/full_detected_leaks_deployable.csv")
    parser.add_argument("--excluded-csv", default="evaluation/evaluation_results/full_detected_leaks_excluded.csv")
    parser.add_argument("--report-md", default="evaluation/evaluation_results/full_detected_leaks_screening.md")
    parser.add_argument("--stats-csv", default="evaluation/evaluation_results/full_detected_leaks_deployable_stats.csv")
    parser.add_argument("--use-readme-rules", action="store_true")
    args = parser.parse_args()

    input_csv = Path(args.input_csv)
    projects_dir = Path(args.projects_dir)
    rows = list(csv.DictReader(open(input_csv, encoding="utf-8")))
    fieldnames = list(rows[0].keys()) if rows else []
    out_fieldnames = fieldnames + ["screen_decision", "screen_reason"]

    project_names = sorted({r["project_name"] for r in rows})
    project_rules: dict[str, tuple[str, str]] = {}
    for pn in project_names:
        project_rules[pn] = decide_project(pn, projects_dir / pn, args.use_readme_rules)

    kept_rows = []
    excluded_rows = []
    for r in rows:
        d, reason = decide_row(project_rules[r["project_name"]][0], r["file_path"])
        rr = dict(r)
        rr["screen_decision"] = d
        rr["screen_reason"] = reason if d == "keep" else f"{reason};{project_rules[r['project_name']][1]}"
        if d == "keep":
            kept_rows.append(rr)
        else:
            excluded_rows.append(rr)

    write_csv(Path(args.output_csv), kept_rows, out_fieldnames)
    write_csv(Path(args.excluded_csv), excluded_rows, out_fieldnames)

    kept_projects = sorted({r["project_name"] for r in kept_rows})
    kept_files = len(kept_rows)
    kept_full = sum(to_int(r.get("full_leak_count", "0")) for r in kept_rows)
    kept_partial = sum(to_int(r.get("partial_leak_count", "0")) for r in kept_rows)

    stats_rows = [
        {"metric": "kept_projects", "value": str(len(kept_projects))},
        {"metric": "kept_files", "value": str(kept_files)},
        {"metric": "kept_full_leak_count", "value": str(kept_full)},
        {"metric": "kept_partial_leak_count", "value": str(kept_partial)},
        {"metric": "excluded_files", "value": str(len(excluded_rows))},
    ]
    write_csv(Path(args.stats_csv), stats_rows, ["metric", "value"])

    kept_by_project = defaultdict(list)
    ex_by_project = defaultdict(list)
    for r in kept_rows:
        kept_by_project[r["project_name"]].append(r)
    for r in excluded_rows:
        ex_by_project[r["project_name"]].append(r)

    report = []
    report.append("# TP 泄露结果二次筛选报告\n")
    report.append("## 筛选原则\n")
    report.append("- 排除非部署仓库：测试/教学/基准/示例/资源类项目。\n")
    report.append("- 排除明显测试路径：`tests`、`benchmark`、`example`、`demo`、`playground` 等目录。\n")
    report.append("- 保留剩余视为实际应用项目候选。\n")
    report.append("\n## 统计\n")
    report.append(f"- 保留项目数: **{len(kept_projects)}**\n")
    report.append(f"- 涉及文件数: **{kept_files}**\n")
    report.append(f"- FULL LEAK 总数: **{kept_full}**\n")
    report.append(f"- PARTIAL LEAK 总数: **{kept_partial}**\n")
    report.append(f"- 排除文件数: **{len(excluded_rows)}**\n")

    report.append("\n## 保留项（按项目）\n")
    for pn in sorted(kept_by_project.keys()):
        items = kept_by_project[pn]
        full_sum = sum(to_int(x.get("full_leak_count", "0")) for x in items)
        part_sum = sum(to_int(x.get("partial_leak_count", "0")) for x in items)
        report.append(f"- {pn}: 文件 {len(items)}，FULL={full_sum}，PARTIAL={part_sum}\n")

    report.append("\n## 排除项（按项目）\n")
    for pn in sorted(ex_by_project.keys()):
        items = ex_by_project[pn]
        reasons = sorted({x["screen_reason"] for x in items})
        report.append(f"- {pn}: 文件 {len(items)}，原因: {', '.join(reasons[:3])}\n")

    Path(args.report_md).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_md).write_text("".join(report), encoding="utf-8")

    print(f"kept_rows={len(kept_rows)} excluded_rows={len(excluded_rows)}")
    print(f"kept_projects={len(kept_projects)} kept_full={kept_full} kept_partial={kept_partial}")
    print(f"output_csv={args.output_csv}")
    print(f"excluded_csv={args.excluded_csv}")
    print(f"report_md={args.report_md}")
    print(f"stats_csv={args.stats_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
