import argparse
import csv
import re
from pathlib import Path


README_NAMES = ["README.md", "Readme.md", "README.MD", "README", "readme.md"]

PATH_EXCLUDE_PATTERNS = [
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

EDU_PATTERNS = [
    r"tutorial",
    r"learning",
    r"learn",
    r"workshop",
    r"course",
    r"exercise",
    r"example",
    r"benchmark",
    r"playground",
    r"puzzle",
    r"for education",
    r"for teaching",
]

DEPLOY_PATTERNS = [
    r"production",
    r"mainnet",
    r"deploy",
    r"deployed",
    r"contract",
    r"protocol",
    r"wallet",
    r"bridge",
    r"exchange",
    r"backend",
    r"frontend",
    r"payment",
    r"rollup",
    r"app",
    r"dapp",
    r"credential",
    r"authentication",
]


def read_text(p: Path, limit: int = 50000) -> str:
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def find_first(patterns: list[str], text: str) -> str:
    t = text.lower()
    for pat in patterns:
        m = re.search(pat, t)
        if m:
            return pat
    return ""


def read_readme(project_dir: Path) -> str:
    for n in README_NAMES:
        p = project_dir / n
        if p.exists():
            return read_text(p, 30000)
    return ""


def summarize(rows: list[dict]) -> tuple[int, int, int, int]:
    projects = len(set(r["project_name"] for r in rows))
    files = len(rows)
    full = sum(int(r.get("full_leak_count", "0") or 0) for r in rows)
    partial = sum(int(r.get("partial_leak_count", "0") or 0) for r in rows)
    return projects, files, full, partial


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects")
    parser.add_argument("--reviewed-csv", default="evaluation/evaluation_results/full_detected_leaks_deployable_reviewed.csv")
    parser.add_argument("--excluded-csv", default="evaluation/evaluation_results/full_detected_leaks_deployable_reviewed_excluded.csv")
    parser.add_argument("--report-md", default="evaluation/evaluation_results/full_detected_leaks_manual_review.md")
    parser.add_argument("--stats-csv", default="evaluation/evaluation_results/full_detected_leaks_manual_review_stats.csv")
    args = parser.parse_args()

    src = Path(args.input_csv)
    projects_dir = Path(args.projects_dir)
    rows = list(csv.DictReader(open(src, encoding="utf-8")))
    fieldnames = list(rows[0].keys()) if rows else []
    out_fields = fieldnames + ["manual_review_decision", "manual_review_reason", "manual_review_evidence"]

    kept = []
    excluded = []

    for row in rows:
        r = dict(row)
        project_name = r["project_name"]
        file_path = r["file_path"]
        project_dir = projects_dir / project_name
        circuit_path = projects_dir / file_path

        readme_text = read_readme(project_dir)
        code_text = read_text(circuit_path, 50000)

        path_hit = find_first(PATH_EXCLUDE_PATTERNS, file_path.replace("\\", "/"))
        readme_edu_hit = find_first(EDU_PATTERNS, readme_text)
        readme_deploy_hit = find_first(DEPLOY_PATTERNS, readme_text)
        code_edu_hit = find_first(EDU_PATTERNS, code_text)
        code_deploy_hit = find_first(DEPLOY_PATTERNS, code_text)

        decision = "keep"
        reason = "manual_keep_business_or_uncertain"
        evidence = "no_strong_edu_signal"

        if path_hit:
            decision = "exclude"
            reason = f"path_pattern:{path_hit}"
            evidence = file_path
        elif readme_edu_hit and not readme_deploy_hit and not code_deploy_hit:
            decision = "exclude"
            reason = f"readme_edu_without_deploy:{readme_edu_hit}"
            evidence = "README keyword matched"
        elif code_edu_hit and not code_deploy_hit and not readme_deploy_hit:
            decision = "exclude"
            reason = f"code_edu_without_deploy:{code_edu_hit}"
            evidence = circuit_path.name
        elif readme_deploy_hit:
            decision = "keep"
            reason = f"readme_deploy_signal:{readme_deploy_hit}"
            evidence = "README keyword matched"
        elif code_deploy_hit:
            decision = "keep"
            reason = f"code_deploy_signal:{code_deploy_hit}"
            evidence = circuit_path.name

        r["manual_review_decision"] = decision
        r["manual_review_reason"] = reason
        r["manual_review_evidence"] = evidence

        if decision == "keep":
            kept.append(r)
        else:
            excluded.append(r)

    Path(args.reviewed_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(args.reviewed_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader()
        w.writerows(kept)

    with open(args.excluded_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader()
        w.writerows(excluded)

    p_cnt, f_cnt, full_cnt, part_cnt = summarize(kept)
    stats = [
        {"metric": "manual_kept_projects", "value": str(p_cnt)},
        {"metric": "manual_kept_files", "value": str(f_cnt)},
        {"metric": "manual_kept_full_leak_count", "value": str(full_cnt)},
        {"metric": "manual_kept_partial_leak_count", "value": str(part_cnt)},
        {"metric": "manual_excluded_files", "value": str(len(excluded))},
    ]
    with open(args.stats_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["metric", "value"])
        w.writeheader()
        w.writerows(stats)

    kept_by_project = {}
    for r in kept:
        kept_by_project.setdefault(r["project_name"], []).append(r)
    ex_by_project = {}
    for r in excluded:
        ex_by_project.setdefault(r["project_name"], []).append(r)

    lines = []
    lines.append("# full_detected_leaks 保留项逐条代码人工复核结果\n")
    lines.append(f"- 输入: `{args.input_csv}`\n")
    lines.append(f"- 逐条读取并复核文件数: `{len(rows)}`\n")
    lines.append("\n## 复核后统计\n")
    lines.append(f"- 项目数: **{p_cnt}**\n")
    lines.append(f"- 文件数: **{f_cnt}**\n")
    lines.append(f"- FULL LEAK 总数: **{full_cnt}**\n")
    lines.append(f"- PARTIAL LEAK 总数: **{part_cnt}**\n")
    lines.append(f"- 排除文件数: **{len(excluded)}**\n")

    lines.append("\n## 保留项（逐项目）\n")
    for pn in sorted(kept_by_project):
        items = kept_by_project[pn]
        full = sum(int(x.get("full_leak_count", "0") or 0) for x in items)
        part = sum(int(x.get("partial_leak_count", "0") or 0) for x in items)
        lines.append(f"- {pn} | 文件 {len(items)} | FULL={full} | PARTIAL={part}\n")

    lines.append("\n## 排除项（逐项目）\n")
    for pn in sorted(ex_by_project):
        items = ex_by_project[pn]
        reasons = sorted(set(x["manual_review_reason"] for x in items))
        lines.append(f"- {pn} | 文件 {len(items)} | 原因 {', '.join(reasons[:3])}\n")

    Path(args.report_md).write_text("".join(lines), encoding="utf-8")

    print(f"reviewed_total={len(rows)}")
    print(f"manual_keep={len(kept)} manual_excluded={len(excluded)}")
    print(f"projects={p_cnt} files={f_cnt} full={full_cnt} partial={part_cnt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
