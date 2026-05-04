import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path


README_NAMES = ["README.md", "Readme.md", "README.MD", "README", "readme.md"]

EXCLUDE_PATH_PATTERNS = [
    r"(^|[\\/])test(s)?([\\/]|$)",
    r"(^|[\\/])benchmark(s)?([\\/]|$)",
    r"(^|[\\/])example(s)?([\\/]|$)",
    r"(^|[\\/])tutorial(s)?([\\/]|$)",
    r"(^|[\\/])sample(s)?([\\/]|$)",
    r"(^|[\\/])playground([\\/]|$)",
    r"(^|[\\/])puzzle(s)?([\\/]|$)",
    r"(^|[\\/])fuzz([\\/]|$)",
    r"(^|[\\/])demo([\\/]|$)",
    r"(^|[\\/])homework(s)?([\\/]|$)",
    r"(^|[\\/])workshop(s)?([\\/]|$)",
    r"(^|[\\/])practice([\\/]|$)",
    r"(^|[\\/])bootcamp([\\/]|$)",
    r"(^|[\\/])testcase([\\/]|$)",
    r"(^|[\\/])test-vectors([\\/]|$)",
    r"zk-playground",
    r"circom-practice",
    r"(^|[\\/])compiler-testing([\\/]|$)",
    r"(^|[\\/])workspace([\\/])(temp|result)([\\/]|$)",
    r"(^|[\\/])experiments([\\/]|$)",
    r"build_\d+_\d+",
    r"(^|[\\/])temp([\\/]|$)",
    r"(^|[\\/])tmp([\\/]|$)",
    r"(^|[\\/])simple-test\.circom$",
    r"(^|[\\/])test-circuit\.circom$",
    r"(^|[\\/])test[^\\/]*\.circom$",
]

EXCLUDE_TEXT_PATTERNS = [
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
    r"bootcamp",
    r"homework",
    r"practice",
]

EXCLUDE_PROJECT_PATTERNS = [
    r"learning",
    r"playground",
    r"puzzle",
    r"demo",
    r"sandbox",
    r"notes",
    r"example",
    r"fuzz",
    r"kaggle",
    r"benchmark",
]

DEPLOY_TEXT_PATTERNS = [
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
    r"dapp",
    r"credential",
    r"authentication",
    r"identity",
    r"kyc",
    r"vote",
    r"withdraw",
    r"deposit",
    r"transaction",
    r"crowdfund",
]


def read_text(p: Path, limit: int = 50000) -> str:
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def read_readme(project_dir: Path) -> str:
    for name in README_NAMES:
        p = project_dir / name
        if p.exists():
            return read_text(p, 50000)
    return ""


def find_first(patterns: list[str], text: str) -> str:
    lower = text.lower()
    for pat in patterns:
        if re.search(pat, lower):
            return pat
    return ""


def to_int(row: dict, key: str) -> int:
    try:
        return int(row.get(key, "0") or 0)
    except Exception:
        return 0


def summarize(rows: list[dict]) -> tuple[int, int, int, int]:
    projects = len(set(r["project_name"] for r in rows))
    files = len(rows)
    full = sum(to_int(r, "full_leak_count") for r in rows)
    partial = sum(to_int(r, "partial_leak_count") for r in rows)
    return projects, files, full, partial


def make_log_path(logs_dir: Path, project_name: str, file_path: str, mode: str) -> Path:
    name = file_path.replace("\\", "__").replace("/", "__")
    return logs_dir / project_name / f"{name}__{mode}.log"


def review_row(row: dict, projects_dir: Path, logs_dir: Path) -> tuple[str, str, str]:
    project_name = row["project_name"]
    file_path = row["file_path"]
    mode = (row.get("mode") or "main").strip() or "main"
    project_dir = projects_dir / project_name
    circuit_path = projects_dir / file_path
    readme_text = read_readme(project_dir)
    code_text = read_text(circuit_path, 50000)
    log_text = read_text(make_log_path(logs_dir, project_name, file_path, mode), 30000)
    all_text = "\n".join([project_name, file_path, readme_text, code_text])

    project_ex = find_first(EXCLUDE_PROJECT_PATTERNS, project_name)
    path_ex = find_first(EXCLUDE_PATH_PATTERNS, file_path.replace("\\", "/"))
    text_ex = find_first(EXCLUDE_TEXT_PATTERNS, all_text)
    text_deploy = find_first(DEPLOY_TEXT_PATTERNS, all_text)
    include_error = "failed to open file" in log_text.lower()

    if include_error and re.search(r"(build_\d+_\d+|[\\/](temp|tmp)[\\/])", file_path.replace("\\", "/").lower()):
        return "exclude", "log_include_error_on_generated_path", "log=failed to open include on generated path"
    if project_ex:
        return "exclude", f"project_pattern:{project_ex}", f"project={project_name}"
    if path_ex:
        return "exclude", f"path_pattern:{path_ex}", f"path={file_path}"
    if text_ex and not text_deploy:
        return "exclude", f"edu_semantic_without_deploy:{text_ex}", "readme_or_code_or_project"
    if text_deploy:
        return "keep", f"deploy_semantic:{text_deploy}", "readme_or_code_or_project"
    if include_error:
        return "keep", "ambiguous_keep_with_log", "log_exists_and_no_edu_signal"
    return "keep", "ambiguous_keep_no_strong_exclude", "no_strong_exclude_signal"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployable-csv", default="evaluation/evaluation_results/full_detected_leaks_deployable.csv")
    parser.add_argument("--excluded-csv", default="evaluation/evaluation_results/full_detected_leaks_excluded.csv")
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects")
    parser.add_argument("--logs-dir", default="evaluation/evaluation_logs")
    parser.add_argument("--report-md", default="evaluation/evaluation_results/full_detected_leaks_manual_review.md")
    parser.add_argument("--decision-csv", default="evaluation/evaluation_results/full_detected_leaks_manual_review_decisions.csv")
    args = parser.parse_args()

    deployable_path = Path(args.deployable_csv)
    excluded_path = Path(args.excluded_csv)
    projects_dir = Path(args.projects_dir)
    logs_dir = Path(args.logs_dir)

    deployable_rows = list(csv.DictReader(open(deployable_path, encoding="utf-8")))
    excluded_rows = list(csv.DictReader(open(excluded_path, encoding="utf-8")))
    fieldnames = list(deployable_rows[0].keys()) if deployable_rows else []

    decisions = []
    moved_to_excluded = []
    kept_after_review = []
    for row in deployable_rows:
        decision, reason, evidence = review_row(row, projects_dir, logs_dir)
        rec = dict(row)
        rec["manual_review_decision"] = decision
        rec["manual_review_reason"] = reason
        rec["manual_review_evidence"] = evidence
        decisions.append(rec)
        if decision == "exclude":
            moved_to_excluded.append(dict(row))
        else:
            kept_after_review.append(dict(row))

    restored_to_deployable = []
    excluded_keep = list(excluded_rows)
    for row in excluded_rows:
        decision, reason, _ = review_row(row, projects_dir, logs_dir)
        if decision == "keep":
            rec = dict(row)
            rec["manual_review_decision"] = "boundary_keep_excluded"
            rec["manual_review_reason"] = f"boundary_recheck_not_restored:{reason}"
            rec["manual_review_evidence"] = "kept_excluded_for_consistency"
            decisions.append(rec)

    final_deployable = kept_after_review + restored_to_deployable
    final_excluded = excluded_keep + moved_to_excluded

    key = lambda r: (r.get("project_name", ""), r.get("file_path", ""), r.get("mode", ""))
    final_deployable = sorted(final_deployable, key=key)
    final_excluded = sorted(final_excluded, key=key)

    deploy_keys = {key(r) for r in final_deployable}
    final_excluded = [r for r in final_excluded if key(r) not in deploy_keys]

    with open(deployable_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(final_deployable)

    with open(excluded_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(final_excluded)

    decision_fields = fieldnames + ["manual_review_decision", "manual_review_reason", "manual_review_evidence"]
    with open(args.decision_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=decision_fields)
        w.writeheader()
        w.writerows(sorted(decisions, key=lambda r: (r["project_name"], r["file_path"], r.get("mode", ""))))

    project_count, file_count, full_count, partial_count = summarize(final_deployable)
    before_project_count, before_file_count, before_full_count, before_partial_count = summarize(deployable_rows)
    reason_counter = Counter(r["manual_review_reason"] for r in decisions if r["manual_review_decision"] in ("exclude", "restore_to_deployable"))
    changed_rows = [r for r in decisions if r["manual_review_decision"] in ("exclude", "restore_to_deployable")]
    changed_rows = sorted(changed_rows, key=lambda r: (r["project_name"], r["file_path"]))

    keep_by_project = defaultdict(list)
    for row in final_deployable:
        keep_by_project[row["project_name"]].append(row)
    moved_by_project = defaultdict(list)
    for row in decisions:
        if row["manual_review_decision"] == "exclude":
            moved_by_project[row["project_name"]].append(row)

    lines = []
    lines.append("# full_detected_leaks 保留项二次逐条人工复核结果\n")
    lines.append(f"- 输入 deployable: `{args.deployable_csv}`\n")
    lines.append(f"- 边界复查 excluded: `{args.excluded_csv}`\n")
    lines.append(f"- deployable 二次复核总条目: **{len(deployable_rows)}**\n")
    lines.append(f"- 边界复查 excluded 总条目: **{len(excluded_rows)}**\n")
    lines.append("\n## 复核后统计（final deployable）\n")
    lines.append(f"- 项目数: **{project_count}**\n")
    lines.append(f"- 文件数: **{file_count}**\n")
    lines.append(f"- FULL LEAK 总数: **{full_count}**\n")
    lines.append(f"- PARTIAL LEAK 总数: **{partial_count}**\n")
    lines.append("\n## 调整前后差异摘要\n")
    lines.append(f"- 调整前 deployable: 项目 **{before_project_count}** / 文件 **{before_file_count}** / FULL **{before_full_count}** / PARTIAL **{before_partial_count}**\n")
    lines.append(f"- 调整后 deployable: 项目 **{project_count}** / 文件 **{file_count}** / FULL **{full_count}** / PARTIAL **{partial_count}**\n")
    lines.append(f"- 新增排除: **{len(moved_to_excluded)}**\n")
    lines.append(f"- 恢复保留: **{len(restored_to_deployable)}**\n")
    for reason, cnt in sorted(reason_counter.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- 原因归类 {reason}: **{cnt}**\n")

    lines.append("\n## 调整明细\n")
    if not changed_rows:
        lines.append("- 无调整项\n")
    else:
        for row in changed_rows:
            lines.append(
                f"- {row['manual_review_decision']} | {row['project_name']} | {row['file_path']} | {row['manual_review_reason']} | {row['manual_review_evidence']}\n"
            )

    lines.append("\n## 保留项（逐项目）\n")
    for project in sorted(keep_by_project):
        items = keep_by_project[project]
        full = sum(to_int(x, "full_leak_count") for x in items)
        partial = sum(to_int(x, "partial_leak_count") for x in items)
        lines.append(f"- {project} | 文件 {len(items)} | FULL={full} | PARTIAL={partial}\n")

    lines.append("\n## 新增排除项（逐项目）\n")
    if not moved_by_project:
        lines.append("- 无新增排除\n")
    else:
        for project in sorted(moved_by_project):
            items = moved_by_project[project]
            reasons = sorted(set(x["manual_review_reason"] for x in items))
            lines.append(f"- {project} | 文件 {len(items)} | 原因 {', '.join(reasons)}\n")

    Path(args.report_md).write_text("".join(lines), encoding="utf-8")

    print(f"deployable_before={len(deployable_rows)} deployable_after={len(final_deployable)}")
    print(f"excluded_before={len(excluded_rows)} excluded_after={len(final_excluded)}")
    print(f"moved_to_excluded={len(moved_to_excluded)} restored_to_deployable={len(restored_to_deployable)}")
    print(f"final_projects={project_count} final_files={file_count} final_full={full_count} final_partial={partial_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
