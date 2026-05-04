import argparse
import csv
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence


@dataclass
class MatchResult:
    matched: Path | None
    reason: str
    expected_names: List[str]
    candidate_paths: List[Path]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="按 evaluation_logs 复制对应源码并生成缺失清单")
    parser.add_argument("--logs-dir", default="evaluation/evaluation_logs", help="日志目录")
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects", help="源码项目目录")
    parser.add_argument("--output-dir", default="evaluation/evaluation_sources_from_logs", help="复制输出目录")
    parser.add_argument("--placement", choices=["mirror", "logs_flat"], default="mirror", help="复制目标布局")
    parser.add_argument("--missing-report", default="evaluation/evaluation_results/evaluation_sources_missing.csv", help="缺失清单 CSV")
    parser.add_argument("--summary-json", default="evaluation/evaluation_results/evaluation_sources_summary.json", help="执行统计 JSON")
    return parser.parse_args()


def normalize(path: Path) -> str:
    return str(path).replace("\\", "/")


def derive_expected_names(log_file_name: str) -> List[str]:
    if not log_file_name.lower().endswith(".log"):
        return []
    base = log_file_name[:-4]
    names: List[str] = []
    if base.lower().endswith(".circom"):
        names.append(base)
    else:
        names.append(f"{base}.circom")
    marker = "_circom__"
    marker_index = base.lower().find(marker)
    if marker_index >= 0:
        prefix = base[:marker_index]
        if prefix:
            names.append(f"{prefix}.circom")
    deduped: List[str] = []
    seen = set()
    for item in names:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def build_circom_index(project_dir: Path) -> Dict[str, List[Path]]:
    index: Dict[str, List[Path]] = {}
    for file in project_dir.rglob("*.circom"):
        key = file.name.lower()
        index.setdefault(key, []).append(file)
    return index


def match_source(log_file_name: str, circom_index: Dict[str, List[Path]]) -> MatchResult:
    expected_names = derive_expected_names(log_file_name)
    direct_matches: List[Path] = []
    for name in expected_names:
        direct_matches.extend(circom_index.get(name.lower(), []))
    if len(direct_matches) == 1:
        return MatchResult(matched=direct_matches[0], reason="matched", expected_names=expected_names, candidate_paths=direct_matches)
    if len(direct_matches) > 1:
        return MatchResult(matched=None, reason="ambiguous", expected_names=expected_names, candidate_paths=sorted(set(direct_matches)))
    stems = {Path(x).stem.lower() for x in expected_names}
    stem_matches: List[Path] = []
    for _, files in circom_index.items():
        for file in files:
            if file.stem.lower() in stems:
                stem_matches.append(file)
    if len(stem_matches) == 1:
        return MatchResult(matched=stem_matches[0], reason="matched_by_stem", expected_names=expected_names, candidate_paths=stem_matches)
    if len(stem_matches) > 1:
        return MatchResult(matched=None, reason="ambiguous_by_stem", expected_names=expected_names, candidate_paths=sorted(set(stem_matches)))
    return MatchResult(matched=None, reason="not_found", expected_names=expected_names, candidate_paths=[])


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def copy_one(source: Path, project_dir: Path, output_project_dir: Path, placement: str) -> Path:
    if placement == "logs_flat":
        destination = output_project_dir / source.name
    else:
        relative = source.relative_to(project_dir)
        destination = output_project_dir / relative
    ensure_parent(destination)
    shutil.copy2(source, destination)
    return destination


def write_missing_report(rows: Sequence[Dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "project_name",
                "log_file",
                "reason",
                "expected_names",
                "candidate_paths",
                "projects_dir",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_summary(summary: Dict[str, int | str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parent.parent.parent
    logs_dir = (root / args.logs_dir).resolve()
    projects_dir = (root / args.projects_dir).resolve()
    output_dir = (root / args.output_dir).resolve()
    missing_report = (root / args.missing_report).resolve()
    summary_json = (root / args.summary_json).resolve()

    if not logs_dir.exists() or not logs_dir.is_dir():
        raise SystemExit(f"logs_dir 不存在: {logs_dir}")
    if not projects_dir.exists() or not projects_dir.is_dir():
        raise SystemExit(f"projects_dir 不存在: {projects_dir}")
    destination_root = logs_dir if args.placement == "logs_flat" else output_dir
    destination_root.mkdir(parents=True, exist_ok=True)

    project_log_dirs = sorted([p for p in logs_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower())
    total_logs = 0
    copied_count = 0
    missing_count = 0
    ambiguous_count = 0
    project_missing_dir_count = 0
    scanned_projects = 0
    copied_projects = 0
    missing_rows: List[Dict[str, str]] = []

    for project_log_dir in project_log_dirs:
        project_name = project_log_dir.name
        scanned_projects += 1
        project_source_dir = projects_dir / project_name
        log_files = sorted([p for p in project_log_dir.rglob("*.log") if p.is_file()], key=lambda p: normalize(p).lower())
        total_logs += len(log_files)
        if not project_source_dir.exists() or not project_source_dir.is_dir():
            project_missing_dir_count += 1
            for log_file in log_files:
                missing_count += 1
                missing_rows.append(
                    {
                        "project_name": project_name,
                        "log_file": log_file.name,
                        "reason": "project_dir_missing",
                        "expected_names": ";".join(derive_expected_names(log_file.name)),
                        "candidate_paths": "",
                        "projects_dir": normalize(project_source_dir),
                    }
                )
            continue

        circom_index = build_circom_index(project_source_dir)
        copied_in_project = 0
        for log_file in log_files:
            result = match_source(log_file.name, circom_index)
            if result.matched is not None:
                destination = copy_one(result.matched, project_source_dir, destination_root / project_name, args.placement)
                copied_count += 1
                copied_in_project += 1
                print(f"[COPIED] {project_name} | {log_file.name} -> {normalize(destination)}")
                continue
            missing_count += 1
            if result.reason.startswith("ambiguous"):
                ambiguous_count += 1
            missing_rows.append(
                {
                    "project_name": project_name,
                    "log_file": log_file.name,
                    "reason": result.reason,
                    "expected_names": ";".join(result.expected_names),
                    "candidate_paths": ";".join(normalize(p) for p in result.candidate_paths),
                    "projects_dir": normalize(project_source_dir),
                }
            )
            print(f"[MISSING] {project_name} | {log_file.name} | reason={result.reason}")
        if copied_in_project > 0:
            copied_projects += 1

    write_missing_report(missing_rows, missing_report)
    summary = {
        "logs_dir": normalize(logs_dir),
        "projects_dir": normalize(projects_dir),
        "output_dir": normalize(destination_root),
        "placement": args.placement,
        "missing_report": normalize(missing_report),
        "scanned_projects": scanned_projects,
        "projects_with_copied_files": copied_projects,
        "logs_total": total_logs,
        "copied_total": copied_count,
        "missing_total": missing_count,
        "ambiguous_total": ambiguous_count,
        "project_dir_missing_total": project_missing_dir_count,
    }
    write_summary(summary, summary_json)

    print("copy_log_sources_done")
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
