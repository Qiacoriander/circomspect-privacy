import argparse
import csv
import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from build_dataset_statistics import (
    bucket_name,
    collect_circomlib_templates,
    collect_closure,
    count_loc,
    extract_component_calls,
    extract_main_specs,
    extract_template_input_index,
    extract_templates,
    is_circomlib_path,
    keyword_known,
    parse_signal_stats,
    read_text,
    summarize_bucket,
    build_template_file_index,
)


@dataclass
class InstanceStats:
    project_name: str
    file_path: str
    analysis_success: bool
    status: str
    failure_reason: str
    closure_file_count: int
    unresolved_include_count: int
    loc: int
    subcircuit_count: int
    component_call_count: int
    r_known_hit_count: int
    r_known_hit_rate: float
    signal_count: int
    private_signal_count: int
    private_signal_ratio: float
    signal_count_compact: int
    private_signal_count_compact: int
    private_signal_ratio_compact: float


def calc_instance_stats(
    projects_dir: Path,
    circomlib_dir: Path,
    row: Dict[str, str],
    circomlib_templates: Set[str],
) -> InstanceStats:
    project_name = row.get("project_name", "").strip()
    rel_file = row.get("file_path", "").strip()
    analysis_success = (row.get("success") or "").lower() == "true"
    entry_file = projects_dir / Path(rel_file.replace("\\", "/"))
    if not entry_file.exists():
        return InstanceStats(
            project_name=project_name,
            file_path=rel_file,
            analysis_success=analysis_success,
            status="failed",
            failure_reason="entry_file_missing",
            closure_file_count=0,
            unresolved_include_count=0,
            loc=0,
            subcircuit_count=0,
            component_call_count=0,
            r_known_hit_count=0,
            r_known_hit_rate=0.0,
            signal_count=0,
            private_signal_count=0,
            private_signal_ratio=0.0,
            signal_count_compact=0,
            private_signal_count_compact=0,
            private_signal_ratio_compact=0.0,
        )

    closure, unresolved = collect_closure([entry_file], projects_dir, circomlib_dir)
    template_index = build_template_file_index(closure)

    template_input_index: Dict[str, Dict[str, int]] = {}
    main_public_marks: Set[Tuple[str, str]] = set()
    loc_total = 0
    subcircuits = 0
    signals = 0
    input_signals = 0
    signals_compact = 0
    input_signals_compact = 0
    call_total = 0
    known_hits = 0

    for file_path in closure:
        try:
            content = read_text(file_path)
        except OSError:
            continue
        for template_name, inputs in extract_template_input_index(content).items():
            target = template_input_index.setdefault(template_name, {})
            for input_name, factor in inputs.items():
                if input_name not in target:
                    target[input_name] = factor
        for template_name, public_names in extract_main_specs(content):
            for public_name in public_names:
                main_public_marks.add((template_name, public_name))

        loc_total += count_loc(content)
        templates = extract_templates(content)
        if not is_circomlib_path(file_path):
            subcircuits += len(templates)

        total_sig, input_sig, total_sig_compact, input_sig_compact = parse_signal_stats(content)
        signals += total_sig
        input_signals += input_sig
        signals_compact += total_sig_compact
        input_signals_compact += input_sig_compact

        calls = extract_component_calls(content)
        call_total += len(calls)
        for callee in calls:
            lowered = callee.lower()
            if keyword_known(callee):
                known_hits += 1
                continue
            if lowered in circomlib_templates:
                known_hits += 1
                continue
            source_paths = template_index.get(lowered, set())
            if any("/circomlib/circuits/" in p for p in source_paths):
                known_hits += 1

    public_input_signals = 0
    public_input_signals_compact = 0
    for template_name, input_name in main_public_marks:
        if input_name in template_input_index.get(template_name, {}):
            public_input_signals += template_input_index[template_name][input_name]
            public_input_signals_compact += 1
    private_signals = max(input_signals - public_input_signals, 0)
    private_signals_compact = max(input_signals_compact - public_input_signals_compact, 0)

    return InstanceStats(
        project_name=project_name,
        file_path=rel_file,
        analysis_success=analysis_success,
        status="ok",
        failure_reason="",
        closure_file_count=len(closure),
        unresolved_include_count=len(unresolved),
        loc=loc_total,
        subcircuit_count=subcircuits,
        component_call_count=call_total,
        r_known_hit_count=known_hits,
        r_known_hit_rate=(known_hits / call_total) if call_total > 0 else 0.0,
        signal_count=signals,
        private_signal_count=private_signals,
        private_signal_ratio=(private_signals / signals) if signals > 0 else 0.0,
        signal_count_compact=signals_compact,
        private_signal_count_compact=private_signals_compact,
        private_signal_ratio_compact=(
            private_signals_compact / signals_compact if signals_compact > 0 else 0.0
        ),
    )


def to_project_like(items: List[InstanceStats]):
    class _Row:
        pass
    rows = []
    for it in items:
        r = _Row()
        r.subcircuit_count = it.subcircuit_count
        r.r_known_hit_count = it.r_known_hit_count
        r.component_call_count = it.component_call_count
        r.signal_count = it.signal_count
        r.private_signal_count = it.private_signal_count
        r.signal_count_compact = it.signal_count_compact
        r.private_signal_count_compact = it.private_signal_count_compact
        rows.append(r)
    return rows


def build_markdown(
    rows_all: List[InstanceStats],
    rows_ok: List[InstanceStats],
    small_upper: int,
    medium_upper: int,
    output_csv: Path,
) -> str:
    def table_lines(title: str, rows: List[InstanceStats]) -> List[str]:
        by_bucket: Dict[str, List[InstanceStats]] = {"Small": [], "Medium": [], "Large": []}
        for x in rows:
            by_bucket[bucket_name(x.loc, small_upper, medium_upper)].append(x)
        s = summarize_bucket(to_project_like(by_bucket["Small"]))
        m = summarize_bucket(to_project_like(by_bucket["Medium"]))
        l = summarize_bucket(to_project_like(by_bucket["Large"]))
        t = summarize_bucket(to_project_like(rows))
        out = [f"## {title}", ""]
        out.append("| Scale (LOC) | Instances | Avg. Sub-circuits | Avg. R_known Hit Rate | Avg. Signals (Expanded) | Avg. Signals (Compact) | Avg. Priv Signal Ratio (Expanded) | Avg. Priv Signal Ratio (Compact) |")
        out.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        out.append(f"| Small (< {small_upper}) | {int(s['projects'])} | {s['avg_subcircuits']:.2f} | {s['avg_r_known_rate_pct']:.2f}% | {s['avg_signals']:.2f} | {s['avg_signals_compact']:.2f} | {s['avg_priv_ratio_pct']:.2f}% | {s['avg_priv_ratio_compact_pct']:.2f}% |")
        out.append(f"| Medium ({small_upper} - {medium_upper}) | {int(m['projects'])} | {m['avg_subcircuits']:.2f} | {m['avg_r_known_rate_pct']:.2f}% | {m['avg_signals']:.2f} | {m['avg_signals_compact']:.2f} | {m['avg_priv_ratio_pct']:.2f}% | {m['avg_priv_ratio_compact_pct']:.2f}% |")
        out.append(f"| Large (> {medium_upper}) | {int(l['projects'])} | {l['avg_subcircuits']:.2f} | {l['avg_r_known_rate_pct']:.2f}% | {l['avg_signals']:.2f} | {l['avg_signals_compact']:.2f} | {l['avg_priv_ratio_pct']:.2f}% | {l['avg_priv_ratio_compact_pct']:.2f}% |")
        out.append(f"| **Total / Avg.** | **{int(t['projects'])}** | **{t['avg_subcircuits']:.2f}** | **{t['avg_r_known_rate_pct']:.2f}%** | **{t['avg_signals']:.2f}** | **{t['avg_signals_compact']:.2f}** | **{t['avg_priv_ratio_pct']:.2f}%** | **{t['avg_priv_ratio_compact_pct']:.2f}%** |")
        out.append("")
        return out

    lines = []
    lines.append("# 500/5000 实例级统计汇总")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 输入 CSV: `{output_csv.as_posix()}`")
    lines.append("- 统计口径: 每个 has_main=True 的文件视为一个 circuit instance")
    lines.append("- 比率口径: sum(分子)/sum(分母) 的加权聚合")
    lines.append("")
    lines.extend(table_lines("表1：全部 main 实例（含检测失败实例）", rows_all))
    lines.extend(table_lines("表2：仅检测成功实例（success=True）", rows_ok))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-csv", default="evaluation/evaluation_results/archive/full.csv")
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects")
    parser.add_argument("--circomlib-dir", default="circomlib/circuits")
    parser.add_argument("--output-csv", default="evaluation/evaluation_results/statistics_instances_500_5000.csv")
    parser.add_argument("--output-md", default="evaluation/evaluation_results/statistics_summary_500_5000.md")
    parser.add_argument("--small-upper", type=int, default=500)
    parser.add_argument("--medium-upper", type=int, default=5000)
    args = parser.parse_args()

    full_csv = Path(args.full_csv)
    projects_dir = Path(args.projects_dir)
    circomlib_dir = Path(args.circomlib_dir)
    output_csv = Path(args.output_csv)
    output_md = Path(args.output_md)

    all_rows = list(csv.DictReader(full_csv.open(encoding="utf-8")))
    main_rows = [r for r in all_rows if (r.get("has_main") or "").lower() == "true"]
    circomlib_templates = collect_circomlib_templates(circomlib_dir)

    stats: List[InstanceStats] = []
    for i, row in enumerate(main_rows, start=1):
        st = calc_instance_stats(projects_dir, circomlib_dir, row, circomlib_templates)
        stats.append(st)
        print(f"[{i}/{len(main_rows)}] {st.project_name}::{st.file_path} status={st.status}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "project_name", "file_path", "analysis_success", "status", "failure_reason",
            "closure_file_count", "unresolved_include_count", "loc", "subcircuit_count",
            "component_call_count", "r_known_hit_count", "r_known_hit_rate",
            "signal_count", "private_signal_count", "private_signal_ratio",
            "signal_count_compact", "private_signal_count_compact", "private_signal_ratio_compact",
        ])
        for x in stats:
            w.writerow([
                x.project_name, x.file_path, str(x.analysis_success), x.status, x.failure_reason,
                x.closure_file_count, x.unresolved_include_count, x.loc, x.subcircuit_count,
                x.component_call_count, x.r_known_hit_count, f"{x.r_known_hit_rate:.6f}",
                x.signal_count, x.private_signal_count, f"{x.private_signal_ratio:.6f}",
                x.signal_count_compact, x.private_signal_count_compact, f"{x.private_signal_ratio_compact:.6f}",
            ])

    ok_rows = [x for x in stats if x.analysis_success]
    md = build_markdown(stats, ok_rows, args.small_upper, args.medium_upper, output_csv)
    output_md.write_text(md, encoding="utf-8")
    print(f"instances_total={len(stats)}")
    print(f"instances_success={len(ok_rows)}")
    print(f"output_csv={output_csv}")
    print(f"output_md={output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
