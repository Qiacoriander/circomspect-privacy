import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


LEAK_RE = re.compile(r"^\s*(\d+)\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)\s*$")


@dataclass
class BaselineItem:
    project: str
    file_path: str
    full: int
    partial: int
    status: str

    @property
    def key(self) -> Tuple[str, str]:
        return normalize(self.project), normalize(self.file_path)


def normalize(value: str) -> str:
    return value.strip().strip("`").replace("\\", "/").lower()


def parse_audit_baseline(readme_path: Path) -> List[BaselineItem]:
    text = readme_path.read_text(encoding="utf-8")
    start_marker = "## 待审计与有效泄露清单 (True Positives & Pending)"
    start = text.find(start_marker)
    if start < 0:
        raise ValueError(f"未找到审计基线段落: {start_marker}")
    block = text[start:]
    lines = block.splitlines()
    rows: List[BaselineItem] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("---"):
            break
        if not stripped.startswith("|"):
            continue
        if stripped.startswith("|---") or "项目 | 电路文件" in stripped:
            continue
        cells = [x.strip() for x in stripped.strip("|").split("|")]
        if len(cells) < 4:
            continue
        project = cells[0]
        file_path = cells[1].replace("`", "").strip()
        leak_cell = cells[2]
        status = cells[3]
        leak_match = LEAK_RE.match(leak_cell)
        if leak_match is None:
            continue
        _, full, partial = leak_match.groups()
        rows.append(
            BaselineItem(
                project=project,
                file_path=file_path,
                full=int(full),
                partial=int(partial),
                status=status,
            )
        )
    return [x for x in rows if "确认为有效泄露" in x.status]


def load_variant_counts(csv_path: Path) -> Tuple[Dict[Tuple[str, str], Tuple[int, int]], int]:
    counts: Dict[Tuple[str, str], Tuple[int, int]] = {}
    affected_instances = 0
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (normalize(row.get("project_name", "")), normalize(row.get("file_path", "")))
            full = int(row.get("full_leak_count", "0") or 0)
            partial = int(row.get("partial_leak_count", "0") or 0)
            prev_full, prev_partial = counts.get(key, (0, 0))
            counts[key] = (prev_full + full, prev_partial + partial)
            if int(row.get("leak_count", "0") or 0) > 0:
                affected_instances += 1
    return counts, affected_instances


def fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-readme", default="evaluation/audit/README.md")
    parser.add_argument("--full", default="evaluation/evaluation_results/full.csv")
    parser.add_argument("--no-unroll-conservative", default="evaluation/evaluation_results/no_unroll_conservative.csv")
    parser.add_argument("--single-pass", default="evaluation/evaluation_results/single_pass.csv")
    parser.add_argument("--vanguard-lite", default="evaluation/evaluation_results/vanguard_lite.csv")
    parser.add_argument("--output-md", default="论文需要的表格.md")
    parser.add_argument("--output-summary-csv", default="evaluation/evaluation_results/paper_results_summary.csv")
    parser.add_argument("--output-detail-csv", default="evaluation/evaluation_results/paper_results_tp_mapping.csv")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    audit_readme = (root / args.audit_readme).resolve()
    variant_files = {
        "full": (root / args.full).resolve(),
        "no-unroll-conservative": (root / args.no_unroll_conservative).resolve(),
        "single-pass": (root / args.single_pass).resolve(),
        "vanguard-lite": (root / args.vanguard_lite).resolve(),
    }
    output_md = (root / args.output_md).resolve()
    output_summary_csv = (root / args.output_summary_csv).resolve()
    output_detail_csv = (root / args.output_detail_csv).resolve()

    baseline_items = parse_audit_baseline(audit_readme)
    baseline_map = {x.key: x for x in baseline_items}
    baseline_total_full = sum(x.full for x in baseline_items)
    baseline_total_partial = sum(x.partial for x in baseline_items)
    baseline_total_signals = baseline_total_full + baseline_total_partial
    baseline_total_entries = len(baseline_items)

    variant_counts: Dict[str, Dict[Tuple[str, str], Tuple[int, int]]] = {}
    variant_affected_instances: Dict[str, int] = {}
    for name, csv_path in variant_files.items():
        counts, affected = load_variant_counts(csv_path)
        variant_counts[name] = counts
        variant_affected_instances[name] = affected

    summary_rows: List[Dict[str, object]] = []
    detail_rows: List[Dict[str, object]] = []

    for variant in ["full", "no-unroll-conservative", "single-pass", "vanguard-lite"]:
        counts = variant_counts[variant]
        reported_full = sum(v[0] for v in counts.values())
        reported_partial = sum(v[1] for v in counts.values())

        tp_full = 0
        tp_partial = 0
        fn_entries = 0

        for key, base in baseline_map.items():
            var_full, var_partial = counts.get(key, (0, 0))
            item_tp_full = min(var_full, base.full)
            item_tp_partial = min(var_partial, base.partial)
            hit = (var_full + var_partial) > 0
            if not hit:
                fn_entries += 1
            tp_full += item_tp_full
            tp_partial += item_tp_partial
            detail_rows.append(
                {
                    "variant": variant,
                    "project_name": base.project,
                    "file_path": base.file_path,
                    "baseline_full_tp": base.full,
                    "baseline_partial_tp": base.partial,
                    "variant_full": var_full,
                    "variant_partial": var_partial,
                    "tp_full": item_tp_full,
                    "tp_partial": item_tp_partial,
                    "entry_hit": int(hit),
                    "entry_fn": int(not hit),
                }
            )

        if variant == "vanguard-lite":
            tp_cl_entries = sum(
                1
                for key in baseline_map
                if counts.get(key, (0, 0))[0] > 0
            )
            tp_full = tp_cl_entries
            tp_partial = 0
            fp_full = max(reported_full - tp_full, 0)
            fp_partial = 0
            fn_entries = max(baseline_total_entries - tp_cl_entries, 0)
            precision = (tp_full / reported_full) if reported_full else 0.0
            recall = (tp_cl_entries / baseline_total_entries) if baseline_total_entries else 0.0
            metric_note = "CL_only"
            affected_instances = sum(1 for value in counts.values() if value[0] > 0)
        else:
            tp_total = tp_full + tp_partial
            fp_full = reported_full - tp_full
            fp_partial = reported_partial - tp_partial
            fp_total = fp_full + fp_partial
            precision = (tp_total / (tp_total + fp_total)) if (tp_total + fp_total) else 0.0
            recall = (tp_total / baseline_total_signals) if baseline_total_signals else 0.0
            metric_note = "signal_level"
            affected_instances = variant_affected_instances[variant]

        summary_rows.append(
            {
                "variant": variant,
                "reported_fd": reported_full,
                "reported_pd": reported_partial,
                "tp_fd": tp_full,
                "tp_pd": tp_partial,
                "fp_fd": fp_full,
                "fp_pd": fp_partial,
                "fn_entries": fn_entries,
                "precision": precision,
                "recall": recall,
                "affected_instances": affected_instances,
                "metric_note": metric_note,
            }
        )

    output_summary_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_summary_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "variant",
                "reported_fd",
                "reported_pd",
                "tp_fd",
                "tp_pd",
                "fp_fd",
                "fp_pd",
                "fn_entries",
                "precision",
                "recall",
                "affected_instances",
                "metric_note",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    with output_detail_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "variant",
                "project_name",
                "file_path",
                "baseline_full_tp",
                "baseline_partial_tp",
                "variant_full",
                "variant_partial",
                "tp_full",
                "tp_partial",
                "entry_hit",
                "entry_fn",
            ],
        )
        writer.writeheader()
        writer.writerows(detail_rows)

    variant_label = {
        "full": "ZKFLOW",
        "no-unroll-conservative": "ZKFLOW_NE",
        "single-pass": "ZKFLOW_SP",
        "vanguard-lite": "V-REPLICA",
    }
    lines: List[str] = []
    lines.append("# 论文检测结果总表（Markdown）")
    lines.append("")
    lines.append(f"- 审计基线：`{audit_readme}`")
    lines.append(f"- 基线 TP 条目数：{baseline_total_entries}")
    lines.append(
        f"- 基线 TP 信号数：{baseline_total_signals}（FD={baseline_total_full}, PD={baseline_total_partial}）"
    )
    lines.append(f"- 四变体输入：`{variant_files['full']}`、`{variant_files['no-unroll-conservative']}`、`{variant_files['single-pass']}`、`{variant_files['vanguard-lite']}`")
    lines.append(f"- 汇总 CSV：`{output_summary_csv}`")
    lines.append(f"- 明细 CSV：`{output_detail_csv}`")
    lines.append("")
    lines.append("| Configuration | Reported FD | Reported PD | TP FD | TP PD | FP FD | FP PD | FN | Prec. | Rec. | Affected Instances |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for row in summary_rows:
        if row["variant"] == "vanguard-lite":
            reported_fd_text = f"{row['reported_fd']} (CL)"
            reported_pd_text = f"{row['reported_pd']} (DL)"
            tp_fd_text = f"{row['tp_fd']} (CL)"
            tp_pd_text = "-"
            fp_fd_text = f"{row['fp_fd']} (CL)"
            fp_pd_text = "-"
            prec_text = f"{fmt_pct(float(row['precision']))} (CL)"
        else:
            reported_fd_text = str(row["reported_fd"])
            reported_pd_text = str(row["reported_pd"])
            tp_fd_text = str(row["tp_fd"])
            tp_pd_text = str(row["tp_pd"])
            fp_fd_text = str(row["fp_fd"])
            fp_pd_text = str(row["fp_pd"])
            prec_text = fmt_pct(float(row["precision"]))
        lines.append(
            f"| {variant_label[row['variant']]} | {reported_fd_text} | {reported_pd_text} | "
            f"{tp_fd_text} | {tp_pd_text} | {fp_fd_text} | {fp_pd_text} | {row['fn_entries']} | "
            f"{prec_text} | {fmt_pct(float(row['recall']))} | {row['affected_instances']} |"
        )
    lines.append("")
    lines.append("## 计算口径")
    lines.append("")
    lines.append("- TP/FP（信号级）：以 `evaluation/audit/README.md` 中“确认为有效泄露”的 full 基线为准，按 `(project_name, file_path)` 对齐，类别内按 `min(variant_count, baseline_count)` 计 TP，超出部分计 FP。")
    lines.append("- FN（条目级）：基线 TP 条目在对应变体 `full_leak_count + partial_leak_count == 0` 时记为 FN。")
    lines.append("- Precision：`(TP_FD + TP_PD) / (TP_FD + TP_PD + FP_FD + FP_PD)`。")
    lines.append(f"- Recall：`(TP_FD + TP_PD) / {baseline_total_signals}`（基线 TP 信号总数）。")
    lines.append("- Affected Instances：对应变体 CSV 中 `leak_count > 0` 的实例条目数。")
    lines.append("- V-REPLICA 特殊口径：FD 视为 CL、PD 视为 DL；TP/FP 的精度仅按 CL（条目级）计算，Recall 按基线 TP 条目数计算。")
    lines.append("")
    lines.append("## 可复现命令")
    lines.append("")
    lines.append("```powershell")
    lines.append(
        "python evaluation/tools/build_paper_results_table.py "
        "--audit-readme evaluation/audit/README.md "
        "--full evaluation/evaluation_results/full.csv "
        "--no-unroll-conservative evaluation/evaluation_results/no_unroll_conservative.csv "
        "--single-pass evaluation/evaluation_results/single_pass.csv "
        "--vanguard-lite evaluation/evaluation_results/vanguard_lite.csv "
        "--output-md 论文需要的表格.md "
        "--output-summary-csv evaluation/evaluation_results/paper_results_summary.csv "
        "--output-detail-csv evaluation/evaluation_results/paper_results_tp_mapping.csv"
    )
    lines.append("```")
    lines.append("")

    output_md.write_text("\n".join(lines), encoding="utf-8")

    print(f"baseline_tp_entries={baseline_total_entries}")
    print(f"baseline_tp_signals={baseline_total_signals}")
    print(f"output_md={output_md}")
    print(f"output_summary_csv={output_summary_csv}")
    print(f"output_detail_csv={output_detail_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
