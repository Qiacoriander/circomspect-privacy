import argparse
import csv
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ALL_VARIANTS = ("full", "no-unroll-conservative", "no-unroll-aggressive", "single-pass", "vanguard-lite")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="对比多变体评估结果，兼容旧三变体命令")
    parser.add_argument("--full", required=True, help="full 变体 CSV 路径")
    parser.add_argument(
        "--no-unroll-conservative",
        required=False,
        dest="no_unroll_conservative",
        help="no-unroll-conservative 变体 CSV 路径",
    )
    parser.add_argument(
        "--no-unroll-aggressive",
        required=False,
        dest="no_unroll_aggressive",
        help="no-unroll-aggressive 变体 CSV 路径",
    )
    parser.add_argument(
        "--no-unroll",
        required=False,
        dest="no_unroll",
        help="兼容旧参数：等价于 --no-unroll-conservative",
    )
    parser.add_argument("--single-pass", required=False, dest="single_pass", help="single-pass 变体 CSV 路径")
    parser.add_argument("--vanguard-lite", required=False, dest="vanguard_lite", help="vanguard-lite 变体 CSV 路径")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="输出目录，默认 evaluation/evaluation_results",
    )
    parser.add_argument(
        "--output-prefix",
        default=None,
        help="输出文件名前缀，默认 variant_compare_<月日_时分>",
    )
    return parser.parse_args()


def as_bool(value: str) -> bool:
    lowered = str(value).strip().lower()
    return lowered in {"true", "1", "yes", "y"}


def as_int(value: str, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return default


def as_float(value: str, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def normalize_path(raw_path: str) -> str:
    return str(raw_path).replace("/", "\\").strip()


def build_item_key(row: Dict[str, str]) -> str:
    project_name = row.get("project_name", "").strip()
    file_path = normalize_path(row.get("file_path", ""))
    mode = row.get("mode", "").strip()
    return "||".join((project_name, file_path, mode))


def split_item_key(key: str) -> Tuple[str, str, str]:
    parts = key.split("||")
    if len(parts) < 3:
        return key, "", ""
    return parts[0], parts[1], parts[2]


def parse_variant_input_paths(args: argparse.Namespace) -> Dict[str, Path]:
    if args.no_unroll and args.no_unroll_conservative:
        raise ValueError("请勿同时传入 --no-unroll 与 --no-unroll-conservative")

    selected: Dict[str, Path] = {"full": Path(args.full).resolve()}
    if args.no_unroll_conservative and str(args.no_unroll_conservative).strip():
        selected["no-unroll-conservative"] = Path(args.no_unroll_conservative).resolve()
    elif args.no_unroll and str(args.no_unroll).strip():
        selected["no-unroll-conservative"] = Path(args.no_unroll).resolve()

    if args.no_unroll_aggressive and str(args.no_unroll_aggressive).strip():
        selected["no-unroll-aggressive"] = Path(args.no_unroll_aggressive).resolve()
    if args.single_pass and str(args.single_pass).strip():
        selected["single-pass"] = Path(args.single_pass).resolve()
    if args.vanguard_lite and str(args.vanguard_lite).strip():
        selected["vanguard-lite"] = Path(args.vanguard_lite).resolve()

    if "full" not in selected:
        raise ValueError("必须提供 --full 输入文件")
    if len(selected) < 2:
        raise ValueError("至少提供两个变体输入进行对比（例如 --full + --vanguard-lite）")
    return selected


def read_variant_csv(variant_name: str, csv_path: Path) -> Dict[str, Dict[str, object]]:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV 文件不存在: {csv_path}")

    data: Dict[str, Dict[str, object]] = {}
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"CSV 缺少表头: {csv_path}")
        required = {"project_name", "file_path", "mode", "leak_count", "success"}
        missing = [field for field in required if field not in reader.fieldnames]
        if missing:
            missing_str = ", ".join(missing)
            raise ValueError(f"CSV 缺少必要字段 {missing_str}: {csv_path}")

        for row in reader:
            key = build_item_key(row)
            normalized = {
                "project_name": row.get("project_name", "").strip(),
                "file_path": normalize_path(row.get("file_path", "")),
                "mode": row.get("mode", "").strip(),
                "has_main": as_bool(row.get("has_main", "")),
                "public_inputs_count": as_int(row.get("public_inputs_count", ""), -1),
                "full_leak_count": as_int(row.get("full_leak_count", "")),
                "partial_leak_count": as_int(row.get("partial_leak_count", "")),
                "cascade_leak_count": as_int(row.get("cascade_leak_count", "")),
                "leak_count": as_int(row.get("leak_count", "")),
                "analysis_time": as_float(row.get("analysis_time", "")),
                "success": as_bool(row.get("success", "")),
                "error_message": (row.get("error_message", "") or "").strip(),
                "variant": (row.get("variant", "") or variant_name).strip() or variant_name,
            }
            data[key] = normalized
    return data


def summarize_variant(items: Dict[str, Dict[str, object]]) -> Dict[str, object]:
    total = len(items)
    success_count = 0
    fail_count = 0
    leak_files = 0
    total_leak_signals = 0
    total_full = 0
    total_partial = 0
    total_cascade = 0
    total_analysis_time = 0.0

    for item in items.values():
        success = bool(item["success"])
        leak_count = int(item["leak_count"])
        success_count += 1 if success else 0
        fail_count += 0 if success else 1
        leak_files += 1 if success and leak_count > 0 else 0
        total_leak_signals += leak_count if success else 0
        total_full += int(item["full_leak_count"]) if success else 0
        total_partial += int(item["partial_leak_count"]) if success else 0
        total_cascade += int(item["cascade_leak_count"]) if success else 0
        total_analysis_time += float(item["analysis_time"])

    return {
        "total_items": total,
        "success_items": success_count,
        "failed_items": fail_count,
        "leak_items": leak_files,
        "total_leak_signals": total_leak_signals,
        "total_full_leaks": total_full,
        "total_partial_leaks": total_partial,
        "total_cascade_leaks": total_cascade,
        "total_analysis_time": total_analysis_time,
    }


def classify_diff_reason(
    item_by_variant: Dict[str, Optional[Dict[str, object]]],
    selected_variants: List[str],
) -> str:
    present = [name for name in selected_variants if item_by_variant.get(name) is not None]
    if len(present) != len(selected_variants):
        return "missing_item"

    success_values = {name: bool(item_by_variant[name]["success"]) for name in selected_variants}
    if len(set(success_values.values())) > 1:
        return "success_mismatch"

    metrics = {
        name: (
            int(item_by_variant[name]["leak_count"]),
            int(item_by_variant[name]["full_leak_count"]),
            int(item_by_variant[name]["partial_leak_count"]),
            int(item_by_variant[name]["cascade_leak_count"]),
        )
        for name in selected_variants
    }
    if len(set(metrics.values())) > 1:
        return "leak_count_mismatch"

    return "same"


def classify_task4_category(
    item_by_variant: Dict[str, Optional[Dict[str, object]]],
    selected_variants: List[str],
) -> str:
    required = ("full", "no-unroll-conservative", "no-unroll-aggressive")
    if not all(name in selected_variants for name in required):
        return "n/a"

    full_item = item_by_variant.get("full")
    conservative_item = item_by_variant.get("no-unroll-conservative")
    aggressive_item = item_by_variant.get("no-unroll-aggressive")
    if full_item is None or conservative_item is None or aggressive_item is None:
        return "n/a"

    success_flags = [
        bool(full_item["success"]),
        bool(conservative_item["success"]),
        bool(aggressive_item["success"]),
    ]
    if not all(success_flags):
        return "工具失败"

    full_leak = int(full_item["leak_count"])
    conservative_leak = int(conservative_item["leak_count"])
    aggressive_leak = int(aggressive_item["leak_count"])

    if conservative_leak > full_leak and conservative_leak > aggressive_leak:
        return "保守误报"
    if aggressive_leak > conservative_leak and aggressive_leak >= full_leak:
        return "激进召回"
    return "其他差异"


def build_diff_rows(
    data_by_variant: Dict[str, Dict[str, Dict[str, object]]],
    selected_variants: List[str],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    all_keys = sorted(set().union(*(data.keys() for data in data_by_variant.values())))
    diff_rows: List[Dict[str, object]] = []
    exclusive_rows: List[Dict[str, object]] = []

    for key in all_keys:
        by_variant = {variant: data_by_variant[variant].get(key) for variant in selected_variants}
        project_name, file_path, mode = split_item_key(key)
        row = {
            "project_name": project_name,
            "file_path": file_path,
            "mode": mode,
        }
        for variant in selected_variants:
            key_tag = variant.replace("-", "_")
            item = by_variant[variant]
            row[f"present_{key_tag}"] = item is not None
            row[f"success_{key_tag}"] = "" if item is None else bool(item["success"])
            row[f"leak_{key_tag}"] = "" if item is None else int(item["leak_count"])
            row[f"full_leak_{key_tag}"] = "" if item is None else int(item["full_leak_count"])
            row[f"partial_leak_{key_tag}"] = "" if item is None else int(item["partial_leak_count"])
            row[f"cascade_leak_{key_tag}"] = "" if item is None else int(item["cascade_leak_count"])
        reason = classify_diff_reason(by_variant, selected_variants)
        row["difference_reason"] = reason
        row["task4_category"] = classify_task4_category(by_variant, selected_variants)
        if reason != "same":
            diff_rows.append(row)

        found_variants = []
        for variant in selected_variants:
            item = by_variant[variant]
            if item is not None and bool(item["success"]) and int(item["leak_count"]) > 0:
                found_variants.append(variant)
        if len(found_variants) == 1:
            only_variant = found_variants[0]
            only_item = by_variant[only_variant]
            exclusive_rows.append(
                {
                    "only_variant": only_variant,
                    "project_name": project_name,
                    "file_path": file_path,
                    "mode": mode,
                    "leak_count": int(only_item["leak_count"]),
                    "full_leak_count": int(only_item["full_leak_count"]),
                    "partial_leak_count": int(only_item["partial_leak_count"]),
                    "cascade_leak_count": int(only_item["cascade_leak_count"]),
                }
            )
            for variant in selected_variants:
                exclusive_rows[-1][f"present_{variant.replace('-', '_')}"] = by_variant[variant] is not None

    return diff_rows, exclusive_rows


def write_csv(rows: List[Dict[str, object]], path: Path, fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_markdown(
    summary_by_variant: Dict[str, Dict[str, object]],
    diff_rows: List[Dict[str, object]],
    exclusive_rows: List[Dict[str, object]],
    total_union_items: int,
    input_paths: Dict[str, Path],
    output_paths: Dict[str, Path],
    selected_variants: List[str],
) -> str:
    lines: List[str] = []
    lines.append("# 多变体检测结果对比报告")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    for variant in selected_variants:
        lines.append(f"- {variant} 输入: `{input_paths[variant]}`")
    lines.append("")
    lines.append("## 每个变体检测结果汇总")
    lines.append("")
    lines.append("| 变体 | 总条目 | 成功 | 失败 | 泄露条目 | 泄露信号总数 | FULL | PARTIAL | CASCADE | 分析总耗时(秒) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for variant in selected_variants:
        summary = summary_by_variant[variant]
        lines.append(
            f"| {variant} | {summary['total_items']} | {summary['success_items']} | {summary['failed_items']} | "
            f"{summary['leak_items']} | {summary['total_leak_signals']} | {summary['total_full_leaks']} | "
            f"{summary['total_partial_leaks']} | {summary['total_cascade_leaks']} | {summary['total_analysis_time']:.4f} |"
        )

    reason_counts: Dict[str, int] = {}
    task4_category_counts: Dict[str, int] = {}
    for row in diff_rows:
        reason = str(row["difference_reason"])
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        task4_category = str(row.get("task4_category", "n/a"))
        if task4_category != "n/a":
            task4_category_counts[task4_category] = task4_category_counts.get(task4_category, 0) + 1

    lines.append("")
    lines.append("## 逐项差异概览")
    lines.append("")
    lines.append(f"- 变体键集合总条目: {total_union_items}")
    lines.append(f"- 存在差异条目: {len(diff_rows)}")
    if reason_counts:
        lines.append("- 差异类型统计:")
        for reason, count in sorted(reason_counts.items(), key=lambda x: x[0]):
            lines.append(f"  - {reason}: {count}")
    lines.append(f"- 差异 CSV: `{output_paths['diff_csv']}`")
    lines.append("")

    if task4_category_counts:
        lines.append("## Task4 差异分类说明")
        lines.append("")
        lines.append("- 工具失败：至少一个变体执行失败，导致无法直接比较泄露统计。")
        lines.append("- 保守误报：conservative 泄露数高于 full 且高于 aggressive。")
        lines.append("- 激进召回：aggressive 泄露数高于 conservative，且不低于 full。")
        lines.append("- 其他差异：其余无法归入上述三类的数值差异。")
        lines.append("")
        for category in ("工具失败", "保守误报", "激进召回", "其他差异"):
            lines.append(f"- {category}: {task4_category_counts.get(category, 0)}")
        lines.append("")

    lines.append("## 仅某变体发现项")
    lines.append("")
    lines.append(f"- 仅单一变体发现的泄露条目总数: {len(exclusive_rows)}")
    counts_by_variant = {variant: 0 for variant in selected_variants}
    for row in exclusive_rows:
        counts_by_variant[str(row["only_variant"])] += 1
    for variant in selected_variants:
        lines.append(f"- 仅 {variant} 发现: {counts_by_variant[variant]}")
    lines.append(f"- 仅单变体发现项 CSV: `{output_paths['exclusive_csv']}`")
    lines.append("")

    lines.append("## 差异样例（最多前20条）")
    lines.append("")
    sample_header = "| 项目 | 文件 | 模式 | " + " | ".join(selected_variants) + " | 差异类型 |"
    sample_sep = "|---|---|---|" + "|".join("---:" for _ in selected_variants) + "|---|"
    lines.append(sample_header)
    lines.append(sample_sep)
    for row in diff_rows[:20]:
        leak_columns = " | ".join(str(row[f"leak_{variant.replace('-', '_')}"]) for variant in selected_variants)
        lines.append(
            f"| {row['project_name']} | `{row['file_path']}` | {row['mode']} | {leak_columns} | {row['difference_reason']} |"
        )
    if not diff_rows:
        lines.append("| - | - | - | " + " | ".join("-" for _ in selected_variants) + " | 无差异 |")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    input_paths = parse_variant_input_paths(args)
    selected_variants = [variant for variant in ALL_VARIANTS if variant in input_paths]
    script_dir = Path(__file__).resolve().parent
    default_output_dir = script_dir.parent / "evaluation_results"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else default_output_dir.resolve()
    timestamp = datetime.datetime.now().strftime("%m%d_%H%M")
    output_prefix = args.output_prefix or f"variant_compare_{timestamp}"
    data_by_variant = {
        variant: read_variant_csv(variant, input_paths[variant])
        for variant in selected_variants
    }
    summary_by_variant = {variant: summarize_variant(data_by_variant[variant]) for variant in selected_variants}
    diff_rows, exclusive_rows = build_diff_rows(data_by_variant, selected_variants)
    total_union_items = len(set().union(*(data.keys() for data in data_by_variant.values())))

    output_paths = {
        "diff_csv": output_dir / f"{output_prefix}_differences.csv",
        "exclusive_csv": output_dir / f"{output_prefix}_exclusive_findings.csv",
        "summary_csv": output_dir / f"{output_prefix}_summary.csv",
        "markdown": output_dir / f"{output_prefix}_report.md",
    }

    summary_rows = []
    for variant in selected_variants:
        row = {"variant": variant}
        row.update(summary_by_variant[variant])
        summary_rows.append(row)

    diff_fieldnames = [
        "project_name",
        "file_path",
        "mode",
        "difference_reason",
        "task4_category",
    ]
    metric_columns: List[str] = []
    for variant in selected_variants:
        tag = variant.replace("-", "_")
        metric_columns.extend(
            [
                f"present_{tag}",
                f"success_{tag}",
                f"leak_{tag}",
                f"full_leak_{tag}",
                f"partial_leak_{tag}",
                f"cascade_leak_{tag}",
            ]
        )
    diff_fieldnames = ["project_name", "file_path", "mode"] + metric_columns + ["difference_reason", "task4_category"]
    exclusive_fieldnames = [
        "only_variant",
        "project_name",
        "file_path",
        "mode",
        "leak_count",
        "full_leak_count",
        "partial_leak_count",
        "cascade_leak_count",
    ]
    exclusive_fieldnames.extend([f"present_{variant.replace('-', '_')}" for variant in selected_variants])
    summary_fieldnames = [
        "variant",
        "total_items",
        "success_items",
        "failed_items",
        "leak_items",
        "total_leak_signals",
        "total_full_leaks",
        "total_partial_leaks",
        "total_cascade_leaks",
        "total_analysis_time",
    ]

    write_csv(diff_rows, output_paths["diff_csv"], diff_fieldnames)
    write_csv(exclusive_rows, output_paths["exclusive_csv"], exclusive_fieldnames)
    write_csv(summary_rows, output_paths["summary_csv"], summary_fieldnames)

    markdown = build_markdown(
        summary_by_variant,
        diff_rows,
        exclusive_rows,
        total_union_items,
        input_paths,
        output_paths,
        selected_variants,
    )
    output_paths["markdown"].parent.mkdir(parents=True, exist_ok=True)
    with open(output_paths["markdown"], "w", encoding="utf-8", newline="") as f:
        f.write(markdown)

    print("对比报告已生成:")
    print(f"- Markdown: {output_paths['markdown']}")
    print(f"- 差异表 CSV: {output_paths['diff_csv']}")
    print(f"- 仅单变体发现 CSV: {output_paths['exclusive_csv']}")
    print(f"- 汇总表 CSV: {output_paths['summary_csv']}")
    print(f"- 逐项差异数量: {len(diff_rows)}")
    print(f"- 仅单变体发现数量: {len(exclusive_rows)}")


if __name__ == "__main__":
    main()
