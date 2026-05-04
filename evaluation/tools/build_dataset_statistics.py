import argparse
import csv
import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


KEYWORD_HASH = ("poseidon", "mimc7", "pedersen", "eddsa", "mimcsponge", "hasher", "keccak", "hashbytes", "sha256", "blake", "commit")
KEYWORD_COMPARE = ("lessthan", "greaterthan", "lesseqthan", "greatereqthan", "iszero", "isequal", "compconstant", "comparator")
KEYWORD_LOGIC = ("and", "or", "xor", "not", "nand", "nor", "gate", "switch")
INCLUDE_RE = re.compile(r'\binclude\s+["\']([^"\']+)["\']\s*;', re.IGNORECASE)
MAIN_RE = re.compile(r"\bcomponent\s+main\b", re.IGNORECASE)
TEMPLATE_RE = re.compile(r"\btemplate\s+([A-Za-z_]\w*)\s*\(", re.IGNORECASE)
COMPONENT_CALL_RE = re.compile(r"\bcomponent\s+[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*=\s*([A-Za-z_]\w*)\s*\(", re.IGNORECASE)
MAIN_COMPONENT_RE = re.compile(
    r"\bcomponent\s+main\s*(\{[^}]*\})?\s*=\s*([A-Za-z_]\w*)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
PUBLIC_LIST_RE = re.compile(r"\bpublic\s*\[([^\]]*)\]", re.IGNORECASE | re.DOTALL)
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
DIM_RE = re.compile(r"\[(.*?)\]")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_]\w*")


@dataclass
class ProjectStats:
    project_name: str
    status: str
    failure_reason: str
    main_entry_count: int
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建评测数据集统计流水线")
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects", help="评测项目根目录")
    parser.add_argument("--circomlib-dir", default="circomlib/circuits", help="circomlib circuits 目录")
    parser.add_argument("--output-csv", default="evaluation/evaluation_results/dataset_statistics_projects.csv", help="项目级明细 CSV 输出路径")
    parser.add_argument("--output-md", default="evaluation/evaluation_results/dataset_statistics_summary.md", help="论文汇总 Markdown 输出路径")
    parser.add_argument("--output-failures-csv", default="evaluation/evaluation_results/dataset_statistics_failures.csv", help="失败样本 CSV 输出路径")
    parser.add_argument("--small-upper", type=int, default=200, help="Small 桶上界（不含）")
    parser.add_argument("--medium-upper", type=int, default=1000, help="Medium 桶上界（含）")
    return parser.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def strip_comments(content: str) -> str:
    no_block = BLOCK_COMMENT_RE.sub("", content)
    return LINE_COMMENT_RE.sub("", no_block)


def count_loc(content: str) -> int:
    cleaned = strip_comments(content)
    return sum(1 for line in cleaned.splitlines() if line.strip())


def split_top_level_commas(expr: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    depth_round = 0
    depth_square = 0
    depth_curly = 0
    for ch in expr:
        if ch == "," and depth_round == 0 and depth_square == 0 and depth_curly == 0:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
            continue
        current.append(ch)
        if ch == "(":
            depth_round += 1
        elif ch == ")":
            depth_round = max(depth_round - 1, 0)
        elif ch == "[":
            depth_square += 1
        elif ch == "]":
            depth_square = max(depth_square - 1, 0)
        elif ch == "{":
            depth_curly += 1
        elif ch == "}":
            depth_curly = max(depth_curly - 1, 0)
    token = "".join(current).strip()
    if token:
        parts.append(token)
    return parts


def try_parse_int(text: str) -> int:
    value = text.strip()
    if not value:
        return 1
    if re.fullmatch(r"\d+", value):
        parsed = int(value)
        if parsed <= 0 or parsed > 10000:
            return 1
        return parsed
    return 1


def estimate_signal_factor(name_expr: str) -> int:
    dims = DIM_RE.findall(name_expr)
    factor = 1
    for dim in dims:
        factor *= try_parse_int(dim)
    return max(factor, 1)


def parse_signal_decl(raw_decl: str) -> Tuple[int, int]:
    normalized = " ".join(raw_decl.replace("\n", " ").replace("\r", " ").split())
    lowered = normalized.lower()
    is_input = bool(re.search(r"\binput\b", lowered))
    is_private = bool(re.search(r"\bprivate\b", lowered))
    body = re.sub(r"\b(input|output|private)\b", " ", normalized, flags=re.IGNORECASE)
    names = split_top_level_commas(body)
    total = 0
    private_total = 0
    for item in names:
        token = item.strip()
        if not token:
            continue
        id_match = IDENTIFIER_RE.match(token)
        if not id_match:
            continue
        factor = estimate_signal_factor(token)
        total += factor
        if is_input and is_private:
            private_total += factor
    return total, private_total


def parse_signal_decl_items(raw_decl: str) -> List[Tuple[str, int, bool]]:
    normalized = " ".join(raw_decl.replace("\n", " ").replace("\r", " ").split())
    lowered = normalized.lower()
    is_input = bool(re.search(r"\binput\b", lowered))
    body = re.sub(r"\b(input|output|private)\b", " ", normalized, flags=re.IGNORECASE)
    names = split_top_level_commas(body)
    items: List[Tuple[str, int, bool]] = []
    for item in names:
        token = item.strip()
        if not token:
            continue
        id_match = IDENTIFIER_RE.match(token)
        if not id_match:
            continue
        factor = estimate_signal_factor(token)
        items.append((id_match.group(0), factor, is_input))
    return items


def parse_signal_stats(content: str) -> Tuple[int, int, int, int]:
    cleaned = strip_comments(content)
    total_expanded = 0
    input_total_expanded = 0
    total_compact = 0
    input_total_compact = 0
    for stmt in cleaned.split(";"):
        fragment = " ".join(stmt.replace("\n", " ").replace("\r", " ").split()).strip()
        if not fragment:
            continue
        if not re.match(r"^signal\b", fragment, flags=re.IGNORECASE):
            continue
        if any(op in fragment for op in ("<==", "==>", ":=", "=")):
            continue
        decl = re.sub(r"^signal\b", "", fragment, flags=re.IGNORECASE).strip()
        items = parse_signal_decl_items(decl)
        for _, factor, is_input in items:
            total_expanded += factor
            total_compact += 1
            if is_input:
                input_total_expanded += factor
                input_total_compact += 1
    return total_expanded, input_total_expanded, total_compact, input_total_compact


def extract_main_specs(content: str) -> List[Tuple[str, Set[str]]]:
    cleaned = strip_comments(content)
    specs: List[Tuple[str, Set[str]]] = []
    for match in MAIN_COMPONENT_RE.finditer(cleaned):
        config_block = match.group(1) or ""
        template_name = (match.group(2) or "").strip()
        public_names: Set[str] = set()
        if config_block:
            pub_match = PUBLIC_LIST_RE.search(config_block)
            if pub_match:
                for token in split_top_level_commas(pub_match.group(1)):
                    ident = IDENTIFIER_RE.match(token.strip())
                    if ident:
                        public_names.add(ident.group(0).lower())
        specs.append((template_name.lower(), public_names))
    return specs


def extract_template_input_index(content: str) -> Dict[str, Dict[str, int]]:
    cleaned = strip_comments(content)
    lines = cleaned.splitlines()
    index: Dict[str, Dict[str, int]] = {}
    current_template = ""
    depth = 0
    pending_signal_stmt = ""

    for line in lines:
        if not current_template:
            start = re.search(r"\btemplate\s+([A-Za-z_]\w*)\s*\(", line, re.IGNORECASE)
            if start:
                current_template = start.group(1).lower()
                index.setdefault(current_template, {})
                depth = line.count("{") - line.count("}")
                pending_signal_stmt = ""
                continue
        else:
            depth += line.count("{") - line.count("}")
            stripped = line.strip()
            if pending_signal_stmt:
                pending_signal_stmt += " " + stripped
                if ";" in stripped:
                    stmt = pending_signal_stmt.split(";", 1)[0].strip()
                    pending_signal_stmt = ""
                    if re.match(r"^signal\b", stmt, flags=re.IGNORECASE):
                        decl = re.sub(r"^signal\b", "", stmt, flags=re.IGNORECASE).strip()
                        for name, factor, is_input in parse_signal_decl_items(decl):
                            if is_input:
                                index[current_template][name.lower()] = factor
            else:
                if re.match(r"^signal\b", stripped, flags=re.IGNORECASE):
                    if ";" in stripped:
                        stmt = stripped.split(";", 1)[0].strip()
                        decl = re.sub(r"^signal\b", "", stmt, flags=re.IGNORECASE).strip()
                        for name, factor, is_input in parse_signal_decl_items(decl):
                            if is_input:
                                index[current_template][name.lower()] = factor
                    else:
                        pending_signal_stmt = stripped
            if depth <= 0:
                current_template = ""
                depth = 0
                pending_signal_stmt = ""
    return index


def is_circomlib_path(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return "/circomlib/circuits/" in normalized or normalized.endswith("/circomlib/circuits")


def contains_main(content: str) -> bool:
    return MAIN_RE.search(strip_comments(content)) is not None


def extract_includes(content: str) -> List[str]:
    cleaned = strip_comments(content)
    return [x.strip() for x in INCLUDE_RE.findall(cleaned) if x.strip()]


def extract_templates(content: str) -> List[str]:
    cleaned = strip_comments(content)
    return TEMPLATE_RE.findall(cleaned)


def extract_component_calls(content: str) -> List[str]:
    cleaned = strip_comments(content)
    return COMPONENT_CALL_RE.findall(cleaned)


def normalize_case_path(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/").lower()


def circomlib_suffix(include_path: str) -> str:
    normalized = include_path.replace("\\", "/")
    marker = "circomlib/"
    idx = normalized.lower().find(marker)
    if idx < 0:
        return ""
    suffix = normalized[idx + len(marker):].strip("/")
    return suffix


def resolve_include(current_file: Path, include_path: str, project_root: Path, circomlib_root: Path) -> Path | None:
    raw = include_path.strip().replace("\\", "/")
    candidates: List[Path] = []
    raw_path = Path(raw)
    if raw_path.is_absolute():
        candidates.append(raw_path)
    candidates.append((current_file.parent / raw_path))
    candidates.append((project_root / raw_path))
    suffix = circomlib_suffix(raw)
    if suffix:
        candidates.append(circomlib_root.parent / suffix)
        candidates.append(project_root.parent / "circomlib" / suffix)
    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def collect_project_main_entries(project_dir: Path) -> List[Path]:
    mains: List[Path] = []
    for circom in project_dir.rglob("*.circom"):
        try:
            text = read_text(circom)
        except OSError:
            continue
        if contains_main(text):
            mains.append(circom.resolve())
    return sorted(set(mains))


def collect_closure(entries: Iterable[Path], project_root: Path, circomlib_root: Path) -> Tuple[Set[Path], List[Tuple[Path, str]]]:
    stack = list(entries)
    visited: Set[str] = set()
    closure: Set[Path] = set()
    unresolved: List[Tuple[Path, str]] = []
    while stack:
        current = Path(stack.pop()).resolve()
        key = normalize_case_path(current)
        if key in visited:
            continue
        visited.add(key)
        if not current.exists() or not current.is_file():
            continue
        closure.add(current)
        try:
            text = read_text(current)
        except OSError:
            continue
        for inc in extract_includes(text):
            resolved = resolve_include(current, inc, project_root, circomlib_root)
            if resolved is None:
                unresolved.append((current, inc))
                continue
            resolved_key = normalize_case_path(resolved)
            if resolved_key not in visited:
                stack.append(resolved)
    return closure, unresolved


def keyword_known(template_name: str) -> bool:
    target = template_name.lower()
    if any(k in target for k in KEYWORD_HASH):
        return True
    if any(k in target for k in KEYWORD_COMPARE):
        return True
    if any(target == k or target == f"{k}gate" for k in KEYWORD_LOGIC):
        return True
    return False


def build_template_file_index(files: Iterable[Path]) -> Dict[str, Set[str]]:
    index: Dict[str, Set[str]] = {}
    for path in files:
        try:
            text = read_text(path)
        except OSError:
            continue
        for template in extract_templates(text):
            lower = template.lower()
            index.setdefault(lower, set()).add(normalize_case_path(path))
    return index


def collect_circomlib_templates(circomlib_root: Path) -> Set[str]:
    templates: Set[str] = set()
    if not circomlib_root.exists():
        return templates
    for circom in circomlib_root.rglob("*.circom"):
        try:
            text = read_text(circom)
        except OSError:
            continue
        for name in extract_templates(text):
            templates.add(name.lower())
    return templates


def calc_project_stats(project_dir: Path, circomlib_root: Path, circomlib_templates: Set[str]) -> ProjectStats:
    project_name = project_dir.name
    entries = collect_project_main_entries(project_dir)
    if not entries:
        return ProjectStats(
            project_name=project_name,
            status="failed",
            failure_reason="no_main_entry",
            main_entry_count=0,
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

    closure, unresolved = collect_closure(entries, project_dir, circomlib_root)
    if not closure:
        return ProjectStats(
            project_name=project_name,
            status="failed",
            failure_reason="empty_closure",
            main_entry_count=len(entries),
            closure_file_count=0,
            unresolved_include_count=len(unresolved),
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
    hit_rate = (known_hits / call_total) if call_total > 0 else 0.0
    private_ratio = (private_signals / signals) if signals > 0 else 0.0
    private_ratio_compact = (
        private_signals_compact / signals_compact
        if signals_compact > 0
        else 0.0
    )
    return ProjectStats(
        project_name=project_name,
        status="ok",
        failure_reason="",
        main_entry_count=len(entries),
        closure_file_count=len(closure),
        unresolved_include_count=len(unresolved),
        loc=loc_total,
        subcircuit_count=subcircuits,
        component_call_count=call_total,
        r_known_hit_count=known_hits,
        r_known_hit_rate=hit_rate,
        signal_count=signals,
        private_signal_count=private_signals,
        private_signal_ratio=private_ratio,
        signal_count_compact=signals_compact,
        private_signal_count_compact=private_signals_compact,
        private_signal_ratio_compact=private_ratio_compact,
    )


def write_projects_csv(rows: List[ProjectStats], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "project_name",
        "status",
        "failure_reason",
        "main_entry_count",
        "closure_file_count",
        "unresolved_include_count",
        "loc",
        "subcircuit_count",
        "component_call_count",
        "r_known_hit_count",
        "r_known_hit_rate",
        "signal_count",
        "private_signal_count",
        "private_signal_ratio",
        "signal_count_compact",
        "private_signal_count_compact",
        "private_signal_ratio_compact",
    ]
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda x: x.project_name.lower()):
            writer.writerow(
                {
                    "project_name": row.project_name,
                    "status": row.status,
                    "failure_reason": row.failure_reason,
                    "main_entry_count": row.main_entry_count,
                    "closure_file_count": row.closure_file_count,
                    "unresolved_include_count": row.unresolved_include_count,
                    "loc": row.loc,
                    "subcircuit_count": row.subcircuit_count,
                    "component_call_count": row.component_call_count,
                    "r_known_hit_count": row.r_known_hit_count,
                    "r_known_hit_rate": f"{row.r_known_hit_rate:.6f}",
                    "signal_count": row.signal_count,
                    "private_signal_count": row.private_signal_count,
                    "private_signal_ratio": f"{row.private_signal_ratio:.6f}",
                    "signal_count_compact": row.signal_count_compact,
                    "private_signal_count_compact": row.private_signal_count_compact,
                    "private_signal_ratio_compact": f"{row.private_signal_ratio_compact:.6f}",
                }
            )


def write_failures_csv(rows: List[ProjectStats], output_csv: Path) -> None:
    failures = [x for x in rows if x.status != "ok"]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project_name", "failure_reason", "main_entry_count", "closure_file_count", "unresolved_include_count"])
        writer.writeheader()
        for row in sorted(failures, key=lambda x: x.project_name.lower()):
            writer.writerow(
                {
                    "project_name": row.project_name,
                    "failure_reason": row.failure_reason,
                    "main_entry_count": row.main_entry_count,
                    "closure_file_count": row.closure_file_count,
                    "unresolved_include_count": row.unresolved_include_count,
                }
            )


def avg(items: List[float]) -> float:
    if not items:
        return 0.0
    return sum(items) / len(items)


def bucket_name(loc: int, small_upper: int, medium_upper: int) -> str:
    if loc < small_upper:
        return "Small"
    if loc <= medium_upper:
        return "Medium"
    return "Large"


def summarize_bucket(rows: List[ProjectStats]) -> Dict[str, float]:
    if not rows:
        return {
            "projects": 0.0,
            "avg_subcircuits": 0.0,
            "avg_r_known_rate_pct": 0.0,
            "avg_signals": 0.0,
            "avg_priv_ratio_pct": 0.0,
            "avg_signals_compact": 0.0,
            "avg_priv_ratio_compact_pct": 0.0,
        }
    total_calls = sum(float(x.component_call_count) for x in rows)
    total_known_hits = sum(float(x.r_known_hit_count) for x in rows)
    total_signals = sum(float(x.signal_count) for x in rows)
    total_private_signals = sum(float(x.private_signal_count) for x in rows)
    total_signals_compact = sum(float(x.signal_count_compact) for x in rows)
    total_private_signals_compact = sum(float(x.private_signal_count_compact) for x in rows)

    return {
        "projects": float(len(rows)),
        "avg_subcircuits": avg([float(x.subcircuit_count) for x in rows]),
        "avg_r_known_rate_pct": (total_known_hits / total_calls * 100.0) if total_calls > 0 else 0.0,
        "avg_signals": avg([float(x.signal_count) for x in rows]),
        "avg_priv_ratio_pct": (total_private_signals / total_signals * 100.0) if total_signals > 0 else 0.0,
        "avg_signals_compact": avg([float(x.signal_count_compact) for x in rows]),
        "avg_priv_ratio_compact_pct": (
            total_private_signals_compact / total_signals_compact * 100.0
        ) if total_signals_compact > 0 else 0.0,
    }


def build_summary_markdown(
    all_rows: List[ProjectStats],
    output_csv: Path,
    output_md: Path,
    failures_csv: Path,
    small_upper: int,
    medium_upper: int,
    projects_dir: Path,
    circomlib_dir: Path,
) -> str:
    ok_rows = [x for x in all_rows if x.status == "ok"]
    failed_rows = [x for x in all_rows if x.status != "ok"]
    buckets: Dict[str, List[ProjectStats]] = {"Small": [], "Medium": [], "Large": []}
    for row in ok_rows:
        buckets[bucket_name(row.loc, small_upper, medium_upper)].append(row)
    bucket_stats = {name: summarize_bucket(rows) for name, rows in buckets.items()}
    total_stats = summarize_bucket(ok_rows)
    lines: List[str] = []
    lines.append("# 评测数据集统计汇总")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 项目目录: `{projects_dir}`")
    lines.append(f"- circomlib 目录: `{circomlib_dir}`")
    lines.append(f"- 项目级明细 CSV: `{output_csv}`")
    lines.append(f"- 失败样本 CSV: `{failures_csv}`")
    lines.append(f"- LOC 分桶边界: Small < {small_upper}, Medium [{small_upper}, {medium_upper}], Large > {medium_upper}")
    lines.append("")
    lines.append("## 论文表格字段汇总")
    lines.append("")
    lines.append("| Scale (LOC) | Projects | Avg. Sub-circuits | Avg. R_known Hit Rate | Avg. Signals | Avg. Priv Signal Ratio |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    lines.append(
        f"| Small (< {small_upper}) | {int(bucket_stats['Small']['projects'])} | {bucket_stats['Small']['avg_subcircuits']:.2f} | "
        f"{bucket_stats['Small']['avg_r_known_rate_pct']:.2f}% | {bucket_stats['Small']['avg_signals']:.2f} | {bucket_stats['Small']['avg_priv_ratio_pct']:.2f}% |"
    )
    lines.append(
        f"| Medium ({small_upper} - {medium_upper}) | {int(bucket_stats['Medium']['projects'])} | {bucket_stats['Medium']['avg_subcircuits']:.2f} | "
        f"{bucket_stats['Medium']['avg_r_known_rate_pct']:.2f}% | {bucket_stats['Medium']['avg_signals']:.2f} | {bucket_stats['Medium']['avg_priv_ratio_pct']:.2f}% |"
    )
    lines.append(
        f"| Large (> {medium_upper}) | {int(bucket_stats['Large']['projects'])} | {bucket_stats['Large']['avg_subcircuits']:.2f} | "
        f"{bucket_stats['Large']['avg_r_known_rate_pct']:.2f}% | {bucket_stats['Large']['avg_signals']:.2f} | {bucket_stats['Large']['avg_priv_ratio_pct']:.2f}% |"
    )
    lines.append(
        f"| **Total / Avg.** | **{int(total_stats['projects'])}** | **{total_stats['avg_subcircuits']:.2f}** | "
        f"**{total_stats['avg_r_known_rate_pct']:.2f}%** | **{total_stats['avg_signals']:.2f}** | **{total_stats['avg_priv_ratio_pct']:.2f}%** |"
    )
    lines.append("")
    lines.append("## 信号口径对照（展开 vs 未展开）")
    lines.append("")
    lines.append("| Scale (LOC) | Avg. Signals (Expanded) | Avg. Signals (Compact) | Avg. Priv Ratio (Expanded) | Avg. Priv Ratio (Compact) |")
    lines.append("|---|---:|---:|---:|---:|")
    lines.append(
        f"| Small (< {small_upper}) | {bucket_stats['Small']['avg_signals']:.2f} | {bucket_stats['Small']['avg_signals_compact']:.2f} | "
        f"{bucket_stats['Small']['avg_priv_ratio_pct']:.2f}% | {bucket_stats['Small']['avg_priv_ratio_compact_pct']:.2f}% |"
    )
    lines.append(
        f"| Medium ({small_upper} - {medium_upper}) | {bucket_stats['Medium']['avg_signals']:.2f} | {bucket_stats['Medium']['avg_signals_compact']:.2f} | "
        f"{bucket_stats['Medium']['avg_priv_ratio_pct']:.2f}% | {bucket_stats['Medium']['avg_priv_ratio_compact_pct']:.2f}% |"
    )
    lines.append(
        f"| Large (> {medium_upper}) | {bucket_stats['Large']['avg_signals']:.2f} | {bucket_stats['Large']['avg_signals_compact']:.2f} | "
        f"{bucket_stats['Large']['avg_priv_ratio_pct']:.2f}% | {bucket_stats['Large']['avg_priv_ratio_compact_pct']:.2f}% |"
    )
    lines.append(
        f"| **Total / Avg.** | **{total_stats['avg_signals']:.2f}** | **{total_stats['avg_signals_compact']:.2f}** | "
        f"**{total_stats['avg_priv_ratio_pct']:.2f}%** | **{total_stats['avg_priv_ratio_compact_pct']:.2f}%** |"
    )
    lines.append("")
    lines.append("## 运行质量")
    lines.append("")
    lines.append(f"- 成功项目数: {len(ok_rows)}")
    lines.append(f"- 失败项目数: {len(failed_rows)}")
    lines.append(f"- 成功项目 unresolved include 总数: {sum(x.unresolved_include_count for x in ok_rows)}")
    lines.append("")
    lines.append("## 可复现实验命令")
    lines.append("")
    lines.append("```bash")
    lines.append(
        "python evaluation/tools/build_dataset_statistics.py "
        f"--projects-dir {projects_dir} --circomlib-dir {circomlib_dir} "
        f"--output-csv {output_csv} --output-md {output_md} "
        f"--output-failures-csv {failures_csv} --small-upper {small_upper} --medium-upper {medium_upper}"
    )
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parent.parent.parent
    projects_dir = (root / args.projects_dir).resolve()
    circomlib_dir = (root / args.circomlib_dir).resolve()
    output_csv = (root / args.output_csv).resolve()
    output_md = (root / args.output_md).resolve()
    output_failures_csv = (root / args.output_failures_csv).resolve()

    if not projects_dir.exists() or not projects_dir.is_dir():
        raise SystemExit(f"projects_dir 不存在: {projects_dir}")
    if not circomlib_dir.exists() or not circomlib_dir.is_dir():
        raise SystemExit(f"circomlib_dir 不存在: {circomlib_dir}")

    circomlib_templates = collect_circomlib_templates(circomlib_dir)
    project_dirs = sorted([p for p in projects_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower())
    rows: List[ProjectStats] = []
    for idx, project_dir in enumerate(project_dirs, start=1):
        row = calc_project_stats(project_dir, circomlib_dir, circomlib_templates)
        rows.append(row)
        print(
            f"[{idx}/{len(project_dirs)}] {project_dir.name}: {row.status}, "
            f"mains={row.main_entry_count}, closure={row.closure_file_count}, "
            f"loc={row.loc}, sub={row.subcircuit_count}, rk={row.r_known_hit_rate:.2%}, "
            f"sig={row.signal_count}, priv_ratio={row.private_signal_ratio:.2%}"
        )

    write_projects_csv(rows, output_csv)
    write_failures_csv(rows, output_failures_csv)
    md = build_summary_markdown(
        rows,
        output_csv=output_csv,
        output_md=output_md,
        failures_csv=output_failures_csv,
        small_upper=args.small_upper,
        medium_upper=args.medium_upper,
        projects_dir=projects_dir,
        circomlib_dir=circomlib_dir,
    )
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(md, encoding="utf-8")

    ok_cnt = sum(1 for x in rows if x.status == "ok")
    fail_cnt = len(rows) - ok_cnt
    print("dataset_statistics_done")
    print(f"projects_total={len(rows)}")
    print(f"projects_ok={ok_cnt}")
    print(f"projects_failed={fail_cnt}")
    print(f"output_csv={output_csv}")
    print(f"output_md={output_md}")
    print(f"output_failures_csv={output_failures_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
