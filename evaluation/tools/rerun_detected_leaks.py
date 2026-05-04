import argparse
import csv
import subprocess
import time
from pathlib import Path


def build_command(circomspect_path: str | None, circuit_file: Path, mode: str, variant: str) -> list[str]:
    if circomspect_path:
        cmd = [circomspect_path]
    else:
        cmd = ["cargo", "run", "--release", "--bin", "circomspect", "--"]
    rust_mode = "all" if mode == "library" else mode
    cmd.extend([str(circuit_file), "--mode", rust_mode, "--ccig-variant", variant])
    return cmd


def safe_log_name(file_path: str, mode: str, used_names: set[str]) -> str:
    base_name = Path(file_path).name
    candidate = f"{base_name}.log"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    stem = base_name.replace(".", "_")
    i = 2
    while True:
        candidate = f"{stem}__{mode}__{i}.log"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        i += 1


def to_int(row: dict, key: str) -> int:
    try:
        return int(row.get(key, "0"))
    except Exception:
        return 0


def filter_leak_rows(rows: list[dict]) -> list[dict]:
    filtered = []
    for row in rows:
        full_leak = to_int(row, "full_leak_count")
        partial_leak = to_int(row, "partial_leak_count")
        if full_leak > 0 or partial_leak > 0:
            filtered.append(row)
    return filtered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--filtered-csv", default=None)
    parser.add_argument("--projects-dir", default="evaluation/evaluation_projects")
    parser.add_argument("--logs-root", default="evaluation/evaluation_logs")
    parser.add_argument("--circomspect", default=None)
    parser.add_argument("--variant-override", default=None)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    input_csv = Path(args.input_csv)
    if not input_csv.exists():
        print(f"输入文件不存在: {input_csv}")
        return 1

    filtered_csv = Path(args.filtered_csv) if args.filtered_csv else input_csv.with_name(f"{input_csv.stem}_detected_leaks.csv")
    projects_dir = Path(args.projects_dir)
    logs_root = Path(args.logs_root)
    logs_root.mkdir(parents=True, exist_ok=True)

    with open(input_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    leak_rows = filter_leak_rows(rows)
    if args.limit > 0:
        leak_rows = leak_rows[: args.limit]

    with open(filtered_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(leak_rows)

    print(f"筛选完成: {len(leak_rows)} 条，输出: {filtered_csv}")

    success = 0
    failed = 0

    used_names_by_project: dict[str, set[str]] = {}

    for row in leak_rows:
        project_name = row.get("project_name", "").strip()
        file_path = row.get("file_path", "").strip()
        mode = row.get("mode", "main").strip() or "main"
        variant = (args.variant_override or row.get("variant", "full")).strip() or "full"

        circuit_file = projects_dir / file_path
        project_log_dir = logs_root / project_name
        project_log_dir.mkdir(parents=True, exist_ok=True)
        used_names = used_names_by_project.setdefault(project_name, set())
        log_file = project_log_dir / safe_log_name(file_path, mode, used_names)

        if not circuit_file.exists():
            log_file.write_text(f"文件不存在: {circuit_file}\n", encoding="utf-8")
            print(f"[缺失] {project_name} | {file_path}")
            failed += 1
            continue

        cmd = build_command(args.circomspect, circuit_file, mode, variant)
        start = time.time()
        proc = subprocess.Popen(
            cmd,
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output, _ = proc.communicate()
        elapsed = time.time() - start

        with open(log_file, "w", encoding="utf-8", newline="") as f:
            f.write(output or "")
            f.write(f"\n\n[meta] return_code={proc.returncode} elapsed={elapsed:.3f}s\n")
            f.write(f"[meta] cmd={' '.join(cmd)}\n")

        if proc.returncode in (0, 1):
            success += 1
            print(f"[完成] {project_name} | {file_path} | rc={proc.returncode}")
        else:
            failed += 1
            print(f"[失败] {project_name} | {file_path} | rc={proc.returncode}")

    print(f"执行完成: 成功={success}, 失败={failed}, 日志目录={logs_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
