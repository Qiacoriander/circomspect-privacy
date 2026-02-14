
import csv
import os
import subprocess
import time

# Configuration
CSV_FILE = '/Users/zhangwenzhe/Develop/circomspect/audit/audit_record.csv'
OUTPUT_DIR = '/Users/zhangwenzhe/Develop/circomspect/audit/outputs'
TOOL_PATH = '/Users/zhangwenzhe/Develop/circomspect/target/release/circomspect'
PROJECT_ROOT = '/Users/zhangwenzhe/Develop/circomspect'

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_audit_execution():
    print(f"Starting audit execution...")
    print(f"CSV File: {CSV_FILE}")
    print(f"Output Dir: {OUTPUT_DIR}")
    
    rows = []
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    print(f"Total tasks: {total}")

    for i, row in enumerate(rows):
        task_id = row['id']
        file_path = row['file_path']
        mode = row['mode'] # 'library' or 'main'
        
        # Construct output file path
        output_file = os.path.join(OUTPUT_DIR, f"{task_id}.txt")
        
        # Skip if already exists AND was successful (check content for "Exit Code: 0" or "Exit Code: 1")
        # Exit Code 1 means issues found, which is a valid result for us.
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if "Exit Code: 0" in content or "Exit Code: 1" in content:
                    print(f"[{i+1}/{total}] Skipping ID {task_id}: Output already exists.")
                    continue
                else:
                    print(f"[{i+1}/{total}] Re-processing ID {task_id}: Previous run failed (Code != 0/1).")


        print(f"[{i+1}/{total}] Processing ID {task_id}: {file_path} ({mode})")
        
        # Resolve file path relative to project root if needed
        # The CSV paths seem to use Windows backslashes, convert to forward slashes
        abs_file_path = os.path.join(PROJECT_ROOT, 'benchmarks', 'projects', file_path.replace('\\', '/'))

        # Command construction
        # Map 'library' mode in CSV to 'all' mode for the tool
        tool_mode = 'all' if mode == 'library' else mode

        cmd = [
            TOOL_PATH,
            abs_file_path,
            '--mode', tool_mode,
            '--leak-threshold', '8',
            '--min-leak-severity', 'Low'
        ]

        try:
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60 # Set a timeout to prevent hanging
            )
            duration = time.time() - start_time
            
            # Save output
            with open(output_file, 'w', encoding='utf-8') as out_f:
                out_f.write(f"Command: {' '.join(cmd)}\n")
                out_f.write(f"Exit Code: {result.returncode}\n")
                out_f.write(f"Duration: {duration:.2f}s\n")
                out_f.write("-" * 40 + "\n")
                out_f.write("STDOUT:\n")
                out_f.write(result.stdout)
                out_f.write("\n" + "-" * 40 + "\n")
                out_f.write("STDERR:\n")
                out_f.write(result.stderr)
                
            print(f"    -> Finished in {duration:.2f}s. Exit code: {result.returncode}")

        except subprocess.TimeoutExpired:
            print(f"    -> TIMEOUT after 60s")
            with open(output_file, 'w', encoding='utf-8') as out_f:
                out_f.write(f"Command: {' '.join(cmd)}\n")
                out_f.write("ERROR: Timeout after 60s\n")
        except Exception as e:
            print(f"    -> ERROR: {e}")
            with open(output_file, 'w', encoding='utf-8') as out_f:
                out_f.write(f"ERROR: Exception occurred: {e}\n")

    print("\nBatch execution phase completed.")

if __name__ == "__main__":
    run_audit_execution()
