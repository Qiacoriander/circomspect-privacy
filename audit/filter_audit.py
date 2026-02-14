
import csv
import os

def filter_csv(file_path):
    temp_file = file_path + '.tmp'
    total_rows = 0
    kept_rows = 0
    
    with open(file_path, 'r', newline='', encoding='utf-8') as f_in, \
         open(temp_file, 'w', newline='', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            total_rows += 1
            has_output_taint = row.get('has_output_taint', 'False').strip()
            has_quantified_leak = row.get('has_quantified_leak', 'False').strip()
            
            # Condition: keep if either is NOT 'False' (meaning 'True')
            if has_output_taint != 'False' or has_quantified_leak != 'False':
                writer.writerow(row)
                kept_rows += 1

    os.replace(temp_file, file_path)
    print(f"Processed {total_rows} rows. Kept {kept_rows} rows.")

if __name__ == "__main__":
    filter_csv('/Users/zhangwenzhe/Develop/circomspect/audit/audit_record.csv')
