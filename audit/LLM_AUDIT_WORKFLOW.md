
# LLM Audit Workflow for Privacy Leakage

This document outlines the workflow for an AI agent to audit the privacy leakage results recorded in `audit/audit_record.csv`. The goal is to determine if a reported leakage is a **True Positive** (real security risk) or a **False Positive** (acceptable or expected behavior).

## 1. Preparation

-   **WorkingDirectory**: `/Users/zhangwenzhe/Develop/circomspect`
-   **AuditFile**: `audit/audit_record.csv`
-   **OutputDir**: `audit/outputs` (Ensure this directory exists)
-   **ExecutionCommand**: `target/release/circomspect <FILE_PATH> --mode <MODE> --leak-threshold 8 --min-leak-severity Low`

## 2. Workflow Loop

The agent should iterate through `audit/audit_record.csv` for rows where `audit_result` is empty.

### Step 1: Get Next Task
1.  Read `audit/audit_record.csv`.
2.  Find the first row where `audit_result` is empty.
3.  Extract: `id`, `file_path`.

### Step 2: Retrieve Context
1.  **Read Tool Output**: The tool has already been executed. Read the output from `audit/outputs/<id>.txt`.
    *   *Note*: If the file does not exist or indicates an error, mark `audit_result` as `Error` and move to the next task.
2.  **Read Source Code**: Read the content of `<file_path>`.
    *   *Note*: Resolving the path might require prepending `benchmarks/projects/` if the CSV path is relative.
3.  **Read Included Files**: If the file imports other templates, read those files as well.

### Step 3: LLM Audit Judgment
Act as a Zero-Knowledge Proof Circuit Security Expert. Analyze the leakage report based on the code context.

**Judgment Criteria:**
*   **True Positive (Leak)**:
    *   Private inputs flow to public outputs without proper encryption or hiding (hashing).
    *   Logic bugs allow inferring private inputs from outputs.
    *   *Example*: `output <== private_input;`
*   **False Positive (Safe/Expected)**:
    *   The output is *intended* to be public (e.g., a hash digest of a private commitment).
    *   The "leakage" is actually a mathematical necessity and safe (e.g., public key derivation from private key).
    *   The component is a low-level utility (like `Num2Bits`) whose sole purpose is data transformation, and it is the *caller's* responsibility to protect the data. (Mark as **False Positive** or **Utility**).

**Determine:**
1.  `audit_result`: `True Positive`, `False Positive`, or `Unsure`.
2.  `notes`: An explanation of *why* .

### Step 5: Update Record
1.  Update the row in `audit/audit_record.csv` with the determined `audit_result` and `notes` (the content of `notes` should be relatively detailed, intuitive, and easy to understand). If multiple input signals are involved, try to explain the `audit_result` and `notes` for each signal independently.
2.  Save the CSV file immediately to prevent data loss.

## 3. Instructions for the Agent

*   **Batching**: You may process multiple rows in one session, but update the CSV frequently.
*   **Error Handling**: If the tool fails to run (e.g., compilation error), mark `audit_result` as `Error` and log the error in `notes`.
*   **Self-Correction**: If you cannot find a file, check for path issues (e.g., Windows backslashes `\` vs Unix forward slashes `/`).

---
**Example Entry:**
`1,aes-circom,circuits/aes_256.circom,library,TRUE,FALSE`
-> **Action**: Run tool, Read output.
-> **Analysis**: "Output is ciphertext. Key is private. This is correct encryption."
-> **Result**: `False Positive` (if tool flagged it as leak) OR `True Positive` (if tool correctly identified a side-channel).
*Correction*: If the tool reports "Tainted" for Ciphertext, and the user *wants* to know if it flows to valid outputs, the tool is *correct* that it flows. But is it a *Privacy Violation*? 
*   If the tool says "Leakage: 256 bits" for Ciphertext -> It is a "Taint Flow", but cryptographically safe.
    *   **Thesis Context**: We classify "Safe Encryption Output" as a **False Positive** in terms of *Vulnerability*, even if the Taint logic is correct. We are auditing for *Bugs*.

## 4. Taint Propagation Reference (For Precision)

Use these rules to determine if the *Tool's Logic* was correct, even if the *Security Risk* is low.

### Basic Operations
*   **Arithmetic (+, -, *, /)**: `x ∨ y → z` (**Tainted**). If any input is tainted, output is tainted.
*   **Bitwise (&, |, ^)**: `x → z` (**PartialLeak**). Generally leaks specific bits or probabilistic information.
*   **Assignment (<==, ===)**: `x → z` (**Tainted**). Direct propagation.

### Component Rules
*   **Hash/Encryption (Poseidon, MiMC, EdDSA)**: `Tainted → Downgraded`.
    *   *Interpretation*: These are mathematically "One-Way". The tool considers them safe (Downgraded), but might report them if connected to a public output that *expects* raw data.
    *   *Audit*: If a `Downgraded` signal flows to a public output that is *intended* to be a commitment/digest, this is a **False Positive** (Safe).
*   **Comparators (LessThan, IsEqual)**: `Tainted → PartialLeak` (1 bit).
    *   *Audit*: Leaking a boolean result of a private comparison is usually *necessary* for ZK logic (e.g., range check). Mark as **False Positive** if the logic implies a validity check.
*   **Bit Decomposition (Num2Bits)**: `Tainted → Tainted` (Array of bits).
    *   *Audit*: This is a utility. If the bits are then constrained (e.g., `bits[i] === 0`), it's a constraint. If the bits are *output* publicly, it's a **True Positive** (Leak).

### Risk Classification
*   **Critical**: Tainted signal flows directly to public output.
*   **High**: >8 bits of partial leakage (e.g., loop accumulation).
*   **Medium/Low**: <8 bits (e.g., single comparison or bit extraction).


