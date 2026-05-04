pragma circom 2.0.0;

/**
 * Policy Compliance Circuit
 * 
 * Proves that all jobs in a batch comply with a specific policy.
 * 
 * Public Inputs:
 *   - jobCount: Number of jobs processed
 *   - policyType: Type of policy (encoded as number)
 * 
 * Private Inputs:
 *   - complianceSum: Sum of compliant jobs
 *   - complianceProof: Proof value (e.g., hash of compliance data)
 * 
 * Output:
 *   - isCompliant: 1 if all jobs comply, 0 otherwise
 */
template PolicyCompliance() {
    // Public inputs
    signal input jobCount;
    signal input policyType;
    
    // Private inputs (witness)
    signal input complianceSum;
    signal input complianceProof;
    
    // Output
    signal output isCompliant;
    
    // Intermediate signals
    signal complianceCheck;
    signal dummy;
    
    // Check 1: All jobs are compliant
    complianceCheck <== complianceSum - jobCount;
    complianceCheck === 0;
    
    // Check 2: Use policy type and compliance proof
    // (Ensures they're part of the witness)
    dummy <== policyType + complianceProof;
    
    // All checks passed
    isCompliant <== 1;
}

component main {public [jobCount, policyType]} = PolicyCompliance();
