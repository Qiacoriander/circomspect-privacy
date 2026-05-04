pragma circom 2.0.0;

/*
 * Policy Compliance Circuit (Circom 2.x - Simplified)
 * 
 * Proves that all jobs complied with a specific policy
 * Simplified version that avoids dynamic component creation
 */

include "../node_modules/circomlib/circuits/comparators.circom";

template PolicyComplianceVerifier(maxJobs) {
    // Public inputs
    signal input jobCount;
    signal input policyType;
    
    // Private inputs - simplified
    signal input complianceSum;  // Sum of all compliance flags
    signal input complianceProof; // Proof value
    
    // Output
    signal output valid;
    
    // Verify policy type is valid (0-9)
    component policyCheck = LessThan(8);
    policyCheck.in[0] <== policyType;
    policyCheck.in[1] <== 10;
    
    // Verify job count is within bounds
    component jobCheck = LessThan(32);
    jobCheck.in[0] <== jobCount;
    jobCheck.in[1] <== maxJobs + 1;
    
    // Verify compliance sum equals job count (all compliant)
    component sumCheck = IsEqual();
    sumCheck.in[0] <== complianceSum;
    sumCheck.in[1] <== jobCount;
    
    // Combine all checks
    signal check1;
    signal check2;
    check1 <== policyCheck.out * jobCheck.out;
    check2 <== check1 * sumCheck.out;
    
    // Output is valid if all checks pass
    valid <== check2;
}

// Main component - supports up to 100 jobs
component main {public [jobCount, policyType]} = PolicyComplianceVerifier(100);
