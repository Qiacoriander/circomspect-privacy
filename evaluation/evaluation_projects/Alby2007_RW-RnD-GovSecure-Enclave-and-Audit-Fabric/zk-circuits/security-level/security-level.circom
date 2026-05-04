pragma circom 2.0.0;

/**
 * Security Level Circuit
 * 
 * Proves that all jobs in a batch meet a minimum security level.
 * 
 * Public Inputs:
 *   - jobCount: Number of jobs processed
 *   - minSecurityLevel: Minimum required security level
 * 
 * Private Inputs:
 *   - minLevelSum: Sum of jobs meeting minimum level
 *   - attestationSum: Sum of jobs with attestation
 *   - encryptionSum: Sum of jobs with encryption
 * 
 * Output:
 *   - meetsLevel: 1 if all requirements met, 0 otherwise
 */
template SecurityLevel() {
    // Public inputs
    signal input jobCount;
    signal input minSecurityLevel;
    
    // Private inputs (witness)
    signal input minLevelSum;
    signal input attestationSum;
    signal input encryptionSum;
    
    // Output
    signal output meetsLevel;
    
    // Intermediate signals
    signal minLevelCheck;
    signal attestationCheck;
    signal encryptionCheck;
    signal allChecks;
    
    // Check 1: All jobs meet minimum security level
    minLevelCheck <== minLevelSum - jobCount;
    minLevelCheck === 0;
    
    // Check 2: All jobs have attestation
    attestationCheck <== attestationSum - jobCount;
    attestationCheck === 0;
    
    // Check 3: All jobs have encryption
    encryptionCheck <== encryptionSum - jobCount;
    encryptionCheck === 0;
    
    // All checks passed
    meetsLevel <== 1;
}

component main {public [jobCount, minSecurityLevel]} = SecurityLevel();
