pragma circom 2.0.0;

/*
 * Security Level Circuit (Circom 2.x - Simplified)
 * 
 * Proves that all jobs met a minimum security level
 * Simplified version that avoids dynamic component creation
 */

include "../node_modules/circomlib/circuits/comparators.circom";

template SecurityLevelVerifier(maxJobs) {
    // Public inputs
    signal input jobCount;
    signal input minSecurityLevel;
    
    // Private inputs - simplified
    signal input minLevelSum;  // Sum of (level >= minLevel) for all jobs
    signal input attestationSum; // Sum of attestation flags
    signal input encryptionSum;  // Sum of encryption flags
    
    // Output
    signal output valid;
    
    // Verify minimum security level is valid (1-5)
    component minCheck1 = GreaterThan(8);
    minCheck1.in[0] <== minSecurityLevel;
    minCheck1.in[1] <== 0;
    
    component minCheck2 = LessThan(8);
    minCheck2.in[0] <== minSecurityLevel;
    minCheck2.in[1] <== 6;
    
    // Verify job count is within bounds
    component jobCheck = LessThan(32);
    jobCheck.in[0] <== jobCount;
    jobCheck.in[1] <== maxJobs + 1;
    
    // Verify all jobs meet minimum level
    component levelCheck = IsEqual();
    levelCheck.in[0] <== minLevelSum;
    levelCheck.in[1] <== jobCount;
    
    // If minLevel >= 3, all must have attestation
    component needsAttestation = GreaterEqThan(8);
    needsAttestation.in[0] <== minSecurityLevel;
    needsAttestation.in[1] <== 3;
    
    component attestationCheck = IsEqual();
    attestationCheck.in[0] <== attestationSum;
    attestationCheck.in[1] <== jobCount * needsAttestation.out;
    
    // If minLevel >= 4, all must have encryption
    component needsEncryption = GreaterEqThan(8);
    needsEncryption.in[0] <== minSecurityLevel;
    needsEncryption.in[1] <== 4;
    
    component encryptionCheck = IsEqual();
    encryptionCheck.in[0] <== encryptionSum;
    encryptionCheck.in[1] <== jobCount * needsEncryption.out;
    
    // Combine all checks
    signal check1;
    signal check2;
    signal check3;
    signal check4;
    check1 <== minCheck1.out * minCheck2.out;
    check2 <== check1 * jobCheck.out;
    check3 <== check2 * levelCheck.out;
    check4 <== check3 * attestationCheck.out;
    
    // Output is valid if all checks pass
    valid <== check4 * encryptionCheck.out;
}

// Main component - supports up to 100 jobs
component main {public [jobCount, minSecurityLevel]} = SecurityLevelVerifier(100);
