pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Experience Proof Circuit
 * Proves that a candidate has at least X years of work experience
 * without revealing the exact experience duration or job details
 * 
 * Inputs:
 *   - experienceMonths: Total work experience in months
 *   - requiredMonths: Minimum required experience in months
 *   - salt: Random salt for commitment
 *   - credentialHash: Hash of the credential on-chain
 * 
 * Outputs:
 *   - commitment: Poseidon hash of (experienceMonths, salt)
 *   - valid: 1 if experienceMonths >= requiredMonths, 0 otherwise
 */
template ExperienceProof() {
    // Private inputs
    signal input experienceMonths;
    signal input salt;
    signal input credentialHash;
    
    // Public inputs
    signal input requiredMonths;
    signal input expectedCommitment;
    
    // Outputs
    signal output valid;
    
    // Constants
    var MAX_EXPERIENCE = 600; // 50 years in months
    var MIN_EXPERIENCE = 0;
    
    // Constraint: Experience must be in valid range
    component expRangeCheck = LessEqThan(32);
    expRangeCheck.in[0] = experienceMonths;
    expRangeCheck.in[1] = MAX_EXPERIENCE;
    expRangeCheck.out === 1;
    
    component expMinCheck = GreaterEqThan(32);
    expMinCheck.in[0] = experienceMonths;
    expMinCheck.in[1] = MIN_EXPERIENCE;
    expMinCheck.out === 1;
    
    // Check if experience >= required
    component expCheck = GreaterEqThan(32);
    expCheck.in[0] = experienceMonths;
    expCheck.in[1] = requiredMonths;
    valid <== expCheck.out;
    
    // Compute commitment using Poseidon hash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== experienceMonths;
    hasher.inputs[1] <== salt;
    hasher.inputs[2] <== credentialHash;
    
    // Verify commitment matches expected value
    hasher.out === expectedCommitment;
}

component main {public [requiredMonths, expectedCommitment]} = ExperienceProof();


