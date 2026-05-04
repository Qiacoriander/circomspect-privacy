pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * GPA Proof Circuit
 * Proves that a candidate's GPA is greater than or equal to a threshold
 * without revealing the actual GPA value
 * 
 * Inputs:
 *   - gpa: Actual GPA (scaled by 100, e.g., 3.75 -> 375)
 *   - threshold: Minimum required GPA (scaled by 100)
 *   - salt: Random salt for commitment
 *   - credentialHash: Hash of the credential on-chain
 * 
 * Outputs:
 *   - commitment: Poseidon hash of (gpa, salt)
 *   - valid: 1 if gpa >= threshold, 0 otherwise
 */
template GPAProof() {
    // Private inputs
    signal input gpa;
    signal input salt;
    signal input credentialHash;
    
    // Public inputs
    signal input threshold;
    signal input expectedCommitment;
    
    // Outputs
    signal output valid;
    
    // Constants
    var MAX_GPA = 400; // 4.0 scaled by 100
    var MIN_GPA = 0;
    
    // Constraint: GPA must be in valid range (0 to 4.0)
    component gpaRangeCheck = LessEqThan(32);
    gpaRangeCheck.in[0] = gpa;
    gpaRangeCheck.in[1] = MAX_GPA;
    gpaRangeCheck.out === 1;
    
    component gpaMinCheck = GreaterEqThan(32);
    gpaMinCheck.in[0] = gpa;
    gpaMinCheck.in[1] = MIN_GPA;
    gpaMinCheck.out === 1;
    
    // Check if GPA >= threshold
    component gpaCheck = GreaterEqThan(32);
    gpaCheck.in[0] = gpa;
    gpaCheck.in[1] = threshold;
    valid <== gpaCheck.out;
    
    // Compute commitment using Poseidon hash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== gpa;
    hasher.inputs[1] <== salt;
    hasher.inputs[2] <== credentialHash;
    
    // Verify commitment matches expected value
    hasher.out === expectedCommitment;
}

component main {public [threshold, expectedCommitment]} = GPAProof();


