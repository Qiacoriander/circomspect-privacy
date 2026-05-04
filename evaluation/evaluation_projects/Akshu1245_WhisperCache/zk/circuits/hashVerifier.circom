pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

/*
 * Simple Hash Verifier Circuit
 * 
 * A minimal circuit for testing the ZK pipeline.
 * Proves knowledge of a preimage without revealing it.
 * 
 * Inputs:
 *   - preimage: The secret value (private)
 *   - hash: The expected Poseidon hash (public)
 * 
 * Outputs:
 *   - valid: 1 if hash(preimage) == hash, 0 otherwise
 */

template HashVerifier() {
    // Private input
    signal input preimage;
    
    // Public input
    signal input hash;
    
    // Output
    signal output valid;
    
    // Compute Poseidon hash of preimage
    component hasher = Poseidon(1);
    hasher.inputs[0] <== preimage;
    
    // Check if computed hash equals expected hash
    signal diff;
    diff <== hasher.out - hash;
    
    // If diff is 0, they match
    // Use IsZero pattern
    signal isZero;
    signal inv;
    inv <-- diff != 0 ? 1/diff : 0;
    isZero <== 1 - diff * inv;
    diff * isZero === 0;
    
    valid <== isZero;
}

component main {public [hash]} = HashVerifier();
