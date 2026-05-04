pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/**
 * VeriChain Trust Score Range Circuit
 * 
 * This circuit allows a user to prove their trust score falls within
 * a certain range without revealing the exact score.
 * 
 * Public Inputs:
 * - minScore: Minimum required trust score
 * - maxScore: Maximum trust score (optional, can be 100)
 * - commitment: Hash of (actualScore, secret, userAddress)
 * 
 * Private Inputs:
 * - actualScore: User's actual trust score
 * - secret: User's secret for commitment
 * - userAddress: User's wallet address (as field element)
 */
template TrustScoreRange() {
    // Public inputs
    signal input minScore;
    signal input maxScore;
    signal input commitment;
    
    // Private inputs
    signal input actualScore;
    signal input secret;
    signal input userAddress;
    
    // Output
    signal output inRange;
    
    // Verify commitment
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== actualScore;
    poseidon.inputs[1] <== secret;
    poseidon.inputs[2] <== userAddress;
    commitment === poseidon.out;
    
    // Check actualScore >= minScore
    component gte = GreaterEqThan(8); // 8 bits for 0-255 range
    gte.in[0] <== actualScore;
    gte.in[1] <== minScore;
    
    // Check actualScore <= maxScore
    component lte = LessEqThan(8);
    lte.in[0] <== actualScore;
    lte.in[1] <== maxScore;
    
    // Both conditions must be true
    inRange <== gte.out * lte.out;
    
    // Ensure result is 1 (in range)
    inRange === 1;
}

component main {public [minScore, maxScore, commitment]} = TrustScoreRange();
