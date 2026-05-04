pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

/**
 * @title UniversityRankProof
 * @dev Prove that a university is within a certain ranking range without revealing exact rank
 * Example: Prove university is in top 100 without revealing if it's #5 or #87
 */
template UniversityRankProof() {
    // Private inputs
    signal input universityId;
    signal input actualRank;
    signal input universityName; // Hashed value
    signal input credentialId;
    
    // Public inputs
    signal input minRank; // Lower bound (e.g., 1)
    signal input maxRank; // Upper bound (e.g., 100)
    signal input credentialHash; // Hash to verify credential authenticity
    
    // Outputs
    signal output isInRankRange;
    signal output isValidCredential;
    
    // Verify credential hash
    component hasher = Poseidon(4);
    hasher.inputs[0] <== universityId;
    hasher.inputs[1] <== actualRank;
    hasher.inputs[2] <== universityName;
    hasher.inputs[3] <== credentialId;
    
    signal hashDiff;
    hashDiff <== hasher.out - credentialHash;
    hashDiff === 0;
    isValidCredential <== 1;
    
    // Check if actualRank >= minRank
    component greaterEqMin = GreaterEqThan(32);
    greaterEqMin.in[0] <== actualRank;
    greaterEqMin.in[1] <== minRank;
    
    // Check if actualRank <= maxRank
    component lessEqMax = LessEqThan(32);
    lessEqMax.in[0] <== actualRank;
    lessEqMax.in[1] <== maxRank;
    
    // Rank is in range if BOTH conditions are true
    isInRankRange <== greaterEqMin.out * lessEqMax.out;
    
    // Ensure output is binary
    isInRankRange * (1 - isInRankRange) === 0;
    
    // Add constraint: rank must be positive and reasonable (1-10000)
    component rankPositive = GreaterThan(32);
    rankPositive.in[0] <== actualRank;
    rankPositive.in[1] <== 0;
    rankPositive.out === 1;
    
    component rankReasonable = LessThan(32);
    rankReasonable.in[0] <== actualRank;
    rankReasonable.in[1] <== 10001;
    rankReasonable.out === 1;
}

component main {public [minRank, maxRank, credentialHash]} = UniversityRankProof();
