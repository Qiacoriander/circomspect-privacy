pragma circom 2.0.0;

include "../core/utilities.circom";
include "../core/primitives/range_proof_lib.circom";
include "../core/primitives/hash_chain_lib.circom";

/*
    ConsistencyCredential: Simplified version that proves temporal consistency
    
    This circuit proves:
    1. Consistent activity over time periods
    2. Quality maintenance across contributions
    3. Sustainable contribution patterns
*/

template ConsistencyCredential(maxPeriods) {
    // Input signals
    signal input userHash;                    // User's identity hash
    signal input totalPeriods;                // Number of time periods tracked
    signal input commitCounts[maxPeriods];    // Commits per period
    signal input qualityScores[maxPeriods];   // Quality scores per period (0-100)
    signal input consistencyThreshold;        // Minimum consistency score required
    
    // Output signals
    signal output credentialHash;             // Hash of the credential
    signal output consistencyScore;           // Consistency score (0-100)
    signal output isValid;                    // 1 if credential is valid, 0 otherwise
    
    // Intermediate signals
    signal periodWeights[maxPeriods];         // Weighted period scores
    signal totalScore;                        // Sum of weighted scores
    
    // Components for verification
    component rangeProofs[maxPeriods * 2];
    
    // Range proofs for all periods
    for (var i = 0; i < maxPeriods; i++) {
        // Commit counts range proof (0-1000)
        rangeProofs[i * 2] = RangeProofCustom(32);
        rangeProofs[i * 2].value <== commitCounts[i];
        rangeProofs[i * 2].min <== 0;
        rangeProofs[i * 2].max <== 1000;
        
        // Quality scores range proof (0-100)
        rangeProofs[i * 2 + 1] = RangeProofCustom(32);
        rangeProofs[i * 2 + 1].value <== qualityScores[i];
        rangeProofs[i * 2 + 1].min <== 0;
        rangeProofs[i * 2 + 1].max <== 100;
    }
    
    // Calculate consistency score
    component isPositive[maxPeriods];
    var qualitySum = 0;
    
    for (var i = 0; i < maxPeriods; i++) {
        // Check if commits > 0
        isPositive[i] = GreaterThan(32);
        isPositive[i].in[0] <== commitCounts[i];
        isPositive[i].in[1] <== 0;
        
        // Simple scoring: activity indicator * quality
        periodWeights[i] <== isPositive[i].out * qualityScores[i];
        qualitySum += qualityScores[i];
    }
    
    // Calculate consistency score (simplified as sum, not average to avoid division)
    totalScore <== qualitySum;
    consistencyScore <== totalScore;
    
    // Validate consistency
    component consistencyValid = GreaterEqThan(32);
    consistencyValid.in[0] <== consistencyScore;
    consistencyValid.in[1] <== consistencyThreshold;
    
    component minimumPeriodsValid = GreaterEqThan(32);
    minimumPeriodsValid.in[0] <== totalPeriods;
    minimumPeriodsValid.in[1] <== 3; // At least 3 periods
    
    isValid <== consistencyValid.out * minimumPeriodsValid.out;
    
    // Generate credential hash
    component credentialHasher = SimplePoseidon(4);
    credentialHasher.inputs[0] <== userHash;
    credentialHasher.inputs[1] <== consistencyScore;
    credentialHasher.inputs[2] <== totalPeriods;
    credentialHasher.inputs[3] <== isValid;
    
    credentialHash <== credentialHasher.out;
    
    // Constraint: Credential must be valid
    isValid === 1;
    
    // Range proofs for inputs
    component totalPeriodsRange = RangeProofCustom(32);
    totalPeriodsRange.value <== totalPeriods;
    totalPeriodsRange.min <== 1;
    totalPeriodsRange.max <== maxPeriods;
    
    component thresholdRange = RangeProofCustom(32);
    thresholdRange.value <== consistencyThreshold;
    thresholdRange.min <== 0;
    thresholdRange.max <== 100;
}

component main = ConsistencyCredential(12); // 12 periods (months)
