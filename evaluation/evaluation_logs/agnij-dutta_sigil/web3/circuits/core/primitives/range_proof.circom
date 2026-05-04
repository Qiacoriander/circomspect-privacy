pragma circom 2.0.0;

include "../utilities.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Range Proof Circuit
 * 
 * Proves that a private value is within a specified range [min, max]
 * without revealing the actual value
 * Used for LOC counts, commit counts, collaboration percentages, etc.
 */

template RangeProof() {
    // Public inputs
    signal input min;
    signal input max;
    signal input commitment; // Hash of the secret value
    
    // Private inputs
    signal input value;
    signal input nonce;
    
    // Outputs
    signal output valid;
    
    // Verify the commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== nonce;
    
    component commitmentCheck = IsEqual();
    commitmentCheck.in[0] <== hasher.out;
    commitmentCheck.in[1] <== commitment;
    
    // Check that min <= value <= max
    component minCheck = GreaterEqThan(64);
    minCheck.in[0] <== value;
    minCheck.in[1] <== min;
    
    component maxCheck = LessEqThan(64);
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== max;
    
    // All checks must pass
    component andGate1 = AND();
    andGate1.a <== commitmentCheck.out;
    andGate1.b <== minCheck.out;
    
    component andGate2 = AND();
    andGate2.a <== andGate1.out;
    andGate2.b <== maxCheck.out;
    
    valid <== andGate2.out;
}

/*
 * Range Proof with Custom Bit Length
 */
template RangeProofCustom(n) {
    signal input min;
    signal input max;
    signal input value;
    signal output valid;
    
    // Check bounds
    component minCheck = GreaterEqThan(n);
    minCheck.in[0] <== value;
    minCheck.in[1] <== min;
    
    component maxCheck = LessEqThan(n);
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== max;
    
    component andGate = AND();
    andGate.a <== minCheck.out;
    andGate.b <== maxCheck.out;
    
    valid <== andGate.out;
}

/*
 * Multi-Range Proof
 * 
 * Proves multiple values are each within their respective ranges
 * More efficient than individual range proofs
 */
template MultiRangeProof(n, bitWidth) {
    signal input values[n];
    signal input mins[n];
    signal input maxs[n];
    signal output valid;
    
    component rangeChecks[n];
    component andGates[n > 1 ? n - 1 : 1];
    
    // Check each range
    for (var i = 0; i < n; i++) {
        rangeChecks[i] = RangeProofCustom(bitWidth);
        rangeChecks[i].value <== values[i];
        rangeChecks[i].min <== mins[i];
        rangeChecks[i].max <== maxs[i];
    }
    
    // AND all results
    if (n == 1) {
        valid <== rangeChecks[0].valid;
    } else {
        andGates[0] = AND();
        andGates[0].a <== rangeChecks[0].valid;
        andGates[0].b <== rangeChecks[1].valid;
        
        for (var i = 1; i < n - 1; i++) {
            andGates[i] = AND();
            andGates[i].a <== andGates[i - 1].out;
            andGates[i].b <== rangeChecks[i + 1].valid;
        }
        
        valid <== andGates[n - 2].out;
    }
}

/*
 * Percentage Range Proof
 * 
 * Specialized for proving percentages (0-100)
 * with additional validation
 */
template PercentageProof() {
    signal input percentage;      // Value to prove is valid percentage
    signal input minPercent;      // Minimum allowed percentage
    signal input maxPercent;      // Maximum allowed percentage
    
    signal output isValidPercent; // 1 if valid percentage in range
    
    // Basic range check
    component rangeCheck = RangeProof();
    rangeCheck.value <== percentage;
    rangeCheck.min <== minPercent;
    rangeCheck.max <== maxPercent;
    
    // Ensure within 0-100 bounds
    component boundsCheck = RangeProof();
    boundsCheck.value <== percentage;
    boundsCheck.min <== 0;
    boundsCheck.max <== 100;
    
    // Both checks must pass
    component and = AND();
    and.a <== rangeCheck.valid;
    and.b <== boundsCheck.valid;
    
    isValidPercent <== and.out;
}

/*
 * Sum Range Proof
 * 
 * Proves that a sum of private values is within a range
 * without revealing individual values or the exact sum
 */
template SumRangeProof(n) {
    signal input values[n];       // Private values to sum
    signal input minSum;          // Minimum allowed sum
    signal input maxSum;          // Maximum allowed sum
    
    signal output sumInRange;     // 1 if sum is in range
    
    // Calculate sum
    var sum = 0;
    for (var i = 0; i < n; i++) {
        sum += values[i];
    }
    
    // Prove sum is in range
    component rangeProof = RangeProof();
    rangeProof.value <== sum;
    rangeProof.min <== minSum;
    rangeProof.max <== maxSum;
    
    sumInRange <== rangeProof.valid;
}

/*
 * Threshold Proof
 * 
 * Proves a value meets a minimum threshold
 * Used for meaningful usage proofs (minimum LOC, commits, etc.)
 */
template ThresholdProof() {
    signal input value;          // Private value to check
    signal input threshold;      // Minimum threshold (public)
    
    signal output meetsThreshold; // 1 if value >= threshold
    
    component geq = GreaterEqThan(32);
    geq.in[0] <== value;
    geq.in[1] <== threshold;
    
    meetsThreshold <== geq.out;
}

/*
 * Multi-Threshold Proof
 * 
 * Proves multiple values each meet their respective thresholds
 */
template MultiThresholdProof(n) {
    signal input values[n];       // Private values to check
    signal input thresholds[n];   // Minimum thresholds for each
    
    signal output allMeetThreshold; // 1 if all values meet thresholds
    
    component thresholdProofs[n];
    
    for (var i = 0; i < n; i++) {
        thresholdProofs[i] = ThresholdProof();
        thresholdProofs[i].value <== values[i];
        thresholdProofs[i].threshold <== thresholds[i];
    }
    
    // All proofs must be valid
    var allValid = 1;
    for (var i = 0; i < n; i++) {
        allValid *= thresholdProofs[i].meetsThreshold;
    }
    
    allMeetThreshold <== allValid;
}

/*
 * Bounded Difference Proof
 * 
 * Proves that |value1 - value2| <= maxDifference
 * Used for consistency checks
 */
template BoundedDifferenceProof() {
    signal input value1;         // First private value
    signal input value2;         // Second private value  
    signal input maxDifference;  // Maximum allowed difference
    
    signal output withinBounds;  // 1 if difference is bounded
    
    // Calculate absolute difference
    component isGreater = GreaterThan(32);
    isGreater.in[0] <== value1;
    isGreater.in[1] <== value2;
    
    component diff1 = Num2Bits(32);
    diff1.in <== value1 - value2;
    
    component diff2 = Num2Bits(32);
    diff2.in <== value2 - value1;
    
    component selector = Mux1();
    selector.c[0] <== value2 - value1;  // If value1 <= value2
    selector.c[1] <== value1 - value2;  // If value1 > value2
    selector.s <== isGreater.out;
    
    // Check absolute difference <= maxDifference
    component leq = LessEqThan(32);
    leq.in[0] <== selector.out;
    leq.in[1] <== maxDifference;
    
    withinBounds <== leq.out;
}

/*
 * Progressive Range Proof
 * 
 * Proves values are in increasing ranges (useful for experience levels)
 * junior: 0-50 commits, mid: 50-200, senior: 200+
 */
template ProgressiveRangeProof(levels) {
    signal input value;           // Value to categorize
    signal input thresholds[levels]; // Thresholds for each level
    signal input claimedLevel;    // Level user claims (0 to levels-1)
    
    signal output validLevel;     // 1 if value supports claimed level
    
    // Check value meets minimum threshold for claimed level
    component minCheck = GreaterEqThan(32);
    minCheck.in[0] <== value;
    minCheck.in[1] <== thresholds[claimedLevel];
    
    // If not at max level, check value doesn't exceed next threshold
    component maxCheck = LessEqThan(32);
    
    // Use conditional logic for max level
    component isMaxLevel = IsEqual();
    isMaxLevel.in[0] <== claimedLevel;
    isMaxLevel.in[1] <== levels - 1;
    
    component nextThresholdSelector = Mux1();
    nextThresholdSelector.c[0] <== thresholds[claimedLevel + 1]; // Next threshold
    nextThresholdSelector.c[1] <== 2**32 - 1;                   // Max value if at top level
    nextThresholdSelector.s <== isMaxLevel.out;
    
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== nextThresholdSelector.out;
    
    // Both checks must pass
    component and = AND();
    and.a <== minCheck.out;
    and.b <== maxCheck.out;
    
    validLevel <== and.out;
}

// Utility templates
// Utility templates are included from ../utilities.circom

/*
 * Optimized Range Proof using bit decomposition
 */
template OptimizedRangeProof(bits) {
    signal input value;
    signal input min;
    signal input max;
    signal output valid;
    
    // Decompose value into bits
    component valueBits = Num2Bits(bits);
    valueBits.in <== value;
    
    // Check bounds using comparison
    component geqMin = GreaterEqThan(bits);
    geqMin.in[0] <== value;
    geqMin.in[1] <== min;
    
    component leqMax = LessEqThan(bits);
    leqMax.in[0] <== value;
    leqMax.in[1] <== max;
    
    component finalAnd = AND();
    finalAnd.a <== geqMin.out;
    finalAnd.b <== leqMax.out;
    
    valid <== finalAnd.out;
}

/*
 * Range Proof with Zero Knowledge
 * Hides the actual value while proving it's in range
 */
template ZKRangeProof(bits) {
    signal input commitment;
    signal input min;
    signal input max;
    
    // Private inputs
    signal input value;
    signal input salt;
    
    signal output valid;
    
    // Verify commitment
    component commitHash = Poseidon(2);
    commitHash.inputs[0] <== value;
    commitHash.inputs[1] <== salt;
    
    component commitCheck = IsEqual();
    commitCheck.in[0] <== commitHash.out;
    commitCheck.in[1] <== commitment;
    
    // Range check
    component rangeCheck = OptimizedRangeProof(bits);
    rangeCheck.value <== value;
    rangeCheck.min <== min;
    rangeCheck.max <== max;
    
    // Combine results
    component finalAnd = AND();
    finalAnd.a <== commitCheck.out;
    finalAnd.b <== rangeCheck.valid;
    
    valid <== finalAnd.out;
}

// Main component for compilation
component main = RangeProof();
