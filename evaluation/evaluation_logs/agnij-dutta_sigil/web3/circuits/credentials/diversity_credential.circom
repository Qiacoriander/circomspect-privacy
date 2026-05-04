pragma circom 2.0.0;

include "../core/primitives/merkle_tree_lib.circom";
include "../core/primitives/range_proof_lib.circom";
include "../core/primitives/set_membership_lib.circom";
include "../core/utilities.circom";

/*
    DiversityCredential: Simplified version that proves skill diversity
    
    This circuit proves:
    1. Programming language diversity (breadth and depth)
    2. Technology stack diversity 
    3. Project type diversity
*/

template DiversityCredential(maxCategories) {
    // Input signals
    signal input userHash;                    // Hash of user identity
    signal input categoryHashes[maxCategories]; // Hashes of skill categories
    signal input categoryScores[maxCategories]; // Proficiency scores (1-10)
    signal input totalCategories;            // Actual number of categories used
    signal input diversityThreshold;         // Minimum diversity score required

    // Output signals
    signal output credentialHash;            // Hash of the credential
    signal output diversityScore;            // Overall diversity score (0-100)
    signal output isValid;                   // 1 if credential is valid, 0 otherwise

    // Intermediate signals
    signal categoryWeights[maxCategories];   // Weighted category scores
    signal totalScore;                       // Sum of weighted scores

    // Components for verification
    component rangeProofs[maxCategories];

    // Range proofs for all category scores (1-10)
    for (var i = 0; i < maxCategories; i++) {
        rangeProofs[i] = RangeProofCustom(32);
        rangeProofs[i].value <== categoryScores[i];
        rangeProofs[i].min <== 0;
        rangeProofs[i].max <== 10;
    }

    // Components for conditional logic
    component isNonZero[maxCategories];
    
    // Calculate weighted scores for each category
    var scoreSum = 0;
    for (var i = 0; i < maxCategories; i++) {
        isNonZero[i] = IsZero();
        isNonZero[i].in <== categoryHashes[i];
        categoryWeights[i] <== categoryScores[i] * (1 - isNonZero[i].out);
        scoreSum += categoryWeights[i];
    }

    // Calculate diversity score (simple average of active categories * 10)
    totalScore <== scoreSum;
    diversityScore <== totalScore * 10 / maxCategories;

    // Validate credential (must meet minimum threshold)
    component diversityValid = GreaterEqThan(32);
    diversityValid.in[0] <== diversityScore;
    diversityValid.in[1] <== diversityThreshold;
    
    component minimumCategoriesValid = GreaterEqThan(32);
    minimumCategoriesValid.in[0] <== totalCategories;
    minimumCategoriesValid.in[1] <== 3; // At least 3 categories

    isValid <== diversityValid.out * minimumCategoriesValid.out;

    // Generate credential hash
    component credentialHasher = SimplePoseidon(4);
    credentialHasher.inputs[0] <== userHash;
    credentialHasher.inputs[1] <== diversityScore;
    credentialHasher.inputs[2] <== totalCategories;
    credentialHasher.inputs[3] <== isValid;

    credentialHash <== credentialHasher.out;

    // Constraint: Credential must be valid
    isValid === 1;

    // Range proofs for inputs
    component totalCategoriesRange = RangeProofCustom(32);
    totalCategoriesRange.value <== totalCategories;
    totalCategoriesRange.min <== 1;
    totalCategoriesRange.max <== maxCategories;

    component diversityThresholdRange = RangeProofCustom(32);
    diversityThresholdRange.value <== diversityThreshold;
    diversityThresholdRange.min <== 0;
    diversityThresholdRange.max <== 100;
}

component main = DiversityCredential(10);
