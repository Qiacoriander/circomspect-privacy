pragma circom 2.0.0;

include "../core/primitives/merkle_tree_lib.circom";
include "../core/primitives/range_proof_lib.circom";
include "../core/primitives/set_membership_lib.circom";
include "../core/utilities.circom";

/*
    LeadershipCredential: Simplified version that proves technical leadership capabilities
    
    This circuit proves:
    1. Technical mentoring and knowledge sharing
    2. Project leadership and delivery responsibility
    3. Team coordination and influence
*/

template LeadershipCredential(maxActivities) {
    // Input signals
    signal input userHash;                     // Hash of user identity
    signal input activityHashes[maxActivities]; // Hashes of leadership activities
    signal input activityScores[maxActivities]; // Impact scores (1-10)
    signal input totalActivities;             // Actual number of activities
    signal input yearsOfLeadership;           // Years of leadership experience
    signal input leadershipThreshold;         // Minimum leadership score required

    // Output signals
    signal output credentialHash;             // Hash of the credential
    signal output leadershipScore;            // Overall leadership score (0-100)
    signal output isValid;                    // 1 if credential is valid, 0 otherwise

    // Intermediate signals
    signal activityWeights[maxActivities];    // Weighted activity scores
    signal totalScore;                        // Sum of weighted scores

    // Components for verification
    component rangeProofs[maxActivities];

    // Range proofs for all activity scores (1-10)
    for (var i = 0; i < maxActivities; i++) {
        rangeProofs[i] = RangeProofCustom(32);
        rangeProofs[i].value <== activityScores[i];
        rangeProofs[i].min <== 0;
        rangeProofs[i].max <== 10;
    }

    // Components for conditional logic
    component isNonZero[maxActivities];
    
    // Calculate weighted scores for each activity
    var scoreSum = 0;
    for (var i = 0; i < maxActivities; i++) {
        isNonZero[i] = IsZero();
        isNonZero[i].in <== activityHashes[i];
        activityWeights[i] <== activityScores[i] * (1 - isNonZero[i].out);
        scoreSum += activityWeights[i];
    }

    // Calculate leadership score with experience bonus
    totalScore <== scoreSum;
    leadershipScore <== totalScore * 10 / maxActivities + yearsOfLeadership * 2; // Experience bonus

    // Validate credential (must meet minimum threshold)
    component leadershipValid = GreaterEqThan(32);
    leadershipValid.in[0] <== leadershipScore;
    leadershipValid.in[1] <== leadershipThreshold;
    
    component minimumActivitiesValid = GreaterEqThan(32);
    minimumActivitiesValid.in[0] <== totalActivities;
    minimumActivitiesValid.in[1] <== 3; // At least 3 leadership activities

    component minimumExperienceValid = GreaterEqThan(32);
    minimumExperienceValid.in[0] <== yearsOfLeadership;
    minimumExperienceValid.in[1] <== 1; // At least 1 year

    signal tempValid <== leadershipValid.out * minimumActivitiesValid.out;
    isValid <== tempValid * minimumExperienceValid.out;

    // Generate credential hash
    component credentialHasher = SimplePoseidon(5);
    credentialHasher.inputs[0] <== userHash;
    credentialHasher.inputs[1] <== leadershipScore;
    credentialHasher.inputs[2] <== totalActivities;
    credentialHasher.inputs[3] <== yearsOfLeadership;
    credentialHasher.inputs[4] <== isValid;

    credentialHash <== credentialHasher.out;

    // Constraint: Credential must be valid
    isValid === 1;

    // Range proofs for inputs
    component totalActivitiesRange = RangeProofCustom(32);
    totalActivitiesRange.value <== totalActivities;
    totalActivitiesRange.min <== 1;
    totalActivitiesRange.max <== maxActivities;

    component yearsRange = RangeProofCustom(32);
    yearsRange.value <== yearsOfLeadership;
    yearsRange.min <== 0;
    yearsRange.max <== 50; // Max 50 years

    component thresholdRange = RangeProofCustom(32);
    thresholdRange.value <== leadershipThreshold;
    thresholdRange.min <== 0;
    thresholdRange.max <== 100;
}

component main = LeadershipCredential(10);
