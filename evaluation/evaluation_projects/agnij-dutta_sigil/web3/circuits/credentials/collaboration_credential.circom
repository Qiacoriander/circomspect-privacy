pragma circom 2.0.0;

include "../core/primitives/range_proof_lib.circom";
include "../core/utilities.circom";

/*
 * CollaborationCredential Circuit - Simplified Version
 * 
 * Proves collaboration in team environments:
 * 1. Repository had multiple collaborators
 * 2. User was not the sole contributor
 * 3. User's contribution percentage was reasonable
 */

template CollaborationCredential(maxCollaborators) {
    // Input signals
    signal input userHash;                   // User's identity hash
    signal input actualCollaborators;        // Actual number of collaborators
    signal input userContributionPercentage; // User's contribution % (0-100)
    signal input maxContributionPercent;     // Max reasonable contribution % (e.g., 70%)
    signal input collaborationThreshold;     // Minimum collaboration score required
    
    // Output signals
    signal output credentialHash;            // Hash of the credential
    signal output collaborationScore;        // Collaboration score (0-100)
    signal output isValid;                   // 1 if valid collaboration proven
    
    // Intermediate signals
    signal teamSizeScore;                    // Score based on team size
    signal contributionScore;                // Score based on contribution distribution
    
    // Components for verification
    component rangeProofs[3];
    
    // Range proof for collaborator count (2-maxCollaborators)
    rangeProofs[0] = RangeProofCustom(32);
    rangeProofs[0].value <== actualCollaborators;
    rangeProofs[0].min <== 2;
    rangeProofs[0].max <== maxCollaborators;
    
    // Range proof for user contribution percentage (0-100)
    rangeProofs[1] = RangeProofCustom(32);
    rangeProofs[1].value <== userContributionPercentage;
    rangeProofs[1].min <== 0;
    rangeProofs[1].max <== 100;
    
    // Range proof for max contribution threshold (0-100)
    rangeProofs[2] = RangeProofCustom(32);
    rangeProofs[2].value <== maxContributionPercent;
    rangeProofs[2].min <== 0;
    rangeProofs[2].max <== 100;
    
    // Verify minimum team size (at least 2 people)
    component minTeamSize = GreaterEqThan(32);
    minTeamSize.in[0] <== actualCollaborators;
    minTeamSize.in[1] <== 2;
    
    // Verify user wasn't dominant contributor
    component contributionCheck = LessEqThan(32);
    contributionCheck.in[0] <== userContributionPercentage;
    contributionCheck.in[1] <== maxContributionPercent;
    
    // Calculate team size score (larger teams get higher scores)
    teamSizeScore <== actualCollaborators * 10; // 10 points per collaborator
    
    // Calculate contribution score (lower user contribution = higher collaboration)
    contributionScore <== 100 - userContributionPercentage;
    
    // Calculate overall collaboration score
    collaborationScore <== (teamSizeScore + contributionScore) / 2;
    
    // Validate collaboration
    component collaborationValid = GreaterEqThan(32);
    collaborationValid.in[0] <== collaborationScore;
    collaborationValid.in[1] <== collaborationThreshold;
    
    // Combine all validations
    signal tempValid <== minTeamSize.out * contributionCheck.out;
    isValid <== tempValid * collaborationValid.out;
    
    // Generate credential hash
    component credentialHasher = SimplePoseidon(5);
    credentialHasher.inputs[0] <== userHash;
    credentialHasher.inputs[1] <== actualCollaborators;
    credentialHasher.inputs[2] <== userContributionPercentage;
    credentialHasher.inputs[3] <== collaborationScore;
    credentialHasher.inputs[4] <== isValid;
    
    credentialHash <== credentialHasher.out;
    
    // Constraint: Credential must be valid
    isValid === 1;
    
    // Range proof for collaboration threshold
    component thresholdRange = RangeProofCustom(32);
    thresholdRange.value <== collaborationThreshold;
    thresholdRange.min <== 0;
    thresholdRange.max <== 100;
}

component main = CollaborationCredential(10);
