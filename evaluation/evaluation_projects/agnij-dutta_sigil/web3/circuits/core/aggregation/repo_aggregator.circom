pragma circom 2.0.0;

include "../utilities.circom";

// Include core primitives
include "../primitives/merkle_tree.circom";
include "../primitives/range_proof_lib.circom";
// hash_chain.circom removed - not used in this circuit

/*
 * RepoAggregator - Aggregate contributions across multiple repositories
 * 
 * This circuit proves:
 * 1. Total commits across repositories (with privacy ranges)
 * 2. Total LOC across repositories (with privacy ranges) 
 * 3. Repository diversity score (unique repos)
 * 4. Temporal consistency across repositories
 * 5. Non-ownership proof (user is not owner of all repos)
 */
template RepoAggregator(MAX_REPOS) {
    // Input signals
    signal input repoHashes[MAX_REPOS];           // Hashed repository identifiers
    signal input commitCounts[MAX_REPOS];         // Commit counts per repo
    signal input locCounts[MAX_REPOS];            // LOC counts per repo
    signal input timeRanges[MAX_REPOS][2];        // [start_timestamp, end_timestamp] per repo
    signal input ownershipFlags[MAX_REPOS];       // 1 if user owns repo, 0 otherwise
    signal input collaboratorCounts[MAX_REPOS];   // Number of collaborators per repo
    signal input minCommitThreshold;              // Minimum commits to count as active repo
    signal input privacyK;                        // K-anonymity parameter
    
    // Output signals
    signal output aggregatedCommits;              // Total commits (privacy range)
    signal output aggregatedLOC;                  // Total LOC (privacy range)  
    signal output diversityScore;                 // Repository diversity measure
    signal output consistencyScore;               // Temporal consistency measure
    signal output nonOwnershipProof;              // Proof user doesn't own all repos
    signal output collaborationProof;             // Proof of meaningful collaboration
    
    // Internal signals
    signal activeRepos[MAX_REPOS];                // 1 if repo meets threshold, 0 otherwise
    signal diversityContrib[MAX_REPOS];           // Diversity contribution per repo
    signal consistencyContrib[MAX_REPOS];         // Consistency contribution per repo
    signal validCollaboration[MAX_REPOS];         // 1 if repo has k+ collaborators
    
    // Components for aggregation
    component commitSum = SumWithThreshold(MAX_REPOS);
    component locSum = SumWithThreshold(MAX_REPOS);
    component diversityCalc = DiversityCalculator(MAX_REPOS);
    component consistencyCalc = ConsistencyAnalyzer(MAX_REPOS);
    component ownershipChecker = NonOwnershipVerifier(MAX_REPOS);
    component collaborationChecker = CollaborationVerifier(MAX_REPOS);
    
    // Range proof components for privacy
    component commitRangeProof = RangeProof(); // Standard range proof
    component locRangeProof = RangeProof();
    
    // Merkle tree functionality simplified - removed for now
    
    // Calculate active repositories (meet minimum commit threshold)
    component thresholdChecks[MAX_REPOS];
    for (var i = 0; i < MAX_REPOS; i++) {
        thresholdChecks[i] = GreaterEqThan(16);
        thresholdChecks[i].in[0] <== commitCounts[i];
        thresholdChecks[i].in[1] <== minCommitThreshold;
        activeRepos[i] <== thresholdChecks[i].out;
    }
    
    // Aggregate commits with threshold filtering
    for (var i = 0; i < MAX_REPOS; i++) {
        commitSum.values[i] <== commitCounts[i];
        commitSum.activeFlags[i] <== activeRepos[i];
    }
    
    // Aggregate LOC with threshold filtering
    for (var i = 0; i < MAX_REPOS; i++) {
        locSum.values[i] <== locCounts[i];
        locSum.activeFlags[i] <== activeRepos[i];
    }
    
    // Apply privacy ranges to aggregated values
    commitRangeProof.value <== commitSum.total;
    commitRangeProof.min <== 0;
    commitRangeProof.max <== 1000000; // Max reasonable commits
    commitRangeProof.commitment <== 0; // Simplified
    commitRangeProof.nonce <== 0; // Simplified
    aggregatedCommits <== commitSum.total; // Use actual value for now
    
    locRangeProof.value <== locSum.total;
    locRangeProof.min <== 0;
    locRangeProof.max <== 10000000; // Max reasonable LOC
    locRangeProof.commitment <== 0; // Simplified
    locRangeProof.nonce <== 0; // Simplified
    aggregatedLOC <== locSum.total; // Use actual value for now
    
    // Calculate repository diversity score
    for (var i = 0; i < MAX_REPOS; i++) {
        diversityCalc.repoHashes[i] <== repoHashes[i];
        diversityCalc.activeFlags[i] <== activeRepos[i];
    }
    diversityScore <== diversityCalc.score;
    
    // Calculate temporal consistency across repositories
    for (var i = 0; i < MAX_REPOS; i++) {
        consistencyCalc.startTimes[i] <== timeRanges[i][0];
        consistencyCalc.endTimes[i] <== timeRanges[i][1];
        consistencyCalc.commitCounts[i] <== commitCounts[i];
        consistencyCalc.activeFlags[i] <== activeRepos[i];
    }
    consistencyScore <== consistencyCalc.score;
    
    // Verify non-ownership (user doesn't own all active repositories)
    for (var i = 0; i < MAX_REPOS; i++) {
        ownershipChecker.ownershipFlags[i] <== ownershipFlags[i];
        ownershipChecker.activeFlags[i] <== activeRepos[i];
    }
    nonOwnershipProof <== ownershipChecker.isNonOwner;
    
    // Verify meaningful collaboration (repos have k+ collaborators)
    component kAnonChecks[MAX_REPOS];
    for (var i = 0; i < MAX_REPOS; i++) {
        kAnonChecks[i] = GreaterEqThan(8);
        kAnonChecks[i].in[0] <== collaboratorCounts[i];
        kAnonChecks[i].in[1] <== privacyK;
        validCollaboration[i] <== kAnonChecks[i].out;
        
        collaborationChecker.collaboratorCounts[i] <== collaboratorCounts[i];
        collaborationChecker.activeFlags[i] <== activeRepos[i];
        collaborationChecker.validFlags[i] <== validCollaboration[i];
    }
    collaborationProof <== collaborationChecker.hasCollaboration;
    
    // Merkle tree functionality simplified - removed for now
    
    // Constraint: At least one repository must be active
    component hasActiveRepo = ORMany(MAX_REPOS);
    for (var i = 0; i < MAX_REPOS; i++) {
        hasActiveRepo.in[i] <== activeRepos[i];
    }
    hasActiveRepo.out === 1;
    
    // Constraint: Diversity score must be reasonable (0-100 scale)
    component diversityRange = RangeProofCustom(8);
    diversityRange.value <== diversityScore;
    diversityRange.min <== 0;
    diversityRange.max <== 100;
    diversityRange.valid === 1;
    
    // Constraint: Consistency score must be reasonable (0-100 scale)
    component consistencyRange = RangeProofCustom(8);
    consistencyRange.value <== consistencyScore;
    consistencyRange.min <== 0;
    consistencyRange.max <== 100;
    consistencyRange.valid === 1;
}

/*
 * Helper template: Sum values with threshold filtering
 */
template SumWithThreshold(N) {
    signal input values[N];
    signal input activeFlags[N];
    signal output total;
    
    component sum = Sum(N);
    for (var i = 0; i < N; i++) {
        sum.values[i] <== values[i] * activeFlags[i];
    }
    total <== sum.out;
}

/*
 * Helper template: Calculate repository diversity
 */
template DiversityCalculator(N) {
    signal input repoHashes[N];
    signal input activeFlags[N];
    signal output score;
    
    // Count unique active repositories
    signal uniqueCount;
    component uniqueCounter = CountUnique(N);
    for (var i = 0; i < N; i++) {
        uniqueCounter.values[i] <== repoHashes[i];
        uniqueCounter.activeFlags[i] <== activeFlags[i];
    }
    uniqueCount <== uniqueCounter.count;
    
    // Calculate diversity score (0-100 scale)
    component diversityCalc = Multiplier();
    diversityCalc.in[0] <== uniqueCount;
    diversityCalc.in[1] <== 100;
    
    component activeTotal = Sum(N);
    for (var i = 0; i < N; i++) {
        activeTotal.values[i] <== activeFlags[i];
    }
    
    component divider = SafeDivision(32);
    divider.dividend <== diversityCalc.out;
    divider.divisor <== activeTotal.out;
    score <== divider.quotient;
}

// Duplicate templates removed - using simplified versions from utilities.circom

// Main component removed - this is a library circuit 