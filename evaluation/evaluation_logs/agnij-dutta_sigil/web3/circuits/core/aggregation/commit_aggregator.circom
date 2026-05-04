pragma circom 2.0.0;

include "../utilities.circom";
include "../primitives/range_proof.circom";

/*
 * CommitAggregator combines multiple commit proofs into aggregate statistics
 * Proves total commits and LOC ranges across multiple repositories
 */
template CommitAggregator(maxRepos) {
    // Inputs: Array of commit counts per repository
    signal input commitCounts[maxRepos];
    signal input repositoryHashes[maxRepos];
    signal input validRepos; // Number of valid repositories
    
    // Outputs: Aggregated statistics
    signal output totalCommits;
    signal output repoCount;
    signal output aggregateHash;
    signal output isValid;
    
    // Internal signals
    signal runningSum[maxRepos + 1];
    signal validRepoCount[maxRepos + 1];
    
    // Initialize
    runningSum[0] <== 0;
    validRepoCount[0] <== 0;
    
    // Aggregate commit counts and count valid repos
    component isPositive[maxRepos];
    for (var i = 0; i < maxRepos; i++) {
        isPositive[i] = GreaterThan(32);
        isPositive[i].in[0] <== commitCounts[i];
        isPositive[i].in[1] <== 0;
        
        runningSum[i + 1] <== runningSum[i] + commitCounts[i];
        validRepoCount[i + 1] <== validRepoCount[i] + isPositive[i].out;
    }
    
    totalCommits <== runningSum[maxRepos];
    repoCount <== validRepoCount[maxRepos];
    
    // Verify repo count matches claimed valid repos
    component countCheck = IsEqual();
    countCheck.in[0] <== repoCount;
    countCheck.in[1] <== validRepos;
    
    // Create aggregate hash of all repository hashes
    component hasher = Poseidon(maxRepos);
    for (var i = 0; i < maxRepos; i++) {
        hasher.inputs[i] <== repositoryHashes[i];
    }
    aggregateHash <== hasher.out;
    
    // Range check: total commits should be reasonable
    component rangeCheck = RangeProofCustom(32);
    rangeCheck.value <== totalCommits;
    rangeCheck.min <== 1;
    rangeCheck.max <== 1000000; // Max 1M commits total
    
    // Combine validity checks
    component validityAnd = AND();
    validityAnd.a <== countCheck.out;
    validityAnd.b <== rangeCheck.valid;
    
    isValid <== validityAnd.out;
}

/*
 * LOCAggregator aggregates Lines of Code across repositories
 */
template LOCAggregator(maxRepos) {
    signal input locCounts[maxRepos];
    signal input validRepos;
    
    signal output totalLOC;
    signal output avgLOCPerRepo;
    signal output locDistributionHash;
    signal output isValid;
    
    signal runningLOCSum[maxRepos + 1];
    runningLOCSum[0] <== 0;
    
    component isValidLOC[maxRepos];
    var validLOCCount = 0;
    
    for (var i = 0; i < maxRepos; i++) {
        isValidLOC[i] = GreaterThan(32);
        isValidLOC[i].in[0] <== locCounts[i];
        isValidLOC[i].in[1] <== 0;
        
        runningLOCSum[i + 1] <== runningLOCSum[i] + locCounts[i];
        validLOCCount += isValidLOC[i].out;
    }
    
    totalLOC <== runningLOCSum[maxRepos];
    
    // Calculate average (simplified division)
    component divider = SafeDivision(32);
    divider.dividend <== totalLOC;
    divider.divisor <== validRepos;
    avgLOCPerRepo <== divider.quotient;
    
    // Create distribution hash
    component locHasher = Poseidon(maxRepos);
    for (var i = 0; i < maxRepos; i++) {
        locHasher.inputs[i] <== locCounts[i];
    }
    locDistributionHash <== locHasher.out;
    
    // Validate total LOC is reasonable
    component locRangeCheck = RangeProofCustom(32);
    locRangeCheck.value <== totalLOC;
    locRangeCheck.min <== 1;
    locRangeCheck.max <== 10000000; // Max 10M LOC total
    
    isValid <== locRangeCheck.valid;
}

// SafeDivision template removed - using from utilities.circom

// Utility templates removed - using from utilities.circom

// Main component removed - this is a library circuit
