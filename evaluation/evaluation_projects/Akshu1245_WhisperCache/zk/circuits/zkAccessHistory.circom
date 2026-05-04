pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * ZK Access History Circuit
 * 
 * Proves access history without revealing:
 * - Who accessed what
 * - When specific accesses occurred
 * - The content that was accessed
 * 
 * This circuit enables:
 * 1. Proving N accesses occurred in a time range
 * 2. Proving all accesses were authorized
 * 3. Proving access patterns match policy
 * 
 * Inputs (Private):
 *   - accessHashes[4]: Hashes of individual access events
 *   - accessorSecrets[4]: Secrets proving authorization
 *   - timestamps[4]: When each access occurred
 * 
 * Inputs (Public):
 *   - policyHash: Hash of the access policy
 *   - startTime: Start of the time range
 *   - endTime: End of the time range
 *   - expectedAccessCount: Number of accesses to prove
 * 
 * Outputs:
 *   - historyValid: 1 if access history is valid
 *   - accessCount: Number of valid accesses found
 *   - historyCommitment: Merkle root of access history
 */

template ZKAccessHistory() {
    var MAX_ACCESSES = 4;
    
    // Private inputs
    signal input accessHashes[MAX_ACCESSES];
    signal input accessorSecrets[MAX_ACCESSES];
    signal input timestamps[MAX_ACCESSES];
    
    // Public inputs
    signal input policyHash;
    signal input startTime;
    signal input endTime;
    signal input expectedAccessCount;
    
    // Outputs
    signal output historyValid;
    signal output accessCount;
    signal output historyCommitment;
    
    // Intermediate signals
    signal validAccess[MAX_ACCESSES];
    signal inTimeRange[MAX_ACCESSES];
    signal authorized[MAX_ACCESSES];
    signal runningCount[MAX_ACCESSES + 1];
    
    runningCount[0] <== 0;
    
    // Check each access
    for (var i = 0; i < MAX_ACCESSES; i++) {
        // Check if access is non-zero (exists)
        signal accessExists;
        signal accessInv;
        accessInv <-- accessHashes[i] != 0 ? 1/accessHashes[i] : 0;
        accessExists <== accessHashes[i] * accessInv;
        
        // Check if timestamp is in range
        component gtStart = GreaterEqThan(64);
        gtStart.in[0] <== timestamps[i];
        gtStart.in[1] <== startTime;
        
        component ltEnd = LessEqThan(64);
        ltEnd.in[0] <== timestamps[i];
        ltEnd.in[1] <== endTime;
        
        inTimeRange[i] <== gtStart.out * ltEnd.out;
        
        // Check authorization
        component authHasher = Poseidon(2);
        authHasher.inputs[0] <== accessHashes[i];
        authHasher.inputs[1] <== accessorSecrets[i];
        
        // For simplicity, we check if auth hash relates to policy
        // In production, this would be more sophisticated
        signal authCheck;
        authCheck <== authHasher.out - policyHash;
        
        signal authInv;
        authInv <-- authCheck != 0 ? 1/authCheck : 0;
        authorized[i] <== 1 - authCheck * authInv;
        authCheck * authorized[i] === 0;
        
        // Access is valid if: exists AND in time range AND authorized
        // For non-existent accesses (hash=0), we skip the check
        signal partialValid;
        partialValid <== inTimeRange[i] * authorized[i];
        validAccess[i] <== accessExists * partialValid + (1 - accessExists);
        
        // Count valid accesses that exist
        runningCount[i + 1] <== runningCount[i] + (accessExists * partialValid);
    }
    
    accessCount <== runningCount[MAX_ACCESSES];
    
    // Check if count matches expected
    signal countCheck;
    countCheck <== accessCount - expectedAccessCount;
    
    signal countInv;
    countInv <-- countCheck != 0 ? 1/countCheck : 0;
    signal countMatches;
    countMatches <== 1 - countCheck * countInv;
    countCheck * countMatches === 0;
    
    // All accesses must be valid
    signal allValid[MAX_ACCESSES];
    allValid[0] <== validAccess[0];
    for (var i = 1; i < MAX_ACCESSES; i++) {
        allValid[i] <== allValid[i-1] * validAccess[i];
    }
    
    historyValid <== allValid[MAX_ACCESSES - 1] * countMatches;
    
    // Create history commitment (Merkle-like structure)
    component merkle1 = Poseidon(2);
    merkle1.inputs[0] <== accessHashes[0];
    merkle1.inputs[1] <== accessHashes[1];
    
    component merkle2 = Poseidon(2);
    merkle2.inputs[0] <== accessHashes[2];
    merkle2.inputs[1] <== accessHashes[3];
    
    component merkleRoot = Poseidon(2);
    merkleRoot.inputs[0] <== merkle1.out;
    merkleRoot.inputs[1] <== merkle2.out;
    
    historyCommitment <== merkleRoot.out;
}

component main {public [policyHash, startTime, endTime, expectedAccessCount]} = ZKAccessHistory();
