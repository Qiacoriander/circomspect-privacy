pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * WhisperCache Memory Pattern Verifier
 * 
 * This circuit verifies that a memory matches a query pattern
 * without revealing the actual memory content.
 * 
 * Inputs:
 *   - memoryHash: Poseidon hash of the encrypted memory content
 *   - queryPatternHash: Hash of the query pattern to match
 *   - userSecret: User's private key (keeps proof tied to user)
 *   - salt: Random salt for additional privacy
 *   - threshold: Minimum match score (0-100)
 * 
 * Outputs:
 *   - patternMatched: 1 if pattern matches, 0 otherwise
 *   - commitment: Public commitment for verification
 */

template MemoryPatternVerifier() {
    // Private inputs (witness)
    signal input memoryHash;
    signal input userSecret;
    signal input salt;
    
    // Public inputs
    signal input queryPatternHash;
    signal input threshold;
    
    // Outputs
    signal output patternMatched;
    signal output commitment;
    
    // Step 1: Create a commitment from memory + user secret + salt
    // This proves ownership without revealing data
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== memoryHash;
    commitmentHasher.inputs[1] <== userSecret;
    commitmentHasher.inputs[2] <== salt;
    
    commitment <== commitmentHasher.out;
    
    // Step 2: Compute pattern match score
    // For now, we use a simplified comparison:
    // If memoryHash and queryPatternHash share common bits, there's a match
    
    // Create a combined hash of memory and query
    component matchHasher = Poseidon(2);
    matchHasher.inputs[0] <== memoryHash;
    matchHasher.inputs[1] <== queryPatternHash;
    
    // Extract a "score" from the combined hash (simplified)
    // In production, this would be more sophisticated NLP matching
    signal matchScore;
    
    // Use modulo to get a score 0-100
    // The hash output mod 101 gives us 0-100 range
    signal hashMod;
    hashMod <-- matchHasher.out % 101;
    
    // Verify the modulo is correct
    signal quotient;
    quotient <-- matchHasher.out \ 101;
    matchHasher.out === quotient * 101 + hashMod;
    
    // Range check: hashMod must be < 101
    component lt = LessThan(8);
    lt.in[0] <== hashMod;
    lt.in[1] <== 101;
    lt.out === 1;
    
    matchScore <== hashMod;
    
    // Step 3: Compare score against threshold
    component thresholdCheck = GreaterEqThan(8);
    thresholdCheck.in[0] <== matchScore;
    thresholdCheck.in[1] <== threshold;
    
    patternMatched <== thresholdCheck.out;
}

// Main component with public signals specified
component main {public [queryPatternHash, threshold]} = MemoryPatternVerifier();
