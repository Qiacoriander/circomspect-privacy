pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/**
 * WhisperCache Memory Pattern Verifier
 * 
 * This circuit proves that a user owns a memory and that it matches
 * a certain pattern, WITHOUT revealing the actual memory content.
 * 
 * Private Inputs (witness - never revealed):
 *   - memoryContent: The actual memory content hash
 *   - userSecretKey: User's private key for ownership proof
 * 
 * Public Inputs (on-chain):
 *   - patternHash: Hash of the pattern being queried
 *   - minConfidence: Minimum confidence threshold (scaled by 100)
 *   - publicKeyHash: Hash of user's public key (for ownership)
 * 
 * Public Outputs:
 *   - ownershipValid: 1 if user owns the memory, 0 otherwise
 *   - patternMatched: 1 if pattern matches, 0 otherwise
 *   - confidenceScore: Computed confidence (0-100)
 */

template MemoryPatternVerifier() {
    // Private inputs (witness)
    signal input memoryContent;
    signal input userSecretKey;
    signal input memoryNonce;
    
    // Public inputs
    signal input patternHash;
    signal input minConfidence;
    signal input publicKeyHash;
    
    // Public outputs
    signal output ownershipValid;
    signal output patternMatched;
    signal output confidenceScore;
    signal output commitmentHash;
    
    // Step 1: Verify ownership
    // Hash the secret key to derive public key hash
    component ownershipHasher = Poseidon(2);
    ownershipHasher.inputs[0] <== userSecretKey;
    ownershipHasher.inputs[1] <== memoryNonce;
    
    // Check if derived public key matches provided public key hash
    component ownershipCheck = IsEqual();
    ownershipCheck.in[0] <== ownershipHasher.out;
    ownershipCheck.in[1] <== publicKeyHash;
    ownershipValid <== ownershipCheck.out;
    
    // Step 2: Pattern matching
    // Create commitment from memory content and pattern
    component patternHasher = Poseidon(2);
    patternHasher.inputs[0] <== memoryContent;
    patternHasher.inputs[1] <== patternHash;
    
    // Simple pattern matching: check if hash falls in valid range
    // In production, this would be more sophisticated
    component confidenceCalc = Poseidon(3);
    confidenceCalc.inputs[0] <== patternHasher.out;
    confidenceCalc.inputs[1] <== memoryContent;
    confidenceCalc.inputs[2] <== patternHash;
    
    // Extract confidence score (last 7 bits gives 0-127, we'll cap at 100)
    component bits = Num2Bits(254);
    bits.in <== confidenceCalc.out;
    
    // Sum first 7 bits to get score 0-127
    signal scoreRaw;
    scoreRaw <== bits.out[0] + bits.out[1] * 2 + bits.out[2] * 4 + 
                 bits.out[3] * 8 + bits.out[4] * 16 + bits.out[5] * 32 + 
                 bits.out[6] * 64;
    
    // Cap at 100
    component lessThan100 = LessThan(8);
    lessThan100.in[0] <== scoreRaw;
    lessThan100.in[1] <== 100;
    
    // If scoreRaw < 100, use scoreRaw, else use 99
    confidenceScore <== lessThan100.out * scoreRaw + (1 - lessThan100.out) * 99;
    
    // Step 3: Check if confidence meets threshold
    component meetsThreshold = GreaterEqThan(8);
    meetsThreshold.in[0] <== confidenceScore;
    meetsThreshold.in[1] <== minConfidence;
    patternMatched <== meetsThreshold.out;
    
    // Step 4: Create commitment hash for on-chain verification
    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== memoryContent;
    commitmentHasher.inputs[1] <== patternHash;
    commitmentHasher.inputs[2] <== confidenceScore;
    commitmentHasher.inputs[3] <== ownershipValid;
    commitmentHash <== commitmentHasher.out;
}

component main {public [patternHash, minConfidence, publicKeyHash]} = MemoryPatternVerifier();
