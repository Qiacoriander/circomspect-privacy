pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * WhisperCache Memory Pattern Policy Circuit
 * 
 * This circuit enforces a simple policy:
 * - If isPersonal == 1, then allowedForAgent must be 0 (blocked)
 * - Otherwise, allowedForAgent can be 1 (allowed)
 * 
 * Proves: "This memory satisfies this policy without revealing the raw memory or content."
 * 
 * PRIVATE INPUTS:
 *   - memoryContent: The raw content hash (private - not revealed)
 *   - salt: Random salt for privacy
 * 
 * PUBLIC INPUTS:
 *   - memoryCommitment: Poseidon(memoryContent, salt) - public commitment
 *   - isFinance: 1 if memory is financial data, 0 otherwise
 *   - isHealth: 1 if memory is health-related, 0 otherwise  
 *   - isPersonal: 1 if memory is personal/private, 0 otherwise
 * 
 * PUBLIC OUTPUTS:
 *   - allowedForAgent: 1 if agent access is allowed, 0 if blocked
 *   - commitment: The verified Poseidon commitment
 */

template MemoryPatternPolicy() {
    // ========== PRIVATE INPUTS ==========
    signal input memoryContent;    // Private: the actual memory hash
    signal input salt;             // Private: random salt for commitment
    
    // ========== PUBLIC INPUTS ==========
    signal input memoryCommitment; // Public: Poseidon(memoryContent, salt)
    signal input isFinance;        // Public: pattern flag (0 or 1)
    signal input isHealth;         // Public: pattern flag (0 or 1)
    signal input isPersonal;       // Public: pattern flag (0 or 1)
    
    // ========== PUBLIC OUTPUTS ==========
    signal output allowedForAgent; // Public: policy result
    signal output commitment;      // Public: verified commitment
    
    // ========== STEP 1: Verify the commitment ==========
    // Prove that we know memoryContent and salt that hash to memoryCommitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== memoryContent;
    hasher.inputs[1] <== salt;
    
    // Commitment must match the public input
    hasher.out === memoryCommitment;
    
    // Output the verified commitment
    commitment <== hasher.out;
    
    // ========== STEP 2: Enforce pattern flags are binary (0 or 1) ==========
    // isFinance must be 0 or 1
    isFinance * (1 - isFinance) === 0;
    
    // isHealth must be 0 or 1
    isHealth * (1 - isHealth) === 0;
    
    // isPersonal must be 0 or 1
    isPersonal * (1 - isPersonal) === 0;
    
    // ========== STEP 3: Apply the policy ==========
    // Policy: If isPersonal == 1, then allowedForAgent must be 0
    //         Otherwise, allowedForAgent can be 1
    //
    // Logic: allowedForAgent = 1 - isPersonal
    //        (If personal, blocked. If not personal, allowed.)
    
    allowedForAgent <== 1 - isPersonal;
    
    // ========== STEP 4: Sanity check output ==========
    // allowedForAgent must be 0 or 1
    allowedForAgent * (1 - allowedForAgent) === 0;
}

// Main component with public inputs declared
component main { public [memoryCommitment, isFinance, isHealth, isPersonal] } = MemoryPatternPolicy();
