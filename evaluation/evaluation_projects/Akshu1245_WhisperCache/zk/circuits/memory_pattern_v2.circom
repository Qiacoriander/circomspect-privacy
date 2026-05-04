pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * WhisperCache Memory Pattern Policy Circuit V2
 * 
 * UPGRADED: Now includes key version and memory status validation.
 * 
 * This circuit enforces comprehensive access control:
 *   1. Memory must be ACTIVE (status == 1)
 *   2. Key version must match the current active key version
 *   3. Pattern-based policy (personal data blocks agent access)
 * 
 * PRIVATE INPUTS:
 *   - memoryContent: The raw content hash (private - not revealed)
 *   - salt: Random salt for privacy
 *   - keyVersion: The key version used to encrypt this memory
 *   - memoryStatus: Status of the memory (1 = ACTIVE, 0 = REVOKED/DELETED)
 * 
 * PUBLIC INPUTS:
 *   - memoryCommitment: Poseidon(memoryContent, salt) - public commitment
 *   - currentKeyVersion: The user's current active key version
 *   - isFinance: 1 if memory is financial data, 0 otherwise
 *   - isHealth: 1 if memory is health-related, 0 otherwise  
 *   - isPersonal: 1 if memory is personal/private, 0 otherwise
 * 
 * PUBLIC OUTPUTS:
 *   - allowedForAgent: 1 if agent access is allowed, 0 if blocked
 *   - commitment: The verified Poseidon commitment
 *   - statusValid: 1 if memory status is ACTIVE
 *   - keyValid: 1 if key version matches current
 * 
 * ACCESS GRANTED ONLY IF:
 *   - memoryStatus == 1 (ACTIVE)
 *   - keyVersion == currentKeyVersion
 *   - isPersonal == 0 (not personal data)
 */

template MemoryPatternPolicyV2() {
    // ========== PRIVATE INPUTS ==========
    signal input memoryContent;    // Private: the actual memory hash
    signal input salt;             // Private: random salt for commitment
    signal input keyVersion;       // Private: key version for this memory
    signal input memoryStatus;     // Private: 1 = ACTIVE, 0 = REVOKED/DELETED
    
    // ========== PUBLIC INPUTS ==========
    signal input memoryCommitment;   // Public: Poseidon(memoryContent, salt)
    signal input currentKeyVersion;  // Public: user's current active key version
    signal input isFinance;          // Public: pattern flag (0 or 1)
    signal input isHealth;           // Public: pattern flag (0 or 1)
    signal input isPersonal;         // Public: pattern flag (0 or 1)
    
    // ========== PUBLIC OUTPUTS ==========
    signal output allowedForAgent;   // Public: final policy result
    signal output commitment;        // Public: verified commitment
    signal output statusValid;       // Public: 1 if status is ACTIVE
    signal output keyValid;          // Public: 1 if key version matches
    
    // ========== STEP 1: Verify the commitment ==========
    // Prove that we know memoryContent and salt that hash to memoryCommitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== memoryContent;
    hasher.inputs[1] <== salt;
    
    // Commitment must match the public input
    hasher.out === memoryCommitment;
    
    // Output the verified commitment
    commitment <== hasher.out;
    
    // ========== STEP 2: Validate memory status ==========
    // memoryStatus must be 0 or 1
    memoryStatus * (1 - memoryStatus) === 0;
    
    // statusValid = 1 if memoryStatus == 1 (ACTIVE)
    statusValid <== memoryStatus;
    
    // ========== STEP 3: Validate key version ==========
    // Check if keyVersion matches currentKeyVersion
    component keyVersionCheck = IsEqual();
    keyVersionCheck.in[0] <== keyVersion;
    keyVersionCheck.in[1] <== currentKeyVersion;
    
    // keyValid = 1 if versions match
    keyValid <== keyVersionCheck.out;
    
    // ========== STEP 4: Enforce pattern flags are binary (0 or 1) ==========
    isFinance * (1 - isFinance) === 0;
    isHealth * (1 - isHealth) === 0;
    isPersonal * (1 - isPersonal) === 0;
    
    // ========== STEP 5: Compute pattern-based access ==========
    // patternAllowed = 1 if not personal data
    signal patternAllowed;
    patternAllowed <== 1 - isPersonal;
    
    // ========== STEP 6: Compute final access decision ==========
    // allowedForAgent = statusValid AND keyValid AND patternAllowed
    // Using multiplication for AND operation on binary values
    signal statusAndKey;
    statusAndKey <== statusValid * keyValid;
    allowedForAgent <== statusAndKey * patternAllowed;
    
    // ========== STEP 7: Sanity check outputs ==========
    allowedForAgent * (1 - allowedForAgent) === 0;
}

// Main component with public inputs declared
component main { public [memoryCommitment, currentKeyVersion, isFinance, isHealth, isPersonal] } = MemoryPatternPolicyV2();
