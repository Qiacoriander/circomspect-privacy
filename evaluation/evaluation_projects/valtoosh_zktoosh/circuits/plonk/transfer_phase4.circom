pragma circom 2.1.8;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * zkUlt PLONK Enhanced Transfer Circuit with Hash-Based Claiming
 * Includes commitment scheme for recipient privacy + Nullifier System (Phase 4)
 *
 * This version adds:
 * - Balance commitment for privacy
 * - Recipient hash for anonymous claiming (Phase 3)
 * - Nullifier for replay attack prevention (Phase 4)
 * - Poseidon hash for efficiency
 *
 * Public Signals Order (8 total):
 * [0] valid - transfer validation result
 * [1] newBalance - sender's balance after transfer
 * [2] newBalanceCommitment - cryptographic commitment to new balance
 * [3] recipientHash - hash for recipient to claim funds
 * [4] assetId - public asset identifier
 * [5] maxAmount - public maximum allowed amount
 * [6] balanceCommitment - cryptographic commitment to original balance
 * [7] nullifier - unique identifier to prevent double-spending (Phase 4)
 */

template PlonkTransferCheckEnhanced() {
    // ============================================
    // PRIVATE INPUTS
    // ============================================
    signal input senderBalance;        
    signal input transferAmount;       
    signal input recipientAddressHash;       
    signal input salt;                 // NEW: For commitment randomness
    
    // ============================================
    // PUBLIC INPUTS
    // ============================================
    signal input assetId;              
    signal input maxAmount;            
    signal input balanceCommitment;    // NEW: Commitment to sender's balance
    
    // ============================================
    // OUTPUTS
    // ============================================
    signal output valid;
    signal output newBalance;
    signal output newBalanceCommitment; // NEW: Commitment to new balance
    signal output recipientHash;        // NEW: Hash for recipient claiming
    signal output nullifier;            // PHASE 4: Nullifier for replay protection
    
    // ============================================
    // COMMITMENT VERIFICATION
    // Verify that sender knows the preimage of balanceCommitment
    // ============================================
    component commitmentCheck = Poseidon(2);
    commitmentCheck.inputs[0] <== senderBalance;
    commitmentCheck.inputs[1] <== salt;
    
    // Ensure provided commitment matches computed commitment
    commitmentCheck.out === balanceCommitment;
    
    // ============================================
    // TRANSFER VALIDATION (Same as basic version)
    // ============================================
    
    component ltMax = LessThan(64);
    ltMax.in[0] <== transferAmount;
    ltMax.in[1] <== maxAmount + 1;
    
    component gtZero = GreaterThan(32);
    gtZero.in[0] <== transferAmount;
    gtZero.in[1] <== 0;
    
    component balanceCheck = LessEqThan(64);
    balanceCheck.in[0] <== transferAmount;
    balanceCheck.in[1] <== senderBalance;
    
    component assetValidation = GreaterThan(32);
    assetValidation.in[0] <== assetId;
    assetValidation.in[1] <== 0;
    
    component recipientValidation = GreaterThan(160);
    recipientValidation.in[0] <== recipientAddressHash;
    recipientValidation.in[1] <== 0;
    
    // ============================================
    // OUTPUT CALCULATIONS
    // ============================================
    
    newBalance <== senderBalance - transferAmount;
    
    // Create commitment to new balance
    component newCommitment = Poseidon(2);
    newCommitment.inputs[0] <== newBalance;
    newCommitment.inputs[1] <== salt; // Same salt for simplicity
    newBalanceCommitment <== newCommitment.out;

    // Create recipient hash for claiming
    // Hash the recipient address with transfer amount for uniqueness
    component recipientHasher = Poseidon(2);
    recipientHasher.inputs[0] <== recipientAddressHash;
    recipientHasher.inputs[1] <== transferAmount;
    recipientHash <== recipientHasher.out;

    // PHASE 4: Generate nullifier for replay attack prevention
    // Nullifier = Hash(balanceCommitment, salt, transferAmount)
    // This creates a unique identifier that proves commitment spending
    // without revealing the actual balance or salt
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== balanceCommitment;
    nullifierHasher.inputs[1] <== salt;
    nullifierHasher.inputs[2] <== transferAmount;
    nullifier <== nullifierHasher.out;

    // Combine all checks
    signal intermediate1;
    signal intermediate2;
    signal intermediate3;
    signal intermediate4;

    intermediate1 <== ltMax.out * gtZero.out;
    intermediate2 <== intermediate1 * balanceCheck.out;
    intermediate3 <== intermediate2 * assetValidation.out;
    intermediate4 <== intermediate3 * recipientValidation.out;
    
    valid <== intermediate4;
}

component main {public [maxAmount, assetId, balanceCommitment]} = PlonkTransferCheckEnhanced();