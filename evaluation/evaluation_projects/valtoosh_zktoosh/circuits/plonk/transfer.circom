pragma circom 2.1.8;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * zkUlt PLONK Enhanced Transfer Circuit with Dual Account Model (Phase 5A)
 * Includes commitment scheme + Nullifier System + ENA (Encrypted Account)
 *
 * This version adds (Phase 5A - Azeroth Parity):
 * - Dual Account Model: EOA (public) + ENA (private encrypted balance)
 * - Symmetric encryption for ENA using Poseidon
 * - Support for public deposits (EOA → ENA) and withdrawals (ENA → EOA)
 * - Balance commitment for privacy
 * - Recipient hash for anonymous claiming (Phase 3)
 * - Nullifier for replay attack prevention (Phase 4)
 * - Poseidon hash for efficiency
 *
 * Public Signals Order (11 total - Phase 5A):
 * Outputs (0-5):
 * [0] valid - transfer validation result
 * [1] newBalance - sender's ENA balance after transfer
 * [2] newBalanceCommitment - cryptographic commitment to new balance
 * [3] recipientHash - hash for recipient to claim funds
 * [4] nullifier - unique identifier to prevent double-spending (Phase 4)
 * [5] sctNew - encrypted new ENA balance (Phase 5A)
 *
 * Public Inputs (6-10):
 * [6] assetId - public asset identifier
 * [7] maxAmount - public maximum allowed amount
 * [8] balanceCommitment - cryptographic commitment to original balance
 * [9] sctOld - encrypted old ENA balance (Phase 5A)
 * [10] vPubDelta - net public transfer amount (vPubIn - vPubOut) (Phase 5A)
 */

template PlonkTransferCheckEnhanced() {
    // ============================================
    // PRIVATE INPUTS
    // ============================================
    signal input senderBalance;
    signal input transferAmount;
    signal input recipientAddressHash;
    signal input salt;                 // For commitment randomness
    signal input kENA;                 // PHASE 5A: Symmetric key for ENA encryption
    signal input vPubIn;               // PHASE 5A: Public deposit amount (EOA → ENA)
    signal input vPubOut;              // PHASE 5A: Public withdrawal amount (ENA → EOA)

    // ============================================
    // PUBLIC INPUTS
    // ============================================
    signal input assetId;
    signal input maxAmount;
    signal input balanceCommitment;    // Commitment to sender's balance
    signal input sctOld;               // PHASE 5A: Encrypted old ENA balance
    signal input vPubDelta;            // PHASE 5A: Net public transfer (vPubIn - vPubOut)

    // ============================================
    // OUTPUTS
    // ============================================
    signal output valid;
    signal output newBalance;
    signal output newBalanceCommitment; // Commitment to new balance
    signal output recipientHash;        // Hash for recipient claiming
    signal output nullifier;            // PHASE 4: Nullifier for replay protection
    signal output sctNew;               // PHASE 5A: Encrypted new ENA balance
    
    // ============================================
    // PHASE 5A: ENA (Encrypted Account) VERIFICATION
    // Verify that sctOld is the correct encryption of senderBalance
    // ============================================
    component verifyOld = Poseidon(2);
    verifyOld.inputs[0] <== kENA;
    verifyOld.inputs[1] <== senderBalance;

    // Verify that computed encryption matches the provided sctOld (public input)
    signal vENAold;
    vENAold <== verifyOld.out;
    vENAold === sctOld;

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
    // PHASE 5A: BALANCE EQUATION (Azeroth's Core)
    // v_ENA_new = v_ENA_old + v_pub_in - v_pub_out - transfer_amount
    // This is where dual account model enables function privacy!
    // ============================================

    // Verify vPubDelta constraint
    vPubDelta === (vPubIn - vPubOut);

    // Calculate new ENA balance
    signal vENAnew;
    vENAnew <== senderBalance + vPubDelta - transferAmount;
    newBalance <== vENAnew;

    // ============================================
    // PHASE 5A: ENA ENCRYPTION
    // Encrypt new ENA balance
    // ============================================
    component encryptNew = Poseidon(2);
    encryptNew.inputs[0] <== kENA;
    encryptNew.inputs[1] <== vENAnew;
    sctNew <== encryptNew.out;

    // ============================================
    // TRANSFER VALIDATION (PHASE 5A: Updated for deposit/transfer/withdrawal)
    // ============================================

    // Transfer amount must be <= maxAmount
    component ltMax = LessThan(64);
    ltMax.in[0] <== transferAmount;
    ltMax.in[1] <== maxAmount + 1;

    // Transfer amount must be >= 0 (always true, but included for completeness)
    component geZero = GreaterEqThan(32);
    geZero.in[0] <== transferAmount;
    geZero.in[1] <== 0;

    // Transfer amount must be <= sender's balance
    component balanceCheck = LessEqThan(64);
    balanceCheck.in[0] <== transferAmount;
    balanceCheck.in[1] <== senderBalance;

    // Asset ID must be valid (> 0)
    component assetValidation = GreaterThan(32);
    assetValidation.in[0] <== assetId;
    assetValidation.in[1] <== 0;

    // Recipient address must be valid (> 0)
    component recipientValidation = GreaterThan(160);
    recipientValidation.in[0] <== recipientAddressHash;
    recipientValidation.in[1] <== 0;
    
    // ============================================
    // OUTPUT CALCULATIONS
    // ============================================

    // Note: newBalance is now calculated in PHASE 5A BALANCE EQUATION section above

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

    // Combine all checks (PHASE 5A: Use GreaterEqThan instead of GreaterThan for transferAmount)
    signal intermediate1;
    signal intermediate2;
    signal intermediate3;
    signal intermediate4;

    intermediate1 <== ltMax.out * geZero.out;
    intermediate2 <== intermediate1 * balanceCheck.out;
    intermediate3 <== intermediate2 * assetValidation.out;
    intermediate4 <== intermediate3 * recipientValidation.out;

    valid <== intermediate4;
}

// Public signals order (11 total):
// Outputs: [0] valid, [1] newBalance, [2] newBalanceCommitment, [3] recipientHash, [4] nullifier, [5] sctNew
// Inputs: [6] assetId, [7] maxAmount, [8] balanceCommitment, [9] sctOld, [10] vPubDelta
component main {public [maxAmount, assetId, balanceCommitment, sctOld, vPubDelta]} = PlonkTransferCheckEnhanced();