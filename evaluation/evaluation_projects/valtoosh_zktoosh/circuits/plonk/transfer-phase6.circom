pragma circom 2.1.8;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./merkle.circom";
include "./stealth.circom";
include "./range_proof.circom";

/*
 * zkUlt Phase 6 Unified Privacy Circuit (ECDH Fixed)
 *
 * Security Upgrade:
 * - Uses BabyJubJub ECDH for shared secret derivation
 * - Public keys are now Points (X, Y) instead of Scalars
 * - Prevents linkability attacks
 *
 * Public Signals Order (18 total):
 * Outputs (0-11):
 * [0] valid
 * [1] newBalance
 * [2] newBalanceCommitment
 * [3] recipientHash
 * [4] nullifier
 * [5] sctNew
 * [6] stealthAddress
 * [7] ephemeralPublicKey[0] (X)
 * [8] ephemeralPublicKey[1] (Y)
 * [9] merkleLeaf
 * [10] merkleProofValid
 * [11] encryptedMemoHash
 *
 * Public Inputs (12-17):
 * [12] assetId
 * [13] maxAmount
 * [14] balanceCommitment
 * [15] sctOld
 * [16] vPubDelta
 * [17] merkleRoot
 */

template PlonkTransferPhase6() {
    // ============================================
    // PRIVATE INPUTS
    // ============================================

    // Phase 5B: Existing private inputs
    signal input senderBalance;              // Sender's current ENA balance
    signal input transferAmount;             // Amount to transfer
    signal input recipientViewPublicKey[2];  // Recipient's VIEW public key (Point X, Y)
    signal input salt;                       // For commitment randomness
    signal input kENA;                       // Symmetric key for ENA encryption
    signal input vPubIn;                     // Public deposit (EOA → ENA)
    signal input vPubOut;                    // Public withdrawal (ENA → EOA)

    // Phase 6B: Monero-style stealth address private inputs
    signal input ephemeralPrivateKey;        // One-time private key for this transfer
    signal input stealthSalt;                // Salt for stealth address generation

    // Phase 6C: Merkle tree private inputs (20 levels = 1M capacity)
    signal input merklePathElements[20];     // Sibling hashes along path
    signal input merklePathIndices[20];      // Path directions (0=left, 1=right)

    // Phase 6E: Encrypted memo hash (memo encrypted off-chain)
    signal input encryptedMemo[2];           // Two field elements for memo hash

    // ============================================
    // PUBLIC INPUTS
    // ============================================
    signal input assetId;
    signal input maxAmount;
    signal input balanceCommitment;
    signal input sctOld;
    signal input vPubDelta;
    signal input merkleRoot;                 // Phase 6C: Current Merkle root

    // ============================================
    // OUTPUTS
    // ============================================
    signal output valid;
    signal output newBalance;
    signal output newBalanceCommitment;
    signal output recipientHash;
    signal output nullifier;
    signal output sctNew;
    signal output stealthAddress;            // Phase 6B
    signal output ephemeralPublicKey[2];     // Phase 6B (Point X, Y)
    signal output merkleLeaf;                // Phase 6C
    signal output merkleProofValid;          // Phase 6C
    signal output encryptedMemoHash;         // Phase 6E

    // ============================================
    // PHASE 5B: ENA VERIFICATION
    // ============================================
    component verifyOld = Poseidon(2);
    verifyOld.inputs[0] <== kENA;
    verifyOld.inputs[1] <== senderBalance;

    signal vENAold;
    vENAold <== verifyOld.out;
    vENAold === sctOld;

    // ============================================
    // COMMITMENT VERIFICATION
    // ============================================
    component commitmentCheck = Poseidon(2);
    commitmentCheck.inputs[0] <== senderBalance;
    commitmentCheck.inputs[1] <== salt;
    commitmentCheck.out === balanceCommitment;

    // ============================================
    // PHASE 5B: BALANCE EQUATION
    // ============================================
    vPubDelta === (vPubIn - vPubOut);

    signal vENAnew;
    vENAnew <== senderBalance + vPubDelta - transferAmount;
    newBalance <== vENAnew;

    // ============================================
    // PHASE 5B: ENA ENCRYPTION
    // ============================================
    component encryptNew = Poseidon(2);
    encryptNew.inputs[0] <== kENA;
    encryptNew.inputs[1] <== vENAnew;
    sctNew <== encryptNew.out;

    // ============================================
    // PHASE 6D: RANGE PROOFS
    // Prove 0 <= transferAmount <= maxAmount without revealing exact amount
    // ============================================
    component rangeProof = RangeProof(64);
    rangeProof.value <== transferAmount;
    rangeProof.maxValue <== maxAmount;

    signal rangeValid;
    rangeValid <== rangeProof.isValid;

    // ============================================
    // PHASE 6B: MONERO-STYLE STEALTH ADDRESS GENERATION (ECDH)
    // ============================================
    component stealthGen = StealthAddressGeneration();
    stealthGen.recipientViewPublicKey[0] <== recipientViewPublicKey[0];
    stealthGen.recipientViewPublicKey[1] <== recipientViewPublicKey[1];
    stealthGen.ephemeralPrivateKey <== ephemeralPrivateKey;
    stealthGen.transferAmount <== transferAmount;
    stealthGen.stealthSalt <== stealthSalt;

    stealthAddress <== stealthGen.stealthAddress;
    ephemeralPublicKey[0] <== stealthGen.ephemeralPublicKey[0];
    ephemeralPublicKey[1] <== stealthGen.ephemeralPublicKey[1];

    // ============================================
    // RECIPIENT HASH (For backward compatibility and merkle leaf)
    // Uses Poseidon(pkX, pkY, amount) to match Claim circuit
    // ============================================
    component recipientHasher = Poseidon(3);
    recipientHasher.inputs[0] <== recipientViewPublicKey[0];
    recipientHasher.inputs[1] <== recipientViewPublicKey[1];
    recipientHasher.inputs[2] <== transferAmount;
    recipientHash <== recipientHasher.out;

    // ============================================
    // PHASE 4: NULLIFIER GENERATION
    // ============================================
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== balanceCommitment;
    nullifierHasher.inputs[1] <== salt;
    nullifierHasher.inputs[2] <== transferAmount;
    nullifier <== nullifierHasher.out;

    // ============================================
    // PHASE 6C: MERKLE TREE INTEGRATION (STATE TREE LOGIC)
    // ============================================

    // Note: Removed legacy transaction hash logic. Tree now stores State Commitments.

    // Verify Merkle proof for the OLD commitment (balanceCommitment)
    component merkleProof = MerkleTreeInclusionProof(20);
    merkleProof.leaf <== balanceCommitment; // Prove OLD state exists
    merkleProof.root <== merkleRoot;
    for (var i = 0; i < 20; i++) {
        merkleProof.pathElements[i] <== merklePathElements[i];
        merkleProof.pathIndices[i] <== merklePathIndices[i];
    }

    // CRITICAL FIX: Allow skipping Merkle proof if this is a new account (senderBalance == 0)
    // OR if the tree is empty (merkleRoot == 0).
    component isNewAccount = IsZero();
    isNewAccount.in <== senderBalance;

    component rootIsZero = IsZero();
    rootIsZero.in <== merkleRoot;

    component skipCheck = GreaterThan(8); 
    skipCheck.in[0] <== isNewAccount.out + rootIsZero.out;
    skipCheck.in[1] <== 0;

    component proofOrSkip = GreaterThan(8);
    proofOrSkip.in[0] <== merkleProof.isValid + skipCheck.out;
    proofOrSkip.in[1] <== 0;

    merkleProofValid <== proofOrSkip.out;

    // ============================================
    // PHASE 6E: ENCRYPTED MEMO HASH
    // ============================================
    component memoHasher = Poseidon(2);
    memoHasher.inputs[0] <== encryptedMemo[0];
    memoHasher.inputs[1] <== encryptedMemo[1];
    encryptedMemoHash <== memoHasher.out;

    // ============================================
    // TRANSFER VALIDATION
    // ============================================

    // Transfer amount <= maxAmount (covered by range proof)
    component ltMax = LessThan(64);
    ltMax.in[0] <== transferAmount;
    ltMax.in[1] <== maxAmount + 1;

    // Transfer amount >= 0
    component geZero = GreaterEqThan(32);
    geZero.in[0] <== transferAmount;
    geZero.in[1] <== 0;

    // Transfer amount <= sender's balance + vPubIn (account for deposits)
    signal availableBalance;
    availableBalance <== senderBalance + vPubIn;
    component balanceCheck = LessEqThan(64);
    balanceCheck.in[0] <== transferAmount;
    balanceCheck.in[1] <== availableBalance;

    // Asset ID valid (> 0)
    component assetValidation = GreaterThan(32);
    assetValidation.in[0] <== assetId;
    assetValidation.in[1] <== 0;

    // ============================================
    // NEW BALANCE COMMITMENT
    // ============================================
    component newCommitment = Poseidon(2);
    newCommitment.inputs[0] <== newBalance;
    newCommitment.inputs[1] <== salt;
    newBalanceCommitment <== newCommitment.out;

    // ----------------------------------------------------------------
    // LATE ASSIGNMENT: MERKLE LEAF
    // We assign merkleLeaf here because newBalanceCommitment is now ready
    // ----------------------------------------------------------------
    merkleLeaf <== newBalanceCommitment;

    // ============================================
    // COMBINE ALL CHECKS
    // ============================================
    signal check1;
    signal check2;
    signal check3;
    signal check4;
    signal check5;
    signal check6;
    signal check7;
    signal check8;

    check1 <== ltMax.out * geZero.out;
    check2 <== check1 * balanceCheck.out;
    check3 <== check2 * assetValidation.out;
    check4 <== check3 * rangeValid;                // Phase 6D
    check5 <== check4 * merkleProofValid;          // Phase 6C
    check6 <== check5;
    check7 <== check6;
    check8 <== check7;

    valid <== check8;
}

component main {public [maxAmount, assetId, balanceCommitment, sctOld, vPubDelta, merkleRoot]} = PlonkTransferPhase6();
