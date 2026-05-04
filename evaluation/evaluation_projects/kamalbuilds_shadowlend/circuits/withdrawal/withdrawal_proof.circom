pragma circom 2.1.0;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * WithdrawalProof Circuit
 *
 * Proves ownership of a deposit and the right to withdraw it
 * without revealing which specific deposit is being withdrawn.
 *
 * The circuit verifies:
 * 1. Knowledge of nullifier preimage (proves ownership)
 * 2. The commitment exists in the Merkle tree
 * 3. The withdrawal amount matches the deposited amount
 *
 * Public Inputs:
 *   - merkleRoot: Root of the deposits Merkle tree
 *   - nullifierHash: Hash of the nullifier (to prevent double-spending)
 *   - withdrawalAmount: Amount being withdrawn
 *   - recipient: Address receiving the withdrawal (for binding proof to recipient)
 *
 * Private Inputs:
 *   - nullifier: Secret nullifier (preimage)
 *   - depositAmount: Original deposit amount
 *   - pathElements: Merkle proof path elements
 *   - pathIndices: Merkle proof path indices
 */

template WithdrawalProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input nullifierHash;
    signal input withdrawalAmount;
    signal input recipient;         // Recipient address (prevents front-running)

    // Private inputs
    signal input nullifier;
    signal input depositAmount;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output: commitment for verification
    signal output commitment;

    // ========== STEP 1: Compute commitment ==========
    // commitment = Poseidon(nullifier, depositAmount)
    component commitmentHasher = PoseidonHash2();
    commitmentHasher.in[0] <== nullifier;
    commitmentHasher.in[1] <== depositAmount;
    commitment <== commitmentHasher.out;

    // ========== STEP 2: Verify Merkle inclusion ==========
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== commitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // ========== STEP 3: Verify nullifier hash ==========
    // Compute: expectedNullifierHash = Poseidon(nullifier, commitment)
    // This binds the nullifier to both the secret and the specific commitment
    component nullifierHasher = PoseidonHash2();
    nullifierHasher.in[0] <== nullifier;
    nullifierHasher.in[1] <== commitment;

    // Verify the computed nullifier hash matches the public input
    nullifierHash === nullifierHasher.out;

    // ========== STEP 4: Verify withdrawal amount ==========
    // The withdrawal amount must equal the deposit amount
    withdrawalAmount === depositAmount;

    // ========== STEP 5: Bind proof to recipient ==========
    // This prevents front-running by ensuring the proof is only valid
    // for the specified recipient. We do this by including recipient
    // in a constraint (even though it's just a "dummy" constraint,
    // it ensures recipient must be provided correctly)
    signal recipientSquared;
    recipientSquared <== recipient * recipient;

    // ========== STEP 6: Range checks ==========
    // Deposit amount must be positive
    component amountPositive = GreaterThan(128);
    amountPositive.in[0] <== depositAmount;
    amountPositive.in[1] <== 0;
    amountPositive.out === 1;
}

/*
 * PartialWithdrawalProof Circuit
 *
 * Proves the right to partially withdraw from a deposit,
 * creating a new commitment for the remaining balance.
 *
 * Public Inputs:
 *   - merkleRoot: Current root
 *   - nullifierHash: For the old commitment
 *   - withdrawalAmount: Amount being withdrawn
 *   - newCommitment: Commitment for remaining balance
 *   - recipient: Address receiving the withdrawal
 *
 * Private Inputs:
 *   - nullifier: Old nullifier
 *   - depositAmount: Original deposit amount
 *   - newNullifier: Nullifier for the new commitment
 *   - pathElements/pathIndices: Merkle proof
 */

template PartialWithdrawalProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input nullifierHash;
    signal input withdrawalAmount;
    signal input newCommitment;
    signal input recipient;

    // Private inputs
    signal input nullifier;
    signal input depositAmount;
    signal input newNullifier;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output
    signal output oldCommitment;

    // ========== STEP 1: Compute old commitment ==========
    component oldCommitmentHasher = PoseidonHash2();
    oldCommitmentHasher.in[0] <== nullifier;
    oldCommitmentHasher.in[1] <== depositAmount;
    oldCommitment <== oldCommitmentHasher.out;

    // ========== STEP 2: Verify Merkle inclusion ==========
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== oldCommitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // ========== STEP 3: Verify nullifier hash ==========
    component nullifierHasher = PoseidonHash2();
    nullifierHasher.in[0] <== nullifier;
    nullifierHasher.in[1] <== oldCommitment;
    nullifierHash === nullifierHasher.out;

    // ========== STEP 4: Verify withdrawal is valid ==========
    // withdrawal must be less than or equal to deposit
    component withdrawalValid = LessEqThan(128);
    withdrawalValid.in[0] <== withdrawalAmount;
    withdrawalValid.in[1] <== depositAmount;
    withdrawalValid.out === 1;

    // ========== STEP 5: Calculate and verify remaining balance ==========
    signal remainingBalance;
    remainingBalance <== depositAmount - withdrawalAmount;

    // Compute expected new commitment: Poseidon(newNullifier, remainingBalance)
    component newCommitmentHasher = PoseidonHash2();
    newCommitmentHasher.in[0] <== newNullifier;
    newCommitmentHasher.in[1] <== remainingBalance;

    // Verify the new commitment matches
    newCommitment === newCommitmentHasher.out;

    // ========== STEP 6: Range checks ==========
    // Withdrawal amount must be positive
    component withdrawalPositive = GreaterThan(128);
    withdrawalPositive.in[0] <== withdrawalAmount;
    withdrawalPositive.in[1] <== 0;
    withdrawalPositive.out === 1;

    // Bind proof to recipient
    signal recipientSquared;
    recipientSquared <== recipient * recipient;
}

/*
 * EmergencyWithdrawalProof Circuit
 *
 * Allows withdrawal with additional time-lock verification.
 * Used when user loses access to their secrets but can prove
 * ownership through other means after a waiting period.
 */

template EmergencyWithdrawalProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input commitment;            // Known commitment
    signal input recipient;
    signal input requestTimestamp;      // When withdrawal was requested
    signal input currentTimestamp;      // Current timestamp
    signal input requiredDelay;         // Required waiting period

    // Private inputs
    signal input nullifier;
    signal input depositAmount;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output
    signal output nullifierHash;

    // ========== STEP 1: Verify commitment computation ==========
    component commitmentHasher = PoseidonHash2();
    commitmentHasher.in[0] <== nullifier;
    commitmentHasher.in[1] <== depositAmount;
    commitment === commitmentHasher.out;

    // ========== STEP 2: Verify Merkle inclusion ==========
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== commitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // ========== STEP 3: Verify time-lock ==========
    // currentTimestamp >= requestTimestamp + requiredDelay
    signal minTimestamp;
    minTimestamp <== requestTimestamp + requiredDelay;

    component timeLockCheck = GreaterEqThan(64);
    timeLockCheck.in[0] <== currentTimestamp;
    timeLockCheck.in[1] <== minTimestamp;
    timeLockCheck.out === 1;

    // ========== STEP 4: Compute nullifier hash ==========
    component nullifierHasher = PoseidonHash2();
    nullifierHasher.in[0] <== nullifier;
    nullifierHasher.in[1] <== commitment;
    nullifierHash <== nullifierHasher.out;

    // Bind to recipient
    signal recipientSquared;
    recipientSquared <== recipient * recipient;
}

// Main component - standard full withdrawal proof
component main {public [merkleRoot, nullifierHash, withdrawalAmount, recipient]} = WithdrawalProof(20);
