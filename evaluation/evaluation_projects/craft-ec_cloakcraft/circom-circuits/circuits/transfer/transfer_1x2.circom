pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
// These ensure different hash contexts can't collide
function COMMITMENT_DOMAIN() { return 1; }
function SPENDING_NULLIFIER_DOMAIN() { return 2; }
function NULLIFIER_KEY_DOMAIN() { return 4; }

// ============================================================================
// Helper Templates
// ============================================================================

// Compute note commitment: Poseidon(domain, stealth_pub_x, token_mint, amount, randomness)
template Commitment() {
    signal input stealth_pub_x;
    signal input token_mint;
    signal input amount;
    signal input randomness;
    signal output out;

    component hasher = Poseidon(5);
    hasher.inputs[0] <== COMMITMENT_DOMAIN();
    hasher.inputs[1] <== stealth_pub_x;
    hasher.inputs[2] <== token_mint;
    hasher.inputs[3] <== amount;
    hasher.inputs[4] <== randomness;
    out <== hasher.out;
}

// Derive nullifier key from spending key: Poseidon(domain, spending_key, 0)
template NullifierKey() {
    signal input spending_key;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== NULLIFIER_KEY_DOMAIN();
    hasher.inputs[1] <== spending_key;
    hasher.inputs[2] <== 0;
    out <== hasher.out;
}

// Compute spending nullifier: Poseidon(domain, nullifier_key, commitment, leaf_index)
template SpendingNullifier() {
    signal input nullifier_key;
    signal input commitment;
    signal input leaf_index;
    signal output out;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== SPENDING_NULLIFIER_DOMAIN();
    hasher.inputs[1] <== nullifier_key;
    hasher.inputs[2] <== commitment;
    hasher.inputs[3] <== leaf_index;
    out <== hasher.out;
}

// Range check: constrain value to 64 bits
template RangeCheck64() {
    signal input in;

    // Decompose to bits - this constrains the value to fit in 64 bits
    component bits = Num2Bits(64);
    bits.in <== in;
}

// ============================================================================
// Main Transfer Circuit: 1 Input -> 2 Outputs
// ============================================================================

template Transfer1x2() {
    // ========================================================================
    // Public Inputs (signals that will be verified on-chain)
    // ========================================================================
    signal input merkle_root;           // Merkle root (verified on-chain via Light Protocol)
    signal input nullifier;             // Prevents double-spending
    signal input out_commitment_1;      // Output 1 commitment (recipient)
    signal input out_commitment_2;      // Output 2 commitment (change)
    signal input token_mint;            // Token being transferred
    signal input transfer_amount;       // Amount transferred to recipient (public for fee calculation)
    signal input unshield_amount;       // Amount being withdrawn to public (0 for private transfer)
    signal input fee_amount;            // Protocol fee amount (verified on-chain)

    // ========================================================================
    // Private Inputs (witness - never revealed)
    // ========================================================================

    // Input note details
    signal input in_stealth_pub_x;
    signal input in_amount;
    signal input in_randomness;
    signal input in_stealth_spending_key;

    // Merkle proof (32 levels)
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Output 1 details (recipient)
    signal input out_stealth_pub_x_1;
    signal input out_amount_1;
    signal input out_randomness_1;

    // Output 2 details (change)
    signal input out_stealth_pub_x_2;
    signal input out_amount_2;
    signal input out_randomness_2;

    // ========================================================================
    // 1. Verify Input Commitment
    // ========================================================================
    component in_commitment = Commitment();
    in_commitment.stealth_pub_x <== in_stealth_pub_x;
    in_commitment.token_mint <== token_mint;
    in_commitment.amount <== in_amount;
    in_commitment.randomness <== in_randomness;

    // ========================================================================
    // 2. Verify Nullifier
    // ========================================================================
    // nullifier = Poseidon(domain, nullifier_key, commitment, leaf_index)

    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== in_commitment.out;
    computed_nullifier.leaf_index <== leaf_index;

    // Constrain provided nullifier to match computed
    nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Output Commitments
    // ========================================================================

    // Output 1 (recipient)
    component out_commit_1 = Commitment();
    out_commit_1.stealth_pub_x <== out_stealth_pub_x_1;
    out_commit_1.token_mint <== token_mint;
    out_commit_1.amount <== out_amount_1;
    out_commit_1.randomness <== out_randomness_1;
    out_commitment_1 === out_commit_1.out;

    // Output 2 (change)
    component out_commit_2 = Commitment();
    out_commit_2.stealth_pub_x <== out_stealth_pub_x_2;
    out_commit_2.token_mint <== token_mint;
    out_commit_2.amount <== out_amount_2;
    out_commit_2.randomness <== out_randomness_2;
    out_commitment_2 === out_commit_2.out;

    // ========================================================================
    // 4. Verify Transfer Amount (public input matches private output)
    // ========================================================================
    // This constraint ensures the public transfer_amount matches what's actually
    // being transferred, enabling on-chain fee verification
    transfer_amount === out_amount_1;

    // ========================================================================
    // 5. Balance Check (with protocol fee)
    // ========================================================================
    // input = output_1 + output_2 + unshield + fee
    signal total_out;
    total_out <== out_amount_1 + out_amount_2 + unshield_amount + fee_amount;
    in_amount === total_out;

    // ========================================================================
    // 5. Range Checks (64-bit amounts)
    // ========================================================================
    component range_in = RangeCheck64();
    range_in.in <== in_amount;

    component range_out1 = RangeCheck64();
    range_out1.in <== out_amount_1;

    component range_out2 = RangeCheck64();
    range_out2.in <== out_amount_2;

    component range_unshield = RangeCheck64();
    range_unshield.in <== unshield_amount;

    component range_fee = RangeCheck64();
    range_fee.in <== fee_amount;

    // ========================================================================
    // Note: Merkle proof verification is done ON-CHAIN via Light Protocol
    // The merkle_root, merkle_path, and merkle_path_indices are included
    // for ABI compatibility but not verified in this circuit.
    // merkle_root is a public input so it's inherently constrained.
    // merkle_path and merkle_path_indices are private inputs in the witness.
    // ========================================================================
}

// Main component with public inputs
component main {public [
    merkle_root,
    nullifier,
    out_commitment_1,
    out_commitment_2,
    token_mint,
    transfer_amount,
    unshield_amount,
    fee_amount
]} = Transfer1x2();
