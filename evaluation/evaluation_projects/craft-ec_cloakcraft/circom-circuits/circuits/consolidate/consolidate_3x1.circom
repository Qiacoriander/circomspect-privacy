pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
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

// Derive nullifier key from spending key
template NullifierKey() {
    signal input spending_key;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== NULLIFIER_KEY_DOMAIN();
    hasher.inputs[1] <== spending_key;
    hasher.inputs[2] <== 0;
    out <== hasher.out;
}

// Compute spending nullifier
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
    component bits = Num2Bits(64);
    bits.in <== in;
}

// ============================================================================
// Consolidate Circuit: 3 Inputs -> 1 Output
// ============================================================================
//
// Purpose: Merge up to 3 notes into a single note
// - No recipient (self-consolidation only)
// - Simplifies wallet state
// - Reduces fragmentation
// - NO FEE for consolidation (encourages cleanup)
//
// Note: Input 2 and 3 can be "dummy" inputs with 0 amount
// This allows the same circuit to handle 1, 2, or 3 inputs
//
// ============================================================================

template Consolidate3x1() {
    // ========================================================================
    // Public Inputs (signals that will be verified on-chain)
    // ========================================================================
    signal input merkle_root;           // Merkle root (verified on-chain via Light Protocol)
    signal input nullifier_1;           // Nullifier for input 1
    signal input nullifier_2;           // Nullifier for input 2 (can be 0 for dummy)
    signal input nullifier_3;           // Nullifier for input 3 (can be 0 for dummy)
    signal input out_commitment;        // Single output commitment
    signal input token_mint;            // Token being consolidated

    // ========================================================================
    // Private Inputs (witness - never revealed)
    // ========================================================================

    // Input note 1 details (required)
    signal input in_stealth_pub_x_1;
    signal input in_amount_1;
    signal input in_randomness_1;
    signal input in_stealth_spending_key_1;
    signal input merkle_path_1[32];
    signal input merkle_path_indices_1[32];
    signal input leaf_index_1;

    // Input note 2 details (optional - can be zeros)
    signal input in_stealth_pub_x_2;
    signal input in_amount_2;
    signal input in_randomness_2;
    signal input in_stealth_spending_key_2;
    signal input merkle_path_2[32];
    signal input merkle_path_indices_2[32];
    signal input leaf_index_2;

    // Input note 3 details (optional - can be zeros)
    signal input in_stealth_pub_x_3;
    signal input in_amount_3;
    signal input in_randomness_3;
    signal input in_stealth_spending_key_3;
    signal input merkle_path_3[32];
    signal input merkle_path_indices_3[32];
    signal input leaf_index_3;

    // Output note details (consolidated)
    signal input out_stealth_pub_x;
    signal input out_amount;
    signal input out_randomness;

    // ========================================================================
    // 1. Verify Input Commitment 1 (always required)
    // ========================================================================
    component in_commitment_1 = Commitment();
    in_commitment_1.stealth_pub_x <== in_stealth_pub_x_1;
    in_commitment_1.token_mint <== token_mint;
    in_commitment_1.amount <== in_amount_1;
    in_commitment_1.randomness <== in_randomness_1;

    component nk_1 = NullifierKey();
    nk_1.spending_key <== in_stealth_spending_key_1;

    component computed_nullifier_1 = SpendingNullifier();
    computed_nullifier_1.nullifier_key <== nk_1.out;
    computed_nullifier_1.commitment <== in_commitment_1.out;
    computed_nullifier_1.leaf_index <== leaf_index_1;

    nullifier_1 === computed_nullifier_1.out;

    // ========================================================================
    // 2. Verify Input Commitment 2 (optional)
    // ========================================================================
    component in_commitment_2 = Commitment();
    in_commitment_2.stealth_pub_x <== in_stealth_pub_x_2;
    in_commitment_2.token_mint <== token_mint;
    in_commitment_2.amount <== in_amount_2;
    in_commitment_2.randomness <== in_randomness_2;

    component nk_2 = NullifierKey();
    nk_2.spending_key <== in_stealth_spending_key_2;

    component computed_nullifier_2 = SpendingNullifier();
    computed_nullifier_2.nullifier_key <== nk_2.out;
    computed_nullifier_2.commitment <== in_commitment_2.out;
    computed_nullifier_2.leaf_index <== leaf_index_2;

    // For dummy inputs (amount=0), nullifier can be 0
    // Otherwise must match computed nullifier
    signal is_input_2_active;
    component amount_2_nonzero = IsZero();
    amount_2_nonzero.in <== in_amount_2;
    is_input_2_active <== 1 - amount_2_nonzero.out;

    // If active: nullifier_2 === computed
    // If inactive: no constraint (can be 0)
    signal expected_nullifier_2;
    expected_nullifier_2 <== is_input_2_active * computed_nullifier_2.out;
    nullifier_2 === expected_nullifier_2;

    // ========================================================================
    // 3. Verify Input Commitment 3 (optional)
    // ========================================================================
    component in_commitment_3 = Commitment();
    in_commitment_3.stealth_pub_x <== in_stealth_pub_x_3;
    in_commitment_3.token_mint <== token_mint;
    in_commitment_3.amount <== in_amount_3;
    in_commitment_3.randomness <== in_randomness_3;

    component nk_3 = NullifierKey();
    nk_3.spending_key <== in_stealth_spending_key_3;

    component computed_nullifier_3 = SpendingNullifier();
    computed_nullifier_3.nullifier_key <== nk_3.out;
    computed_nullifier_3.commitment <== in_commitment_3.out;
    computed_nullifier_3.leaf_index <== leaf_index_3;

    signal is_input_3_active;
    component amount_3_nonzero = IsZero();
    amount_3_nonzero.in <== in_amount_3;
    is_input_3_active <== 1 - amount_3_nonzero.out;

    signal expected_nullifier_3;
    expected_nullifier_3 <== is_input_3_active * computed_nullifier_3.out;
    nullifier_3 === expected_nullifier_3;

    // ========================================================================
    // 4. Verify Output Commitment
    // ========================================================================
    component out_commit = Commitment();
    out_commit.stealth_pub_x <== out_stealth_pub_x;
    out_commit.token_mint <== token_mint;
    out_commit.amount <== out_amount;
    out_commit.randomness <== out_randomness;

    out_commitment === out_commit.out;

    // ========================================================================
    // 5. Balance Check (NO FEE for consolidation)
    // ========================================================================
    // input_1 + input_2 + input_3 = output
    signal total_in;
    total_in <== in_amount_1 + in_amount_2 + in_amount_3;

    total_in === out_amount;

    // ========================================================================
    // 6. Range Checks (64-bit amounts)
    // ========================================================================
    component range_in1 = RangeCheck64();
    range_in1.in <== in_amount_1;

    component range_in2 = RangeCheck64();
    range_in2.in <== in_amount_2;

    component range_in3 = RangeCheck64();
    range_in3.in <== in_amount_3;

    component range_out = RangeCheck64();
    range_out.in <== out_amount;

    // ========================================================================
    // Note: Merkle proof verification is done ON-CHAIN via Light Protocol
    // ========================================================================
}

// Main component with public inputs
component main {public [
    merkle_root,
    nullifier_1,
    nullifier_2,
    nullifier_3,
    out_commitment,
    token_mint
]} = Consolidate3x1();
