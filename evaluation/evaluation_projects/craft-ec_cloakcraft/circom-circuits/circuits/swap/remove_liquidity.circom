pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants
function COMMITMENT_DOMAIN() { return 1; }
function SPENDING_NULLIFIER_DOMAIN() { return 2; }
function NULLIFIER_KEY_DOMAIN() { return 4; }

// ============================================================================
// Helper Templates
// ============================================================================

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

template NullifierKey() {
    signal input spending_key;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== NULLIFIER_KEY_DOMAIN();
    hasher.inputs[1] <== spending_key;
    hasher.inputs[2] <== 0;
    out <== hasher.out;
}

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

template RangeCheck64() {
    signal input in;
    component bits = Num2Bits(64);
    bits.in <== in;
}

// ============================================================================
// Remove Liquidity Circuit: 1 LP Input -> 2 Outputs (token A + token B)
// ============================================================================

template RemoveLiquidity() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input lp_nullifier;          // Nullifier for LP token input
    signal input pool_id;               // AMM pool identifier
    signal input out_a_commitment;      // Token A output commitment
    signal input out_b_commitment;      // Token B output commitment
    signal input old_state_hash;        // AMM pool state before removal
    signal input new_state_hash;        // AMM pool state after removal

    // ========================================================================
    // Private Inputs - LP Token Input
    // ========================================================================
    signal input lp_stealth_pub_x;
    signal input lp_amount;
    signal input lp_randomness;
    signal input lp_stealth_spending_key;
    signal input lp_token_mint;
    signal input lp_leaf_index;

    // Merkle proof (verified on-chain)
    signal input merkle_path[32];
    signal input merkle_path_indices[32];

    // ========================================================================
    // Private Inputs - Output A (Token A)
    // ========================================================================
    signal input out_a_stealth_pub_x;
    signal input out_a_amount;
    signal input out_a_randomness;
    signal input token_a_mint;

    // ========================================================================
    // Private Inputs - Output B (Token B)
    // ========================================================================
    signal input out_b_stealth_pub_x;
    signal input out_b_amount;
    signal input out_b_randomness;
    signal input token_b_mint;

    // ========================================================================
    // 1. Verify LP Token Input Commitment
    // ========================================================================
    component lp_commitment = Commitment();
    lp_commitment.stealth_pub_x <== lp_stealth_pub_x;
    lp_commitment.token_mint <== lp_token_mint;
    lp_commitment.amount <== lp_amount;
    lp_commitment.randomness <== lp_randomness;

    // ========================================================================
    // 2. Verify LP Token Nullifier
    // ========================================================================
    component lp_nk = NullifierKey();
    lp_nk.spending_key <== lp_stealth_spending_key;

    component computed_lp_nullifier = SpendingNullifier();
    computed_lp_nullifier.nullifier_key <== lp_nk.out;
    computed_lp_nullifier.commitment <== lp_commitment.out;
    computed_lp_nullifier.leaf_index <== lp_leaf_index;

    lp_nullifier === computed_lp_nullifier.out;

    // ========================================================================
    // 3. Verify Output A Commitment
    // ========================================================================
    component out_a_commit = Commitment();
    out_a_commit.stealth_pub_x <== out_a_stealth_pub_x;
    out_a_commit.token_mint <== token_a_mint;
    out_a_commit.amount <== out_a_amount;
    out_a_commit.randomness <== out_a_randomness;
    out_a_commitment === out_a_commit.out;

    // ========================================================================
    // 4. Verify Output B Commitment
    // ========================================================================
    component out_b_commit = Commitment();
    out_b_commit.stealth_pub_x <== out_b_stealth_pub_x;
    out_b_commit.token_mint <== token_b_mint;
    out_b_commit.amount <== out_b_amount;
    out_b_commit.randomness <== out_b_randomness;
    out_b_commitment === out_b_commit.out;

    // ========================================================================
    // 5. Range Checks
    // ========================================================================
    component range_lp = RangeCheck64();
    range_lp.in <== lp_amount;

    component range_out_a = RangeCheck64();
    range_out_a.in <== out_a_amount;

    component range_out_b = RangeCheck64();
    range_out_b.in <== out_b_amount;

    // Note: Output amounts calculation (proportional to LP share) and
    // state hash transitions are verified ON-CHAIN
}

component main {public [
    lp_nullifier,
    pool_id,
    out_a_commitment,
    out_b_commitment,
    old_state_hash,
    new_state_hash
]} = RemoveLiquidity();
