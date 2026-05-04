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
// Add Liquidity Circuit: 2 Inputs -> 3 Outputs (LP + change A + change B)
// ============================================================================

template AddLiquidity() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input nullifier_a;           // Nullifier for token A input
    signal input nullifier_b;           // Nullifier for token B input
    signal input pool_id;               // AMM pool identifier
    signal input lp_commitment;         // LP token output commitment
    signal input change_a_commitment;   // Change commitment for token A
    signal input change_b_commitment;   // Change commitment for token B

    // ========================================================================
    // Private Inputs - Token A
    // ========================================================================
    signal input in_a_stealth_pub_x;
    signal input in_a_amount;
    signal input in_a_randomness;
    signal input in_a_stealth_spending_key;
    signal input token_a_mint;
    signal input in_a_leaf_index;

    // Merkle proof A (verified on-chain)
    signal input merkle_path_a[32];
    signal input merkle_path_indices_a[32];

    // ========================================================================
    // Private Inputs - Token B
    // ========================================================================
    signal input in_b_stealth_pub_x;
    signal input in_b_amount;
    signal input in_b_randomness;
    signal input in_b_stealth_spending_key;
    signal input token_b_mint;
    signal input in_b_leaf_index;

    // Merkle proof B (verified on-chain)
    signal input merkle_path_b[32];
    signal input merkle_path_indices_b[32];

    // ========================================================================
    // Private Inputs - Deposit Amounts
    // ========================================================================
    signal input deposit_a;             // Amount of token A to deposit
    signal input deposit_b;             // Amount of token B to deposit

    // ========================================================================
    // Private Inputs - LP Token Output
    // ========================================================================
    signal input lp_stealth_pub_x;
    signal input lp_token_mint;         // LP token mint
    signal input lp_amount;
    signal input lp_randomness;

    // ========================================================================
    // Private Inputs - Change A
    // ========================================================================
    signal input change_a_stealth_pub_x;
    signal input change_a_amount;
    signal input change_a_randomness;

    // ========================================================================
    // Private Inputs - Change B
    // ========================================================================
    signal input change_b_stealth_pub_x;
    signal input change_b_amount;
    signal input change_b_randomness;

    // ========================================================================
    // 1. Verify Token A Input Commitment
    // ========================================================================
    component in_a_commitment = Commitment();
    in_a_commitment.stealth_pub_x <== in_a_stealth_pub_x;
    in_a_commitment.token_mint <== token_a_mint;
    in_a_commitment.amount <== in_a_amount;
    in_a_commitment.randomness <== in_a_randomness;

    // ========================================================================
    // 2. Verify Token A Nullifier
    // ========================================================================
    component nk_a = NullifierKey();
    nk_a.spending_key <== in_a_stealth_spending_key;

    component computed_nullifier_a = SpendingNullifier();
    computed_nullifier_a.nullifier_key <== nk_a.out;
    computed_nullifier_a.commitment <== in_a_commitment.out;
    computed_nullifier_a.leaf_index <== in_a_leaf_index;

    nullifier_a === computed_nullifier_a.out;

    // ========================================================================
    // 3. Verify Token B Input Commitment
    // ========================================================================
    component in_b_commitment = Commitment();
    in_b_commitment.stealth_pub_x <== in_b_stealth_pub_x;
    in_b_commitment.token_mint <== token_b_mint;
    in_b_commitment.amount <== in_b_amount;
    in_b_commitment.randomness <== in_b_randomness;

    // ========================================================================
    // 4. Verify Token B Nullifier
    // ========================================================================
    component nk_b = NullifierKey();
    nk_b.spending_key <== in_b_stealth_spending_key;

    component computed_nullifier_b = SpendingNullifier();
    computed_nullifier_b.nullifier_key <== nk_b.out;
    computed_nullifier_b.commitment <== in_b_commitment.out;
    computed_nullifier_b.leaf_index <== in_b_leaf_index;

    nullifier_b === computed_nullifier_b.out;

    // ========================================================================
    // 5. Verify LP Output Commitment
    // ========================================================================
    component lp_commit = Commitment();
    lp_commit.stealth_pub_x <== lp_stealth_pub_x;
    lp_commit.token_mint <== lp_token_mint;
    lp_commit.amount <== lp_amount;
    lp_commit.randomness <== lp_randomness;
    lp_commitment === lp_commit.out;

    // ========================================================================
    // 6. Verify Change A Commitment
    // ========================================================================
    component change_a_commit = Commitment();
    change_a_commit.stealth_pub_x <== change_a_stealth_pub_x;
    change_a_commit.token_mint <== token_a_mint;
    change_a_commit.amount <== change_a_amount;
    change_a_commit.randomness <== change_a_randomness;
    change_a_commitment === change_a_commit.out;

    // ========================================================================
    // 7. Verify Change B Commitment
    // ========================================================================
    component change_b_commit = Commitment();
    change_b_commit.stealth_pub_x <== change_b_stealth_pub_x;
    change_b_commit.token_mint <== token_b_mint;
    change_b_commit.amount <== change_b_amount;
    change_b_commit.randomness <== change_b_randomness;
    change_b_commitment === change_b_commit.out;

    // ========================================================================
    // 8. Balance Checks
    // ========================================================================
    // Token A: input = deposit + change
    signal total_a_out;
    total_a_out <== deposit_a + change_a_amount;
    in_a_amount === total_a_out;

    // Token B: input = deposit + change
    signal total_b_out;
    total_b_out <== deposit_b + change_b_amount;
    in_b_amount === total_b_out;

    // ========================================================================
    // 9. Range Checks
    // ========================================================================
    component range_in_a = RangeCheck64();
    range_in_a.in <== in_a_amount;

    component range_in_b = RangeCheck64();
    range_in_b.in <== in_b_amount;

    component range_deposit_a = RangeCheck64();
    range_deposit_a.in <== deposit_a;

    component range_deposit_b = RangeCheck64();
    range_deposit_b.in <== deposit_b;

    component range_lp = RangeCheck64();
    range_lp.in <== lp_amount;

    component range_change_a = RangeCheck64();
    range_change_a.in <== change_a_amount;

    component range_change_b = RangeCheck64();
    range_change_b.in <== change_b_amount;

    // Note: LP token amount calculation (sqrt(deposit_a * deposit_b) for first deposit,
    // or proportional for subsequent) is verified ON-CHAIN
}

component main {public [
    nullifier_a,
    nullifier_b,
    pool_id,
    lp_commitment,
    change_a_commitment,
    change_b_commitment
]} = AddLiquidity();
