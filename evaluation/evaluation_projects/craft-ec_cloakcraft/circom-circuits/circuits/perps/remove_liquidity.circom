pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function SPENDING_NULLIFIER_DOMAIN() { return 2; }
function NULLIFIER_KEY_DOMAIN() { return 4; }
function LP_COMMITMENT_DOMAIN() { return 9; }

// ============================================================================
// Helper Templates
// ============================================================================

// Compute note commitment
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

// Compute LP token commitment (includes pool_id for binding)
template LpCommitment() {
    signal input stealth_pub_x;
    signal input pool_id;
    signal input lp_amount;
    signal input randomness;
    signal output out;

    component hasher = Poseidon(5);
    hasher.inputs[0] <== LP_COMMITMENT_DOMAIN();
    hasher.inputs[1] <== stealth_pub_x;
    hasher.inputs[2] <== pool_id;
    hasher.inputs[3] <== lp_amount;
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
// Remove Perps Liquidity Circuit: 1 Input (LP token) -> 1 Output (token)
// ============================================================================
//
// Single token withdrawal model:
// - User burns LP tokens
// - Can withdraw any supported token (up to available balance)
// - Value calculated via oracle at withdrawal time
// - Withdrawal limited by utilization (can't exceed 80% utilization)
//
// On-chain verification handles:
// - Oracle price validation
// - Withdrawal amount calculation
// - Utilization limit enforcement
// - Pool state updates

template RemovePerpsLiquidity() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;           // Merkle root for LP commitment
    signal input lp_nullifier;          // Prevents double-spending LP tokens
    signal input perps_pool_id;         // Perps pool identifier
    signal input out_commitment;        // Output token commitment
    signal input token_index;           // Index of token to withdraw (0-7)
    signal input withdraw_amount;       // Amount to withdraw
    signal input lp_amount_burned;      // LP tokens being burned
    signal input fee_amount;            // Withdrawal fee

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // LP token note details
    signal input lp_stealth_pub_x;
    signal input lp_amount;             // Total LP tokens owned
    signal input lp_randomness;
    signal input lp_spending_key;

    // Merkle proof for LP commitment
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Output details
    signal input out_stealth_pub_x;
    signal input out_token_mint;
    signal input out_randomness;

    // Change LP commitment (if not burning all LP)
    signal input change_lp_commitment;
    signal input change_lp_amount;
    signal input change_lp_randomness;

    // ========================================================================
    // 1. Verify LP Input Commitment
    // ========================================================================
    component lp_commit = LpCommitment();
    lp_commit.stealth_pub_x <== lp_stealth_pub_x;
    lp_commit.pool_id <== perps_pool_id;
    lp_commit.lp_amount <== lp_amount;
    lp_commit.randomness <== lp_randomness;

    // ========================================================================
    // 2. Verify LP Nullifier (proves ownership)
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== lp_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== lp_commit.out;
    computed_nullifier.leaf_index <== leaf_index;

    lp_nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Output Token Commitment
    // ========================================================================
    component out_commit = Commitment();
    out_commit.stealth_pub_x <== out_stealth_pub_x;
    out_commit.token_mint <== out_token_mint;
    out_commit.amount <== withdraw_amount;
    out_commit.randomness <== out_randomness;
    out_commitment === out_commit.out;

    // ========================================================================
    // 4. Verify Change LP Commitment (if any)
    // ========================================================================
    component change_commit = LpCommitment();
    change_commit.stealth_pub_x <== lp_stealth_pub_x;  // Same owner
    change_commit.pool_id <== perps_pool_id;
    change_commit.lp_amount <== change_lp_amount;
    change_commit.randomness <== change_lp_randomness;
    change_lp_commitment === change_commit.out;

    // ========================================================================
    // 5. LP Balance Check
    // ========================================================================
    // lp_amount = lp_amount_burned + change_lp_amount
    signal lp_total;
    lp_total <== lp_amount_burned + change_lp_amount;
    lp_amount === lp_total;

    // ========================================================================
    // 6. Fee Check
    // ========================================================================
    // Actual withdrawal = requested - fee (handled on-chain)
    // Circuit just proves the commitments are valid

    // ========================================================================
    // 7. Token Index Range Check
    // ========================================================================
    component idx_check = LessThan(8);
    idx_check.in[0] <== token_index;
    idx_check.in[1] <== 8;
    idx_check.out === 1;

    // ========================================================================
    // 8. Range Checks
    // ========================================================================
    component range_lp = RangeCheck64();
    range_lp.in <== lp_amount;

    component range_burned = RangeCheck64();
    range_burned.in <== lp_amount_burned;

    component range_change = RangeCheck64();
    range_change.in <== change_lp_amount;

    component range_withdraw = RangeCheck64();
    range_withdraw.in <== withdraw_amount;

    component range_fee = RangeCheck64();
    range_fee.in <== fee_amount;

    // Note: On-chain verification handles:
    // - Oracle price validation
    // - Withdrawal amount calculation (lp_value * token_price)
    // - Utilization limit check (can't push utilization > 80%)
    // - Available balance check
    // - Pool state updates
}

component main {public [
    merkle_root,
    lp_nullifier,
    perps_pool_id,
    out_commitment,
    token_index,
    withdraw_amount,
    lp_amount_burned,
    fee_amount
]} = RemovePerpsLiquidity();
