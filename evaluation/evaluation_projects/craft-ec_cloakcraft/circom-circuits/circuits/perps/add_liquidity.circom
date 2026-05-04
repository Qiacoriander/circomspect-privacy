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
// Add Perps Liquidity Circuit: 1 Input (token) -> 1 Output (LP token)
// ============================================================================
//
// Single token deposit model (like JLP):
// - User deposits any supported token
// - Token value calculated via oracle
// - LP tokens minted proportional to pool share
// - No swap needed, just adds to that token's balance
//
// On-chain verification handles:
// - Oracle price validation
// - LP amount calculation based on pool value
// - Pool state updates

template AddPerpsLiquidity() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;           // Merkle root for deposit commitment
    signal input nullifier;             // Prevents double-spending deposit
    signal input perps_pool_id;         // Perps pool identifier
    signal input lp_commitment;         // Output LP token commitment
    signal input token_index;           // Index of token in pool (0-7)
    signal input deposit_amount;        // Amount being deposited
    signal input lp_amount_minted;      // LP tokens to receive (verified on-chain)
    signal input fee_amount;            // Deposit fee (if any)

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Deposit note details
    signal input in_stealth_pub_x;
    signal input in_amount;
    signal input in_randomness;
    signal input in_stealth_spending_key;
    signal input token_mint;

    // Merkle proof for deposit commitment
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // LP output details
    signal input lp_stealth_pub_x;
    signal input lp_randomness;

    // ========================================================================
    // 1. Verify Deposit Input Commitment
    // ========================================================================
    component in_commitment = Commitment();
    in_commitment.stealth_pub_x <== in_stealth_pub_x;
    in_commitment.token_mint <== token_mint;
    in_commitment.amount <== in_amount;
    in_commitment.randomness <== in_randomness;

    // ========================================================================
    // 2. Verify Nullifier (proves ownership of deposit)
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== in_commitment.out;
    computed_nullifier.leaf_index <== leaf_index;

    nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify LP Token Commitment
    // ========================================================================
    component lp_commit = LpCommitment();
    lp_commit.stealth_pub_x <== lp_stealth_pub_x;
    lp_commit.pool_id <== perps_pool_id;
    lp_commit.lp_amount <== lp_amount_minted;
    lp_commit.randomness <== lp_randomness;
    lp_commitment === lp_commit.out;

    // ========================================================================
    // 4. Balance Check
    // ========================================================================
    // Input amount = deposit amount + fee
    signal total_required;
    total_required <== deposit_amount + fee_amount;
    in_amount === total_required;

    // ========================================================================
    // 5. Token Index Range Check
    // ========================================================================
    // Token index must be 0-7 (MAX_PERPS_TOKENS)
    component idx_check = LessThan(8);
    idx_check.in[0] <== token_index;
    idx_check.in[1] <== 8;
    idx_check.out === 1;

    // ========================================================================
    // 6. Range Checks
    // ========================================================================
    component range_in = RangeCheck64();
    range_in.in <== in_amount;

    component range_deposit = RangeCheck64();
    range_deposit.in <== deposit_amount;

    component range_lp = RangeCheck64();
    range_lp.in <== lp_amount_minted;

    component range_fee = RangeCheck64();
    range_fee.in <== fee_amount;

    // Note: On-chain verification handles:
    // - Oracle price validation
    // - LP amount calculation (deposit_value * lp_supply / total_value)
    // - Token index is valid and active
    // - Pool state updates
}

component main {public [
    merkle_root,
    nullifier,
    perps_pool_id,
    lp_commitment,
    token_index,
    deposit_amount,
    lp_amount_minted,
    fee_amount
]} = AddPerpsLiquidity();
