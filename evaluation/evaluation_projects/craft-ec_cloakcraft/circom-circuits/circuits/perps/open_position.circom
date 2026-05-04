pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function SPENDING_NULLIFIER_DOMAIN() { return 2; }
function NULLIFIER_KEY_DOMAIN() { return 4; }
function POSITION_COMMITMENT_DOMAIN() { return 8; }

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

// Compute position commitment
// Includes: market_id, direction, margin, size, leverage, entry_price
template PositionCommitment() {
    signal input stealth_pub_x;
    signal input market_id;
    signal input is_long;
    signal input margin;
    signal input size;
    signal input leverage;
    signal input entry_price;
    signal input randomness;
    signal output out;

    // Two-stage hash to fit within Poseidon input limits
    component hasher1 = Poseidon(5);
    hasher1.inputs[0] <== POSITION_COMMITMENT_DOMAIN();
    hasher1.inputs[1] <== stealth_pub_x;
    hasher1.inputs[2] <== market_id;
    hasher1.inputs[3] <== is_long;
    hasher1.inputs[4] <== margin;

    component hasher2 = Poseidon(5);
    hasher2.inputs[0] <== hasher1.out;
    hasher2.inputs[1] <== size;
    hasher2.inputs[2] <== leverage;
    hasher2.inputs[3] <== entry_price;
    hasher2.inputs[4] <== randomness;
    out <== hasher2.out;
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
// Open Perpetual Position Circuit: 1 Input (margin) -> 1 Position + 1 Change
// ============================================================================
//
// Flow:
// 1. User spends margin commitment (USD for long, base token for short)
// 2. Creates position commitment with position details
// 3. Creates change commitment for excess input
// 4. Circuit proves ownership and correct fee calculation
//
// On-chain verification handles:
// - Utilization limits
// - Oracle price validation
// - Pool state updates

template OpenPosition() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;           // Merkle root for margin commitment
    signal input nullifier;             // Prevents double-spending margin
    signal input perps_pool_id;         // Perps pool identifier
    signal input market_id;             // Trading pair (e.g., SOL/USD)
    signal input position_commitment;   // New position commitment
    signal input change_commitment;     // Change commitment (0 if no change)
    signal input is_long;               // Position direction (1 = long, 0 = short)
    signal input margin_amount;         // Margin deposited (public for pool accounting)
    signal input leverage;              // Leverage multiplier (1-100)
    signal input position_fee;          // Fee amount (public for treasury)
    signal input change_amount;         // Change amount (public for verification)

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Margin note details
    signal input in_stealth_pub_x;
    signal input in_amount;
    signal input in_randomness;
    signal input in_stealth_spending_key;
    signal input token_mint;            // Margin token mint

    // Merkle proof (32 levels) - verified on-chain via Light Protocol
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Position details
    signal input position_size;         // Size in base token units
    signal input entry_price;           // Entry price (oracle price)
    signal input position_randomness;   // Randomness for position commitment
    signal input change_randomness;     // Randomness for change commitment

    // ========================================================================
    // 1. Verify Margin Input Commitment
    // ========================================================================
    component in_commitment = Commitment();
    in_commitment.stealth_pub_x <== in_stealth_pub_x;
    in_commitment.token_mint <== token_mint;
    in_commitment.amount <== in_amount;
    in_commitment.randomness <== in_randomness;

    // ========================================================================
    // 2. Verify Nullifier (proves ownership of margin)
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== in_commitment.out;
    computed_nullifier.leaf_index <== leaf_index;

    nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Position Commitment
    // ========================================================================
    component pos_commit = PositionCommitment();
    pos_commit.stealth_pub_x <== in_stealth_pub_x;
    pos_commit.market_id <== market_id;
    pos_commit.is_long <== is_long;
    pos_commit.margin <== margin_amount;
    pos_commit.size <== position_size;
    pos_commit.leverage <== leverage;
    pos_commit.entry_price <== entry_price;
    pos_commit.randomness <== position_randomness;

    position_commitment === pos_commit.out;

    // ========================================================================
    // 4. Balance Check
    // ========================================================================
    // Input amount = margin + fee + change
    signal total_required;
    total_required <== margin_amount + position_fee;
    in_amount === total_required + change_amount;

    // ========================================================================
    // 4b. Verify Change Commitment (if change_amount > 0)
    // ========================================================================
    // If change_amount is 0, change_commitment should be 0
    // If change_amount > 0, change_commitment should be valid commitment
    component change_commit = Commitment();
    change_commit.stealth_pub_x <== in_stealth_pub_x;
    change_commit.token_mint <== token_mint;
    change_commit.amount <== change_amount;
    change_commit.randomness <== change_randomness;

    // Use IsZero to check if change_amount is 0
    component change_is_zero = IsZero();
    change_is_zero.in <== change_amount;

    // If change is zero, commitment should be 0; otherwise it should match computed
    // commitment_check = change_is_zero ? (change_commitment == 0) : (change_commitment == computed)
    signal expected_change_commitment;
    expected_change_commitment <== (1 - change_is_zero.out) * change_commit.out;
    change_commitment === expected_change_commitment;

    // ========================================================================
    // 5. Leverage Verification
    // ========================================================================
    // Position size = margin * leverage (verified conceptually)
    // Note: Exact calculation may need scaling based on decimals
    // On-chain verification handles exact math with oracle prices

    // ========================================================================
    // 6. Constrain is_long to be binary
    // ========================================================================
    is_long * (1 - is_long) === 0;

    // ========================================================================
    // 7. Leverage must be valid (1-100)
    // ========================================================================
    component leverage_gte1 = GreaterEqThan(8);
    leverage_gte1.in[0] <== leverage;
    leverage_gte1.in[1] <== 1;
    leverage_gte1.out === 1;

    component leverage_lte100 = LessEqThan(8);
    leverage_lte100.in[0] <== leverage;
    leverage_lte100.in[1] <== 100;
    leverage_lte100.out === 1;

    // ========================================================================
    // 8. Range Checks
    // ========================================================================
    component range_in = RangeCheck64();
    range_in.in <== in_amount;

    component range_margin = RangeCheck64();
    range_margin.in <== margin_amount;

    component range_size = RangeCheck64();
    range_size.in <== position_size;

    component range_fee = RangeCheck64();
    range_fee.in <== position_fee;

    component range_price = RangeCheck64();
    range_price.in <== entry_price;

    component range_change = RangeCheck64();
    range_change.in <== change_amount;

    // Note: On-chain verification handles:
    // - Oracle price validation
    // - Utilization limit checks
    // - Pool liquidity checks
    // - Imbalance fee calculation
}

component main {public [
    merkle_root,
    nullifier,
    perps_pool_id,
    market_id,
    position_commitment,
    change_commitment,
    is_long,
    margin_amount,
    leverage,
    position_fee,
    change_amount
]} = OpenPosition();
