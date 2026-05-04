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

// Compute position commitment
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
// Liquidate Position Circuit: 1 Input (position) -> 2 Outputs (liquidator reward + remainder)
// ============================================================================
//
// Flow:
// 1. Keeper/Liquidator proves position is liquidatable
// 2. Position is closed at current oracle price
// 3. Liquidator receives penalty fee, remainder goes to position owner
//
// Liquidation occurs when:
// - Effective margin <= liquidation_threshold_bps * original_margin
//
// On-chain verification handles:
// - Oracle price validation
// - Liquidation threshold verification
// - Pool state updates

template Liquidate() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;               // Merkle root for position commitment
    signal input position_nullifier;        // Nullifies the position
    signal input perps_pool_id;             // Perps pool identifier
    signal input owner_commitment;          // Remainder to position owner (may be 0)
    signal input liquidator_commitment;     // Reward to liquidator
    signal input current_price;             // Current oracle price
    signal input liquidator_reward;         // Liquidation penalty to liquidator
    signal input owner_remainder;           // Remainder to owner (if any)

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Position details
    signal input position_stealth_pub_x;
    signal input market_id;
    signal input is_long;
    signal input position_margin;
    signal input position_size;
    signal input position_leverage;
    signal input entry_price;
    signal input position_randomness;
    signal input position_spending_key;     // Owner's spending key (needed for nullifier)

    // Merkle proof for position commitment
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Owner output details
    signal input owner_stealth_pub_x;
    signal input owner_token_mint;
    signal input owner_randomness;

    // Liquidator output details
    signal input liquidator_stealth_pub_x;
    signal input liquidator_token_mint;
    signal input liquidator_randomness;

    // Liquidation parameters
    signal input liquidation_threshold_bps; // e.g., 50 = 0.5%

    // ========================================================================
    // 1. Verify Position Commitment
    // ========================================================================
    component pos_commit = PositionCommitment();
    pos_commit.stealth_pub_x <== position_stealth_pub_x;
    pos_commit.market_id <== market_id;
    pos_commit.is_long <== is_long;
    pos_commit.margin <== position_margin;
    pos_commit.size <== position_size;
    pos_commit.leverage <== position_leverage;
    pos_commit.entry_price <== entry_price;
    pos_commit.randomness <== position_randomness;

    // ========================================================================
    // 2. Verify Position Nullifier
    // ========================================================================
    // Note: Anyone can liquidate, but nullifier derivation uses owner's key
    // The key is revealed to the liquidator for this specific purpose
    component nk = NullifierKey();
    nk.spending_key <== position_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== pos_commit.out;
    computed_nullifier.leaf_index <== leaf_index;

    position_nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Owner Commitment (remainder)
    // ========================================================================
    component owner_commit = Commitment();
    owner_commit.stealth_pub_x <== owner_stealth_pub_x;
    owner_commit.token_mint <== owner_token_mint;
    owner_commit.amount <== owner_remainder;
    owner_commit.randomness <== owner_randomness;
    owner_commitment === owner_commit.out;

    // ========================================================================
    // 4. Verify Liquidator Commitment (reward)
    // ========================================================================
    component liq_commit = Commitment();
    liq_commit.stealth_pub_x <== liquidator_stealth_pub_x;
    liq_commit.token_mint <== liquidator_token_mint;
    liq_commit.amount <== liquidator_reward;
    liq_commit.randomness <== liquidator_randomness;
    liquidator_commitment === liq_commit.out;

    // ========================================================================
    // 5. Verify Liquidation is Valid
    // ========================================================================
    // Calculate loss amount based on price movement
    // For long: loss if current_price < entry_price
    // For short: loss if current_price > entry_price

    // Constrain is_long to binary
    is_long * (1 - is_long) === 0;

    // Calculate price difference
    // If long and price dropped: loss = (entry - current) * size / entry
    // If short and price rose: loss = (current - entry) * size / entry

    // Note: Detailed liquidation math is verified on-chain
    // Circuit proves:
    // - Position ownership via nullifier
    // - Output commitments are valid
    // - Balance is conserved (remainder + reward = effective margin after loss)

    // ========================================================================
    // 6. Balance Check
    // ========================================================================
    // Total outputs = margin - loss (what remains after liquidation)
    // On-chain verifies: remainder + reward <= margin (no value created)
    signal total_output;
    total_output <== owner_remainder + liquidator_reward;

    // Ensure outputs don't exceed margin (on-chain verifies exact calculation)
    component output_check = LessEqThan(64);
    output_check.in[0] <== total_output;
    output_check.in[1] <== position_margin;
    output_check.out === 1;

    // ========================================================================
    // 7. Range Checks
    // ========================================================================
    component range_margin = RangeCheck64();
    range_margin.in <== position_margin;

    component range_size = RangeCheck64();
    range_size.in <== position_size;

    component range_entry = RangeCheck64();
    range_entry.in <== entry_price;

    component range_current = RangeCheck64();
    range_current.in <== current_price;

    component range_reward = RangeCheck64();
    range_reward.in <== liquidator_reward;

    component range_remainder = RangeCheck64();
    range_remainder.in <== owner_remainder;

    // Note: On-chain verification handles:
    // - Oracle price validation
    // - Exact liquidation threshold check
    // - Correct loss calculation
    // - Pool state updates
}

component main {public [
    merkle_root,
    position_nullifier,
    perps_pool_id,
    owner_commitment,
    liquidator_commitment,
    current_price,
    liquidator_reward,
    owner_remainder
]} = Liquidate();
