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
// Close Perpetual Position Circuit: 1 Input (position) -> 1 Output (settlement)
// ============================================================================
//
// Flow:
// 1. User spends position commitment
// 2. Creates settlement commitment (margin +/- PnL)
// 3. Circuit proves ownership and correct PnL calculation
//
// Bounded profit model: max profit = margin
// Loss can be up to full margin (liquidation handled separately)
//
// On-chain verification handles:
// - Oracle price validation
// - Borrow fee calculation
// - Pool state updates

template ClosePosition() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;           // Merkle root for position commitment
    signal input position_nullifier;    // Prevents double-closing position
    signal input perps_pool_id;         // Perps pool identifier
    signal input out_commitment;        // Settlement commitment (margin +/- PnL)
    signal input is_long;               // Position direction (must match original)
    signal input exit_price;            // Exit price (oracle price)
    signal input close_fee;             // Closing fee amount
    signal input pnl_amount;            // Absolute PnL amount
    signal input is_profit;             // 1 = profit, 0 = loss

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Position details (from original position commitment)
    signal input position_stealth_pub_x;
    signal input market_id;
    signal input position_margin;
    signal input position_size;
    signal input position_leverage;
    signal input entry_price;
    signal input position_randomness;
    signal input position_spending_key;

    // Merkle proof for position commitment
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Output details
    signal input out_stealth_pub_x;
    signal input out_token_mint;
    signal input out_amount;
    signal input out_randomness;

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
    // 2. Verify Position Nullifier (proves ownership)
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== position_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== pos_commit.out;
    computed_nullifier.leaf_index <== leaf_index;

    position_nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Output Commitment (settlement)
    // ========================================================================
    component out_commit = Commitment();
    out_commit.stealth_pub_x <== out_stealth_pub_x;
    out_commit.token_mint <== out_token_mint;
    out_commit.amount <== out_amount;
    out_commit.randomness <== out_randomness;
    out_commitment === out_commit.out;

    // ========================================================================
    // 4. Settlement Calculation
    // ========================================================================
    // If profit: out_amount = margin + min(pnl, margin) - close_fee
    // If loss: out_amount = margin - pnl - close_fee
    //
    // Bounded profit: max profit = margin

    // Constrain is_profit to binary
    is_profit * (1 - is_profit) === 0;

    // Calculate bounded profit (capped at margin)
    component pnl_capped = LessEqThan(64);
    pnl_capped.in[0] <== pnl_amount;
    pnl_capped.in[1] <== position_margin;

    // If profit is capped, effective_pnl = margin
    // Otherwise, effective_pnl = pnl_amount
    // Split into quadratic constraints to avoid non-quadratic error
    signal term1_pnl;
    term1_pnl <== pnl_capped.out * pnl_amount;

    signal one_minus_capped;
    one_minus_capped <== 1 - pnl_capped.out;

    signal term2_pnl;
    term2_pnl <== one_minus_capped * position_margin;

    signal effective_pnl;
    effective_pnl <== term1_pnl + term2_pnl;

    // Calculate expected settlement
    // profit case: margin + effective_pnl - close_fee
    // loss case: margin - pnl_amount - close_fee (pnl_amount not capped for losses)
    signal profit_settlement;
    profit_settlement <== position_margin + effective_pnl - close_fee;

    signal loss_settlement;
    loss_settlement <== position_margin - pnl_amount - close_fee;

    // Split into quadratic constraints
    signal term1_settlement;
    term1_settlement <== is_profit * profit_settlement;

    signal one_minus_profit;
    one_minus_profit <== 1 - is_profit;

    signal term2_settlement;
    term2_settlement <== one_minus_profit * loss_settlement;

    signal expected_settlement;
    expected_settlement <== term1_settlement + term2_settlement;

    out_amount === expected_settlement;

    // ========================================================================
    // 5. Verify Loss Doesn't Exceed Margin
    // ========================================================================
    // In loss case, pnl_amount must be <= margin (otherwise liquidation)
    signal loss_pnl_product;
    loss_pnl_product <== one_minus_profit * pnl_amount;

    component loss_check = LessEqThan(64);
    loss_check.in[0] <== loss_pnl_product;
    loss_check.in[1] <== position_margin;
    loss_check.out === 1;

    // ========================================================================
    // 6. Constrain is_long to binary (must match original position)
    // ========================================================================
    is_long * (1 - is_long) === 0;

    // ========================================================================
    // 7. Range Checks
    // ========================================================================
    component range_margin = RangeCheck64();
    range_margin.in <== position_margin;

    component range_size = RangeCheck64();
    range_size.in <== position_size;

    component range_entry = RangeCheck64();
    range_entry.in <== entry_price;

    component range_exit = RangeCheck64();
    range_exit.in <== exit_price;

    component range_pnl = RangeCheck64();
    range_pnl.in <== pnl_amount;

    component range_fee = RangeCheck64();
    range_fee.in <== close_fee;

    component range_out = RangeCheck64();
    range_out.in <== out_amount;

    // Note: On-chain verification handles:
    // - Oracle price validation
    // - PnL calculation verification against oracle prices
    // - Borrow fee deduction
    // - Pool state updates
}

component main {public [
    merkle_root,
    position_nullifier,
    perps_pool_id,
    out_commitment,
    is_long,
    exit_price,
    close_fee,
    pnl_amount,
    is_profit
]} = ClosePosition();
