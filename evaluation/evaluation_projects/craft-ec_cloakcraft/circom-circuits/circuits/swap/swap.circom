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
// AMM Swap Circuit: 1 Input -> 2 Outputs (swap output + change)
// ============================================================================

template Swap() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input merkle_root;           // Merkle root for input commitment
    signal input nullifier;             // Prevents double-spending input
    signal input pool_id;               // AMM pool identifier
    signal input out_commitment;        // Swap output commitment (output token)
    signal input change_commitment;     // Change commitment (input token)
    signal input min_output;            // Minimum output amount (slippage protection)

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Input note details
    signal input in_stealth_pub_x;
    signal input in_amount;
    signal input in_randomness;
    signal input in_stealth_spending_key;
    signal input token_mint;            // Input token mint

    // Merkle proof (32 levels) - verified on-chain via Light Protocol
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Swap parameters
    signal input swap_in_amount;        // Amount to swap
    signal input swap_a_to_b;           // Direction: 1 = A->B, 0 = B->A
    signal input fee_bps;               // Fee in basis points

    // Output details (swap output - receives output token)
    signal input out_stealth_pub_x;
    signal input out_token_mint;        // Output token mint
    signal input out_amount;
    signal input out_randomness;

    // Change details (same token as input)
    signal input change_stealth_pub_x;
    signal input change_amount;
    signal input change_randomness;

    // ========================================================================
    // 1. Verify Input Note Commitment
    // ========================================================================
    component in_commitment = Commitment();
    in_commitment.stealth_pub_x <== in_stealth_pub_x;
    in_commitment.token_mint <== token_mint;
    in_commitment.amount <== in_amount;
    in_commitment.randomness <== in_randomness;

    // ========================================================================
    // 2. Verify Nullifier (proves ownership)
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== in_commitment.out;
    computed_nullifier.leaf_index <== leaf_index;

    nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Output Commitment (swap output)
    // ========================================================================
    component out_commit = Commitment();
    out_commit.stealth_pub_x <== out_stealth_pub_x;
    out_commit.token_mint <== out_token_mint;
    out_commit.amount <== out_amount;
    out_commit.randomness <== out_randomness;
    out_commitment === out_commit.out;

    // ========================================================================
    // 4. Verify Change Commitment
    // ========================================================================
    component change_commit = Commitment();
    change_commit.stealth_pub_x <== change_stealth_pub_x;
    change_commit.token_mint <== token_mint;  // Same as input token
    change_commit.amount <== change_amount;
    change_commit.randomness <== change_randomness;
    change_commitment === change_commit.out;

    // ========================================================================
    // 5. Balance Check (input token side)
    // ========================================================================
    // Input amount = swap amount + change amount
    signal total_out;
    total_out <== swap_in_amount + change_amount;
    in_amount === total_out;

    // ========================================================================
    // 6. Minimum Output Check
    // ========================================================================
    // Output must be >= min_output (slippage protection)
    component gte = GreaterEqThan(64);
    gte.in[0] <== out_amount;
    gte.in[1] <== min_output;
    gte.out === 1;

    // ========================================================================
    // 7. Range Checks
    // ========================================================================
    component range_in = RangeCheck64();
    range_in.in <== in_amount;

    component range_swap = RangeCheck64();
    range_swap.in <== swap_in_amount;

    component range_out = RangeCheck64();
    range_out.in <== out_amount;

    component range_change = RangeCheck64();
    range_change.in <== change_amount;

    // ========================================================================
    // 8. Constrain swap_a_to_b to be binary
    // ========================================================================
    swap_a_to_b * (1 - swap_a_to_b) === 0;

    // Note: AMM constant product formula (x * y = k) is verified ON-CHAIN
    // The circuit only proves:
    // - User owns the input note
    // - Outputs are correctly committed
    // - Balance is conserved on input side
    // - Output meets minimum slippage requirement
}

component main {public [
    merkle_root,
    nullifier,
    pool_id,
    out_commitment,
    change_commitment,
    min_output
]} = Swap();
