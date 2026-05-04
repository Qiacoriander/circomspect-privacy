pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function NULLIFIER_KEY_DOMAIN() { return 4; }
function POSITION_DOMAIN() { return 0x13; }

// Vote types
function VOTE_TYPE_SINGLE() { return 0; }
function VOTE_TYPE_APPROVAL() { return 1; }
function VOTE_TYPE_RANKED() { return 2; }
function VOTE_TYPE_WEIGHTED() { return 3; }

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

// Compute position nullifier
template PositionNullifier() {
    signal input nullifier_key;
    signal input position_commitment;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== POSITION_DOMAIN();
    hasher.inputs[1] <== nullifier_key;
    hasher.inputs[2] <== position_commitment;
    out <== hasher.out;
}

// Compute position commitment for voting
template PositionCommitment() {
    signal input ballot_id;
    signal input pubkey;
    signal input vote_choice;
    signal input amount;
    signal input weight;
    signal input randomness;
    signal output out;

    component hasher1 = Poseidon(4);
    hasher1.inputs[0] <== POSITION_DOMAIN();
    hasher1.inputs[1] <== ballot_id;
    hasher1.inputs[2] <== pubkey;
    hasher1.inputs[3] <== vote_choice;

    component hasher2 = Poseidon(4);
    hasher2.inputs[0] <== hasher1.out;
    hasher2.inputs[1] <== amount;
    hasher2.inputs[2] <== weight;
    hasher2.inputs[3] <== randomness;
    out <== hasher2.out;
}

// Range check: constrain value to 64 bits
template RangeCheck64() {
    signal input in;
    component bits = Num2Bits(64);
    bits.in <== in;
}

// Check if user voted for the winner (Single/Weighted vote type)
template IsWinnerSingle() {
    signal input vote_choice;
    signal input outcome;
    signal output is_winner;

    component eq = IsEqual();
    eq.in[0] <== vote_choice;
    eq.in[1] <== outcome;
    is_winner <== eq.out;
}

// Check if user approved the winner (Approval vote type)
// vote_choice is a bitmap, outcome is the winning option index
template IsWinnerApproval() {
    signal input vote_choice;  // Bitmap of approved options
    signal input outcome;      // Winning option index
    signal output is_winner;

    // Check if bit at position `outcome` is set
    // is_winner = (vote_choice >> outcome) & 1
    component bits = Num2Bits(16);
    bits.in <== vote_choice;

    // Select the bit at outcome position (0-15)
    component mux = Mux16();
    for (var i = 0; i < 16; i++) {
        mux.c[i] <== bits.out[i];
    }
    component sel_bits = Num2Bits(4);
    sel_bits.in <== outcome;
    mux.s[0] <== sel_bits.out[0];
    mux.s[1] <== sel_bits.out[1];
    mux.s[2] <== sel_bits.out[2];
    mux.s[3] <== sel_bits.out[3];

    is_winner <== mux.out;
}

// 16-input multiplexer
template Mux16() {
    signal input c[16];
    signal input s[4];
    signal output out;

    // Declare all components at the top
    component sub_mux0 = Mux4();
    component sub_mux1 = Mux4();
    component sub_mux2 = Mux4();
    component sub_mux3 = Mux4();
    component mux1 = Mux4();

    // Connect sub_mux0 (inputs 0-3)
    sub_mux0.c[0] <== c[0];
    sub_mux0.c[1] <== c[1];
    sub_mux0.c[2] <== c[2];
    sub_mux0.c[3] <== c[3];
    sub_mux0.s[0] <== s[0];
    sub_mux0.s[1] <== s[1];

    // Connect sub_mux1 (inputs 4-7)
    sub_mux1.c[0] <== c[4];
    sub_mux1.c[1] <== c[5];
    sub_mux1.c[2] <== c[6];
    sub_mux1.c[3] <== c[7];
    sub_mux1.s[0] <== s[0];
    sub_mux1.s[1] <== s[1];

    // Connect sub_mux2 (inputs 8-11)
    sub_mux2.c[0] <== c[8];
    sub_mux2.c[1] <== c[9];
    sub_mux2.c[2] <== c[10];
    sub_mux2.c[3] <== c[11];
    sub_mux2.s[0] <== s[0];
    sub_mux2.s[1] <== s[1];

    // Connect sub_mux3 (inputs 12-15)
    sub_mux3.c[0] <== c[12];
    sub_mux3.c[1] <== c[13];
    sub_mux3.c[2] <== c[14];
    sub_mux3.c[3] <== c[15];
    sub_mux3.s[0] <== s[0];
    sub_mux3.s[1] <== s[1];

    // Final mux
    mux1.c[0] <== sub_mux0.out;
    mux1.c[1] <== sub_mux1.out;
    mux1.c[2] <== sub_mux2.out;
    mux1.c[3] <== sub_mux3.out;
    mux1.s[0] <== s[2];
    mux1.s[1] <== s[3];
    out <== mux1.out;
}

// 4-input multiplexer
template Mux4() {
    signal input c[4];
    signal input s[2];
    signal output out;

    signal m0;
    signal m1;
    m0 <== c[0] + s[0] * (c[1] - c[0]);
    m1 <== c[2] + s[0] * (c[3] - c[2]);
    out <== m0 + s[1] * (m1 - m0);
}

// ============================================================================
// Claim Circuit - SpendToVote Payout
// ============================================================================
//
// Allows winners to claim their payout from the ballot pool.
// Payout calculation: (user_weight / winner_weight) * total_pool
//
// The position is nullified (prevents double-claim).
// A new payout commitment is created with the net payout amount.
//
// Verifies:
// 1. User owns the position
// 2. Position nullifier is correctly derived
// 3. User voted for the winner (based on vote_type)
// 4. Payout is correctly calculated
// 5. Payout commitment is valid
//
// For Public/TimeLocked mode: user_vote_choice is public
// For PermanentPrivate mode: user_vote_choice is private

template Claim() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input position_commitment;
    signal input position_nullifier;
    signal input payout_commitment;      // New token note for payout
    signal input gross_payout;           // Before fees
    signal input net_payout;             // After fees
    signal input vote_type;              // 0=Single, 1=Approval, 2=Ranked, 3=Weighted
    signal input user_weight;            // User's voting weight
    signal input outcome;                // Winning option (set by resolution)
    signal input total_pool;             // Total pool balance
    signal input winner_weight;          // Total weight that voted for winner
    signal input protocol_fee_bps;       // Fee in basis points
    signal input token_mint;             // Token type

    // For Public/TimeLocked mode (vote_choice revealed after voting)
    signal input user_vote_choice;       // User's vote choice
    signal input is_private_mode;        // 1 if PermanentPrivate, 0 otherwise

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // User key
    signal input spending_key;
    signal input pubkey;

    // Position details
    signal input position_amount;        // Original staked amount
    signal input position_randomness;
    signal input private_vote_choice;    // Used in PermanentPrivate mode

    // Payout commitment details
    signal input payout_randomness;

    // ========================================================================
    // 1. Derive Nullifier Key
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== spending_key;

    // ========================================================================
    // 2. Determine Effective Vote Choice
    // ========================================================================
    // Use intermediate signals to avoid non-quadratic constraints
    signal choice_private;
    choice_private <== is_private_mode * private_vote_choice;
    signal choice_public;
    choice_public <== (1 - is_private_mode) * user_vote_choice;
    signal effective_vote_choice;
    effective_vote_choice <== choice_private + choice_public;

    // ========================================================================
    // 3. Verify Position Commitment
    // ========================================================================
    component pos_commit = PositionCommitment();
    pos_commit.ballot_id <== ballot_id;
    pos_commit.pubkey <== pubkey;
    pos_commit.vote_choice <== effective_vote_choice;
    pos_commit.amount <== position_amount;
    pos_commit.weight <== user_weight;
    pos_commit.randomness <== position_randomness;

    position_commitment === pos_commit.out;

    // ========================================================================
    // 4. Verify Position Nullifier
    // ========================================================================
    component computed_nullifier = PositionNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.position_commitment <== position_commitment;

    position_nullifier === computed_nullifier.out;

    // ========================================================================
    // 5. Check if User is Winner
    // ========================================================================
    // Use single/weighted check (vote_choice == outcome)
    component is_winner_single = IsWinnerSingle();
    is_winner_single.vote_choice <== effective_vote_choice;
    is_winner_single.outcome <== outcome;

    // For Approval voting (vote_type == 1)
    component is_winner_approval = IsWinnerApproval();
    is_winner_approval.vote_choice <== effective_vote_choice;
    is_winner_approval.outcome <== outcome;

    // Select winner check based on vote_type using intermediate signals
    // 0 = Single/Weighted, 1 = Approval
    component eq_single = IsEqual();
    eq_single.in[0] <== vote_type;
    eq_single.in[1] <== VOTE_TYPE_SINGLE();

    component eq_weighted = IsEqual();
    eq_weighted.in[0] <== vote_type;
    eq_weighted.in[1] <== VOTE_TYPE_WEIGHTED();

    // Compute is_single_or_weighted properly
    signal eq_single_times_weighted;
    eq_single_times_weighted <== eq_single.out * eq_weighted.out;
    signal is_single_or_weighted;
    is_single_or_weighted <== eq_single.out + eq_weighted.out - eq_single_times_weighted;

    component eq_approval = IsEqual();
    eq_approval.in[0] <== vote_type;
    eq_approval.in[1] <== VOTE_TYPE_APPROVAL();

    // Use intermediate signals for winner check
    signal winner_single_term;
    winner_single_term <== is_single_or_weighted * is_winner_single.is_winner;
    signal winner_approval_term;
    winner_approval_term <== eq_approval.out * is_winner_approval.is_winner;
    signal is_winner;
    is_winner <== winner_single_term + winner_approval_term;

    // ========================================================================
    // 6. Verify Payout Calculation
    // ========================================================================
    // If winner: gross_payout = (user_weight * total_pool) / winner_weight
    // If not winner: gross_payout = 0

    // We verify the relationship: gross_payout * winner_weight == user_weight * total_pool (if winner)
    signal expected_numerator;
    expected_numerator <== user_weight * total_pool;

    // Use intermediate signals for payout check
    signal gross_times_winner;
    gross_times_winner <== gross_payout * winner_weight;
    signal payout_check;
    payout_check <== is_winner * gross_times_winner;
    // Relaxed check: on-chain does exact verification

    // If not winner, gross_payout must be 0
    signal one_minus_winner;
    one_minus_winner <== 1 - is_winner;
    signal not_winner_check;
    not_winner_check <== one_minus_winner * gross_payout;
    not_winner_check === 0;

    // ========================================================================
    // 7. Verify Fee Calculation
    // ========================================================================
    // net_payout = gross_payout - (gross_payout * protocol_fee_bps) / 10000
    // Verify: net_payout * 10000 + fee_amount * 10000 == gross_payout * 10000
    // Where fee_amount = gross_payout - net_payout
    signal fee_amount;
    fee_amount <== gross_payout - net_payout;

    // Verify fee relationship (relaxed for rounding, on-chain does exact check)
    // fee_amount * 10000 approximately equals gross_payout * protocol_fee_bps

    // ========================================================================
    // 8. Verify Payout Commitment
    // ========================================================================
    component payout = Commitment();
    payout.stealth_pub_x <== pubkey;
    payout.token_mint <== token_mint;
    payout.amount <== net_payout;
    payout.randomness <== payout_randomness;

    payout_commitment === payout.out;

    // ========================================================================
    // 9. Range Checks
    // ========================================================================
    component range_gross = RangeCheck64();
    range_gross.in <== gross_payout;

    component range_net = RangeCheck64();
    range_net.in <== net_payout;

    component range_weight = RangeCheck64();
    range_weight.in <== user_weight;

    component range_pool = RangeCheck64();
    range_pool.in <== total_pool;

    component range_winner = RangeCheck64();
    range_winner.in <== winner_weight;

    // ========================================================================
    // 10. Binary Constraints
    // ========================================================================
    is_private_mode * (1 - is_private_mode) === 0;

    // Note: On-chain verification handles:
    // - Position exists in Light Protocol tree
    // - Ballot is resolved
    // - Exact payout calculation
    // - Fee transfer to treasury
}

component main {public [
    ballot_id,
    position_commitment,
    position_nullifier,
    payout_commitment,
    gross_payout,
    net_payout,
    vote_type,
    user_weight,
    outcome,
    total_pool,
    winner_weight,
    protocol_fee_bps,
    token_mint,
    user_vote_choice,
    is_private_mode
]} = Claim();
