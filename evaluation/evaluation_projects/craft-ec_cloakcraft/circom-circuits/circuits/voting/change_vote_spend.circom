pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function NULLIFIER_KEY_DOMAIN() { return 4; }
function POSITION_DOMAIN() { return 0x13; }

// ============================================================================
// Helper Templates
// ============================================================================

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

// Compute position nullifier: Poseidon(POSITION_DOMAIN, nullifier_key, position_commitment)
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

    // Two-stage hash to fit within Poseidon input limits
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

// ============================================================================
// Change Vote Spend Circuit - Change Vote for SpendToVote Mode
// ============================================================================
//
// Allows user to atomically change their vote in SpendToVote mode:
// - Nullifies old position commitment
// - Creates new position commitment with different vote choice
// - Same amount and weight (tokens don't move)
//
// Flow:
// Phase 0 (this proof): Verify ownership + compute commitments/nullifiers
// Phase 1: verify_commitment_exists for old_position
// Phase 2: create_nullifier_and_pending for old_position_nullifier
// Phase 3: execute_change_vote_spend - Update tally (decrement old, increment new)
// Phase 4: create_commitment for new_position
// Phase 5: close_pending_operation
//
// For Public mode: vote choices are public (for tally updates)
// For Encrypted modes: vote choices are private

template ChangeVoteSpend() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input old_position_commitment;     // Position being changed
    signal input old_position_nullifier;      // Prevents double-spend
    signal input new_position_commitment;     // New position with different choice
    signal input amount;                      // Amount (unchanged)
    signal input weight;                      // Weight (unchanged)
    signal input token_mint;                  // Token type (verified on-chain)

    // For PUBLIC reveal mode only
    signal input old_vote_choice;
    signal input new_vote_choice;
    signal input is_public_mode;              // 1 if public, 0 if encrypted

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // User key
    signal input spending_key;
    signal input pubkey;

    // Old position details
    signal input old_position_randomness;
    signal input private_old_vote_choice;     // Used in encrypted mode

    // New position details
    signal input new_position_randomness;     // Fresh randomness for new position
    signal input private_new_vote_choice;     // Used in encrypted mode

    // ========================================================================
    // 1. Derive Nullifier Key
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== spending_key;

    // ========================================================================
    // 2. Determine Effective Vote Choices
    // ========================================================================
    // Old vote choice
    signal old_choice_public;
    old_choice_public <== is_public_mode * old_vote_choice;
    signal old_choice_private;
    old_choice_private <== (1 - is_public_mode) * private_old_vote_choice;
    signal effective_old_vote_choice;
    effective_old_vote_choice <== old_choice_public + old_choice_private;

    // New vote choice
    signal new_choice_public;
    new_choice_public <== is_public_mode * new_vote_choice;
    signal new_choice_private;
    new_choice_private <== (1 - is_public_mode) * private_new_vote_choice;
    signal effective_new_vote_choice;
    effective_new_vote_choice <== new_choice_public + new_choice_private;

    // ========================================================================
    // 3. Verify Old Position Commitment
    // ========================================================================
    component old_pos_commit = PositionCommitment();
    old_pos_commit.ballot_id <== ballot_id;
    old_pos_commit.pubkey <== pubkey;
    old_pos_commit.vote_choice <== effective_old_vote_choice;
    old_pos_commit.amount <== amount;
    old_pos_commit.weight <== weight;
    old_pos_commit.randomness <== old_position_randomness;

    old_position_commitment === old_pos_commit.out;

    // ========================================================================
    // 4. Verify Old Position Nullifier
    // ========================================================================
    component computed_nullifier = PositionNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.position_commitment <== old_position_commitment;

    old_position_nullifier === computed_nullifier.out;

    // ========================================================================
    // 5. Verify New Position Commitment
    // ========================================================================
    // Creates a new position with different vote choice, same amount/weight
    component new_pos_commit = PositionCommitment();
    new_pos_commit.ballot_id <== ballot_id;
    new_pos_commit.pubkey <== pubkey;
    new_pos_commit.vote_choice <== effective_new_vote_choice;
    new_pos_commit.amount <== amount;         // Same amount
    new_pos_commit.weight <== weight;         // Same weight
    new_pos_commit.randomness <== new_position_randomness;

    new_position_commitment === new_pos_commit.out;

    // ========================================================================
    // 6. Range Checks
    // ========================================================================
    component range_amount = RangeCheck64();
    range_amount.in <== amount;

    component range_weight = RangeCheck64();
    range_weight.in <== weight;

    // ========================================================================
    // 7. Binary Constraints
    // ========================================================================
    is_public_mode * (1 - is_public_mode) === 0;

    // ========================================================================
    // 8. Vote Choice Change Constraint (optional - can be same if just refreshing)
    // ========================================================================
    // No constraint on choices being different - user might just want to refresh randomness

    // Note: On-chain verification handles:
    // - Old position exists (verified via Light Protocol)
    // - Ballot is still active (voting period)
    // - Token mint matches ballot.token_mint
    // - Tally update (decrement old, increment new for public mode)
}

component main {public [
    ballot_id,
    old_position_commitment,
    old_position_nullifier,
    new_position_commitment,
    amount,
    weight,
    token_mint,
    old_vote_choice,
    new_vote_choice,
    is_public_mode
]} = ChangeVoteSpend();
