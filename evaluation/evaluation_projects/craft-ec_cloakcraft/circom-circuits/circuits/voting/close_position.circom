pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function NULLIFIER_KEY_DOMAIN() { return 4; }
function POSITION_DOMAIN() { return 0x13; }

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
// Close Position Circuit - Exit Voting Position
// ============================================================================
//
// Allows user to close their voting position during the voting period.
// Used for:
// 1. Changing vote (close + re-vote with different choice)
// 2. Updating weight (close + consolidate + re-vote)
// 3. Exiting early (close + unshield)
//
// The original token note is CONSUMED forever (spending nullifier was created).
// Closing creates a NEW token commitment (fresh randomness, same amount).
//
// Verifies:
// 1. User owns the position
// 2. Position nullifier is correctly derived
// 3. New token commitment is valid
// 4. Amount in new token matches position amount
//
// For Public mode: vote_choice is public (for tally decrement)
// For Encrypted modes: vote_choice is private

template ClosePosition() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input position_commitment;    // Position being closed
    signal input position_nullifier;     // Prevents double-close
    signal input token_commitment;       // NEW token commitment (fresh)
    signal input amount;                 // Amount being returned
    signal input weight;                 // Weight being removed from tally
    signal input token_mint;             // Token type (verified on-chain)

    // For PUBLIC reveal mode only (for tally decrement)
    signal input vote_choice;
    signal input is_public_mode;         // 1 if public, 0 if encrypted

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // User key
    signal input spending_key;
    signal input pubkey;

    // Position details
    signal input position_randomness;
    signal input private_vote_choice;    // Used in encrypted mode

    // New token commitment details
    signal input token_randomness;       // Fresh randomness for new note

    // ========================================================================
    // 1. Derive Nullifier Key
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== spending_key;

    // ========================================================================
    // 2. Determine Effective Vote Choice
    // ========================================================================
    // Use intermediate signals to avoid non-quadratic constraints
    signal choice_public;
    choice_public <== is_public_mode * vote_choice;
    signal choice_private;
    choice_private <== (1 - is_public_mode) * private_vote_choice;
    signal effective_vote_choice;
    effective_vote_choice <== choice_public + choice_private;

    // ========================================================================
    // 3. Verify Position Commitment
    // ========================================================================
    component pos_commit = PositionCommitment();
    pos_commit.ballot_id <== ballot_id;
    pos_commit.pubkey <== pubkey;
    pos_commit.vote_choice <== effective_vote_choice;
    pos_commit.amount <== amount;
    pos_commit.weight <== weight;
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
    // 5. Verify New Token Commitment
    // ========================================================================
    // Creates a FRESH token note with the same amount
    component new_token = Commitment();
    new_token.stealth_pub_x <== pubkey;
    new_token.token_mint <== token_mint;
    new_token.amount <== amount;        // Same amount as position
    new_token.randomness <== token_randomness;

    token_commitment === new_token.out;

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

    // Note: On-chain verification handles:
    // - Position exists (verified via Light Protocol)
    // - Ballot is still active (voting period)
    // - Token mint matches ballot.token_mint
    // - Tally decrement (using vote_choice for public mode)
}

component main {public [
    ballot_id,
    position_commitment,
    position_nullifier,
    token_commitment,
    amount,
    weight,
    token_mint,
    vote_choice,
    is_public_mode
]} = ClosePosition();
