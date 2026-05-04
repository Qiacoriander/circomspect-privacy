pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function NULLIFIER_KEY_DOMAIN() { return 4; }
function VOTE_NULLIFIER_DOMAIN() { return 0x10; }
function VOTE_COMMITMENT_DOMAIN() { return 0x11; }

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

// Compute vote nullifier: Poseidon(VOTE_NULLIFIER_DOMAIN, nullifier_key, ballot_id)
template VoteNullifier() {
    signal input nullifier_key;
    signal input ballot_id;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== VOTE_NULLIFIER_DOMAIN();
    hasher.inputs[1] <== nullifier_key;
    hasher.inputs[2] <== ballot_id;
    out <== hasher.out;
}

// Compute vote commitment nullifier: Poseidon(VOTE_COMMITMENT_DOMAIN, nullifier_key, vote_commitment)
// Used to invalidate old vote commitment when changing vote
template VoteCommitmentNullifier() {
    signal input nullifier_key;
    signal input vote_commitment;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== VOTE_COMMITMENT_DOMAIN();
    hasher.inputs[1] <== nullifier_key;
    hasher.inputs[2] <== vote_commitment;
    out <== hasher.out;
}

// Compute vote commitment: Poseidon(ballot_id, vote_nullifier, pubkey, vote_choice, weight, randomness)
template VoteCommitment() {
    signal input ballot_id;
    signal input vote_nullifier;
    signal input pubkey;
    signal input vote_choice;
    signal input weight;
    signal input randomness;
    signal output out;

    // Two-stage hash to fit within Poseidon input limits
    component hasher1 = Poseidon(4);
    hasher1.inputs[0] <== 0x11;  // VOTE_COMMITMENT_DOMAIN for commitment hash
    hasher1.inputs[1] <== ballot_id;
    hasher1.inputs[2] <== vote_nullifier;
    hasher1.inputs[3] <== pubkey;

    component hasher2 = Poseidon(4);
    hasher2.inputs[0] <== hasher1.out;
    hasher2.inputs[1] <== vote_choice;
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
// Change Vote Snapshot Circuit - Atomic Vote Change
// ============================================================================
//
// Atomically:
// 1. Proves ownership of OLD vote_commitment
// 2. Nullifies old vote_commitment
// 3. Creates NEW vote_commitment with different vote_choice
//
// The vote_nullifier stays the same (ONE per user per ballot)
// Only vote_choice and randomness can change
// Weight stays the same (derived from same attestation)
//
// For Public mode: old_vote_choice and new_vote_choice are public
// For Encrypted modes: both are private

template ChangeVoteSnapshot() {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input vote_nullifier;               // Same for old and new (proves same user)
    signal input old_vote_commitment;
    signal input old_vote_commitment_nullifier;
    signal input new_vote_commitment;
    signal input weight;                       // Same for old and new (from same attestation)

    // For PUBLIC reveal mode only
    signal input old_vote_choice;              // Public in public mode
    signal input new_vote_choice;              // Public in public mode
    signal input is_public_mode;               // 1 if public, 0 if encrypted

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // User key derivation
    signal input spending_key;
    signal input pubkey;

    // Old vote details
    signal input old_randomness;
    signal input private_old_vote_choice;      // Used in encrypted mode

    // New vote details
    signal input new_randomness;
    signal input private_new_vote_choice;      // Used in encrypted mode

    // ========================================================================
    // 1. Derive Nullifier Key
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== spending_key;

    // ========================================================================
    // 2. Verify Vote Nullifier (proves same user)
    // ========================================================================
    component computed_vote_nullifier = VoteNullifier();
    computed_vote_nullifier.nullifier_key <== nk.out;
    computed_vote_nullifier.ballot_id <== ballot_id;

    vote_nullifier === computed_vote_nullifier.out;

    // ========================================================================
    // 3. Determine Effective Vote Choices
    // ========================================================================
    // Use intermediate signals to avoid non-quadratic constraints
    signal old_choice_public;
    old_choice_public <== is_public_mode * old_vote_choice;
    signal old_choice_private;
    old_choice_private <== (1 - is_public_mode) * private_old_vote_choice;
    signal effective_old_vote_choice;
    effective_old_vote_choice <== old_choice_public + old_choice_private;

    signal new_choice_public;
    new_choice_public <== is_public_mode * new_vote_choice;
    signal new_choice_private;
    new_choice_private <== (1 - is_public_mode) * private_new_vote_choice;
    signal effective_new_vote_choice;
    effective_new_vote_choice <== new_choice_public + new_choice_private;

    // ========================================================================
    // 4. Verify OLD Vote Commitment
    // ========================================================================
    component computed_old_commitment = VoteCommitment();
    computed_old_commitment.ballot_id <== ballot_id;
    computed_old_commitment.vote_nullifier <== vote_nullifier;
    computed_old_commitment.pubkey <== pubkey;
    computed_old_commitment.vote_choice <== effective_old_vote_choice;
    computed_old_commitment.weight <== weight;
    computed_old_commitment.randomness <== old_randomness;

    old_vote_commitment === computed_old_commitment.out;

    // ========================================================================
    // 5. Verify OLD Vote Commitment Nullifier
    // ========================================================================
    component computed_old_nullifier = VoteCommitmentNullifier();
    computed_old_nullifier.nullifier_key <== nk.out;
    computed_old_nullifier.vote_commitment <== old_vote_commitment;

    old_vote_commitment_nullifier === computed_old_nullifier.out;

    // ========================================================================
    // 6. Verify NEW Vote Commitment
    // ========================================================================
    component computed_new_commitment = VoteCommitment();
    computed_new_commitment.ballot_id <== ballot_id;
    computed_new_commitment.vote_nullifier <== vote_nullifier;
    computed_new_commitment.pubkey <== pubkey;
    computed_new_commitment.vote_choice <== effective_new_vote_choice;
    computed_new_commitment.weight <== weight;
    computed_new_commitment.randomness <== new_randomness;

    new_vote_commitment === computed_new_commitment.out;

    // ========================================================================
    // 7. Range Checks
    // ========================================================================
    component range_weight = RangeCheck64();
    range_weight.in <== weight;

    // ========================================================================
    // 8. Binary Constraints
    // ========================================================================
    is_public_mode * (1 - is_public_mode) === 0;

    // ========================================================================
    // 9. Ensure Vote Actually Changed (optional optimization)
    // ========================================================================
    // In production, we might want to enforce that old_vote_choice != new_vote_choice
    // For flexibility, we allow same vote (e.g., user might just want new randomness)
}

component main {public [
    ballot_id,
    vote_nullifier,
    old_vote_commitment,
    old_vote_commitment_nullifier,
    new_vote_commitment,
    weight,
    old_vote_choice,
    new_vote_choice,
    is_public_mode
]} = ChangeVoteSnapshot();
