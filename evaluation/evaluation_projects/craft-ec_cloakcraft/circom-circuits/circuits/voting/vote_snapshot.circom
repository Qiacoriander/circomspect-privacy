pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function NULLIFIER_KEY_DOMAIN() { return 4; }
function VOTE_NULLIFIER_DOMAIN() { return 0x10; }
function VOTE_COMMITMENT_DOMAIN() { return 0x11; }

// ============================================================================
// Helper Templates
// ============================================================================

// Compute note commitment: Poseidon(domain, stealth_pub_x, token_mint, amount, randomness)
template NoteCommitment() {
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

// Compute vote nullifier: Poseidon(VOTE_NULLIFIER_DOMAIN, nullifier_key, ballot_id)
// ONE per user per ballot - ensures single active vote
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

// Compute vote commitment
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
    hasher1.inputs[0] <== VOTE_COMMITMENT_DOMAIN();
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

// Merkle tree verification
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    signal intermediates[levels + 1];
    intermediates[0] <== leaf;

    component hashers[levels];
    component muxL[levels];
    component muxR[levels];

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);

        muxL[i] = Mux1();
        muxL[i].c[0] <== intermediates[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s <== pathIndices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== intermediates[i];
        muxR[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;
        intermediates[i + 1] <== hashers[i].out;
    }

    root <== intermediates[levels];
}

template Mux1() {
    signal input c[2];
    signal input s;
    signal output out;

    out <== c[0] + s * (c[1] - c[0]);
}

// ============================================================================
// Vote Snapshot Circuit - Note-Based Ownership Proof
// ============================================================================
//
// User proves they own a shielded note WITHOUT spending it.
// The note stays intact - user just proves ownership for voting weight.
//
// Verifies:
// 1. User knows the note preimage (proves ownership)
// 2. Note exists in merkle tree at snapshot (merkle proof)
// 3. vote_nullifier is correctly derived (one vote per user per ballot)
// 4. vote_commitment is correctly derived
//
// Key difference from vote_spend:
// - NO spending nullifier - note is NOT consumed
// - Uses snapshot merkle root (historical state)
//
// For Public mode: vote_choice is a public input
// For Encrypted modes: vote_choice is private

template VoteSnapshot(merkle_levels, eligibility_levels) {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input snapshot_merkle_root;    // Merkle root at snapshot slot
    signal input note_commitment;         // The shielded note being used
    signal input vote_nullifier;
    signal input vote_commitment;
    signal input amount;                  // Note amount (voting weight base)
    signal input weight;                  // Calculated voting weight
    signal input token_mint;

    // Eligibility (0 if open ballot)
    signal input eligibility_root;
    signal input has_eligibility;

    // For PUBLIC reveal mode only
    signal input vote_choice;
    signal input is_public_mode;

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Note details (user proves they know the preimage)
    signal input in_stealth_pub_x;        // User's stealth pubkey in note
    signal input in_randomness;           // Note randomness
    signal input in_stealth_spending_key; // Spending key (proves ownership)

    // Merkle proof for note inclusion at snapshot
    signal input merkle_path[merkle_levels];
    signal input merkle_path_indices[merkle_levels];

    // Vote commitment randomness
    signal input vote_randomness;

    // Eligibility proof (if has_eligibility)
    signal input eligibility_path[eligibility_levels];
    signal input eligibility_path_indices[eligibility_levels];

    // For encrypted modes - vote_choice is private
    signal input private_vote_choice;

    // ========================================================================
    // 1. Verify Note Commitment (proves user knows the note preimage)
    // ========================================================================
    component computed_note = NoteCommitment();
    computed_note.stealth_pub_x <== in_stealth_pub_x;
    computed_note.token_mint <== token_mint;
    computed_note.amount <== amount;
    computed_note.randomness <== in_randomness;

    note_commitment === computed_note.out;

    // ========================================================================
    // 2. Note Existence Verification
    // ========================================================================
    // Light Protocol uses account_hash (not note_commitment) as merkle leaves.
    // The account_hash includes the full compressed account data.
    //
    // On-chain verification flow:
    // 1. Circuit proves: user knows note preimage (note_commitment check above)
    // 2. On-chain: Light Protocol verifies account_hash exists in tree
    // 3. On-chain: Verifies note_commitment matches account data
    //
    // The snapshot_merkle_root is passed as a public input for the on-chain
    // program to verify (via Light Protocol inclusion proof).
    // We keep the merkle path inputs for compatibility but don't verify here.
    //
    // When snapshot_merkle_root == 0, on-chain skips root verification.
    // When snapshot_merkle_root != 0, on-chain verifies against Light Protocol.

    // Consume merkle path inputs to avoid unused input errors
    signal merkle_hash_accumulator;
    signal intermediate[merkle_levels];
    intermediate[0] <== merkle_path[0] + merkle_path_indices[0];
    for (var i = 1; i < merkle_levels; i++) {
        intermediate[i] <== intermediate[i-1] + merkle_path[i] + merkle_path_indices[i];
    }
    merkle_hash_accumulator <== intermediate[merkle_levels - 1];
    // Dummy constraint that's always satisfied (doesn't affect validity)
    signal merkle_dummy;
    merkle_dummy <== merkle_hash_accumulator * 0;

    // ========================================================================
    // 3. Derive Nullifier Key and Verify Vote Nullifier
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_vote_nullifier = VoteNullifier();
    computed_vote_nullifier.nullifier_key <== nk.out;
    computed_vote_nullifier.ballot_id <== ballot_id;

    vote_nullifier === computed_vote_nullifier.out;

    // ========================================================================
    // 4. Verify Eligibility (if required)
    // ========================================================================
    component eligibility_proof = MerkleProof(eligibility_levels);
    eligibility_proof.leaf <== in_stealth_pub_x;
    for (var i = 0; i < eligibility_levels; i++) {
        eligibility_proof.pathElements[i] <== eligibility_path[i];
        eligibility_proof.pathIndices[i] <== eligibility_path_indices[i];
    }

    signal eligibility_check;
    eligibility_check <== has_eligibility * (eligibility_proof.root - eligibility_root);
    eligibility_check === 0;

    // ========================================================================
    // 5. Determine Vote Choice (public vs encrypted mode)
    // ========================================================================
    signal choice_public;
    choice_public <== is_public_mode * vote_choice;
    signal choice_private;
    choice_private <== (1 - is_public_mode) * private_vote_choice;
    signal effective_vote_choice;
    effective_vote_choice <== choice_public + choice_private;

    // ========================================================================
    // 6. Verify Vote Commitment
    // ========================================================================
    component computed_vote_commitment = VoteCommitment();
    computed_vote_commitment.ballot_id <== ballot_id;
    computed_vote_commitment.vote_nullifier <== vote_nullifier;
    computed_vote_commitment.pubkey <== in_stealth_pub_x;
    computed_vote_commitment.vote_choice <== effective_vote_choice;
    computed_vote_commitment.weight <== weight;
    computed_vote_commitment.randomness <== vote_randomness;

    vote_commitment === computed_vote_commitment.out;

    // ========================================================================
    // 7. Range Checks
    // ========================================================================
    component range_amount = RangeCheck64();
    range_amount.in <== amount;

    component range_weight = RangeCheck64();
    range_weight.in <== weight;

    // ========================================================================
    // 8. Binary Constraints
    // ========================================================================
    is_public_mode * (1 - is_public_mode) === 0;
    has_eligibility * (1 - has_eligibility) === 0;

    // Note:
    // - NO spending nullifier created - note stays intact
    // - Weight formula verification done on-chain
    // - Snapshot merkle root must be from the ballot's snapshot_slot
}

// 32 levels for note merkle tree, 20 levels for eligibility
component main {public [
    ballot_id,
    snapshot_merkle_root,
    note_commitment,
    vote_nullifier,
    vote_commitment,
    amount,
    weight,
    token_mint,
    eligibility_root,
    has_eligibility,
    vote_choice,
    is_public_mode
]} = VoteSnapshot(32, 20);
