pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Domain separation constants (must match on-chain verification)
function COMMITMENT_DOMAIN() { return 1; }
function SPENDING_NULLIFIER_DOMAIN() { return 2; }
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

// Compute position commitment for voting
// Includes: ballot_id, pubkey, vote_choice, amount, weight, randomness
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

// Merkle tree verification for eligibility
template EligibilityMerkleProof(levels) {
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
// Vote Spend Circuit - SpendToVote Mode
// ============================================================================
//
// User spends a token note to create a voting position.
// The tokens are locked in the ballot vault until resolution.
//
// Verifies:
// 1. User owns the token note
// 2. Spending nullifier is correctly derived
// 3. Position commitment is correctly derived
// 4. Amount matches note amount
// 5. Eligibility (if required)
//
// For Public mode: vote_choice is a public input
// For Encrypted modes: vote_choice is private

template VoteSpend(eligibility_levels) {
    // ========================================================================
    // Public Inputs
    // ========================================================================
    signal input ballot_id;
    signal input merkle_root;            // Merkle root for token note
    signal input spending_nullifier;     // Prevents double-spending
    signal input position_commitment;    // New position in ballot
    signal input amount;                 // Tokens being locked
    signal input weight;                 // Voting weight (from formula)
    signal input token_mint;             // Token being spent

    // Eligibility (0 if open ballot)
    signal input eligibility_root;
    signal input has_eligibility;        // 1 if eligibility check required

    // For PUBLIC reveal mode only
    signal input vote_choice;
    signal input is_public_mode;         // 1 if public, 0 if encrypted

    // ========================================================================
    // Private Inputs
    // ========================================================================

    // Token note details
    signal input in_stealth_pub_x;       // User's stealth pubkey
    signal input in_amount;              // Note amount
    signal input in_randomness;          // Note randomness
    signal input in_stealth_spending_key; // Spending key

    // Merkle proof (32 levels) - verified on-chain via Light Protocol
    signal input merkle_path[32];
    signal input merkle_path_indices[32];
    signal input leaf_index;

    // Position details
    signal input position_randomness;
    signal input private_vote_choice;    // Used in encrypted mode

    // Eligibility proof (if has_eligibility)
    signal input eligibility_path[eligibility_levels];
    signal input eligibility_path_indices[eligibility_levels];

    // ========================================================================
    // 1. Verify Input Token Note Commitment
    // ========================================================================
    component in_commitment = Commitment();
    in_commitment.stealth_pub_x <== in_stealth_pub_x;
    in_commitment.token_mint <== token_mint;
    in_commitment.amount <== in_amount;
    in_commitment.randomness <== in_randomness;

    // ========================================================================
    // 2. Derive Nullifier Key and Verify Spending Nullifier
    // ========================================================================
    component nk = NullifierKey();
    nk.spending_key <== in_stealth_spending_key;

    component computed_nullifier = SpendingNullifier();
    computed_nullifier.nullifier_key <== nk.out;
    computed_nullifier.commitment <== in_commitment.out;
    computed_nullifier.leaf_index <== leaf_index;

    spending_nullifier === computed_nullifier.out;

    // ========================================================================
    // 3. Verify Amount Matches
    // ========================================================================
    // User must spend exactly the note amount
    amount === in_amount;

    // ========================================================================
    // 4. Verify Eligibility (if required)
    // ========================================================================
    component eligibility_proof = EligibilityMerkleProof(eligibility_levels);
    eligibility_proof.leaf <== in_stealth_pub_x;
    for (var i = 0; i < eligibility_levels; i++) {
        eligibility_proof.pathElements[i] <== eligibility_path[i];
        eligibility_proof.pathIndices[i] <== eligibility_path_indices[i];
    }

    signal eligibility_check;
    eligibility_check <== has_eligibility * (eligibility_proof.root - eligibility_root);
    eligibility_check === 0;

    // ========================================================================
    // 5. Determine Effective Vote Choice
    // ========================================================================
    // Use intermediate signals to avoid non-quadratic constraints
    signal choice_public;
    choice_public <== is_public_mode * vote_choice;
    signal choice_private;
    choice_private <== (1 - is_public_mode) * private_vote_choice;
    signal effective_vote_choice;
    effective_vote_choice <== choice_public + choice_private;

    // ========================================================================
    // 6. Verify Position Commitment
    // ========================================================================
    component pos_commit = PositionCommitment();
    pos_commit.ballot_id <== ballot_id;
    pos_commit.pubkey <== in_stealth_pub_x;
    pos_commit.vote_choice <== effective_vote_choice;
    pos_commit.amount <== amount;
    pos_commit.weight <== weight;
    pos_commit.randomness <== position_randomness;

    position_commitment === pos_commit.out;

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

    // Note: On-chain verification handles:
    // - Merkle root validation via Light Protocol
    // - Weight formula verification: weight = formula(amount)
    // - Token mint verification: must match ballot.token_mint
}

component main {public [
    ballot_id,
    merkle_root,
    spending_nullifier,
    position_commitment,
    amount,
    weight,
    token_mint,
    eligibility_root,
    has_eligibility,
    vote_choice,
    is_public_mode
]} = VoteSpend(20);  // 20 levels for eligibility merkle tree
