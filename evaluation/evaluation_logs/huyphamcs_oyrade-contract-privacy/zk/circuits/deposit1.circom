pragma circom 2.2.3;
// Single-leaf deposit circuit for Solnado.
// Public outputs (match on-chain verify_single_deposit_proof):
// - amount32: Fr element encoding 8-byte BE amount in the low 64 bits
// - leaf1: Poseidon(amount32, nullifier, assetId)
// The off-chain client packs public_inputs as:
// [0..8)  -> amount_be8
// [8..40) -> leaf1 bytes
// [40..72)-> unused (but inspected in lib.rs to distinguish 1 vs 2 leaves)

include "../lib/poseidon.circom";
include "../lib/merkle.circom";

template Deposit1(depth) {
    // PARAMETERS
    // ----------
    // depth: Merkle tree depth (number of levels) used for membership proof.

    // PUBLIC SIGNALS
    signal output amount32;   // field element representation of amount
    signal output leaf1;      // commitment leaf
    signal output root;       // Merkle root (deep root expected by on-chain)

    // PRIVATE SIGNALS
    signal input amount;      // u64 amount as field element (0 <= amount < 2^64)
    signal input nullifier;   // 32-byte field element
    signal input assetId;     // 32-byte field element (0 for SOL)

    // Merkle path witness
    signal input pathElements[depth]; // sibling hashes
    signal input pathIndex[depth];    // 0/1 at each level

    // Compute Poseidon leaf = H(amount32, nullifier, assetId).
    component poseidon3 = Poseidon3();
    poseidon3.in[0] <== amount;
    poseidon3.in[1] <== nullifier;
    poseidon3.in[2] <== assetId;

    leaf1 <== poseidon3.out;
    amount32 <== amount;

    // Constrain Merkle membership of leaf1 in tree with root.
    component merkle = MerkleMembership(depth);
    merkle.leaf <== leaf1;

    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndex[i] <== pathIndex[i];
    }

    root <== merkle.root;
}

component main = Deposit1(30);

