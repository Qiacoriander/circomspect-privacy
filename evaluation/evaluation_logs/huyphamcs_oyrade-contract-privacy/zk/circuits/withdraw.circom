// Withdraw circuit for Solnado.
// Public outputs (match on-chain verify_withdraw_proof):
// - amount32: Fr element encoding 8-byte BE amount
// - assetId: asset identifier (0 for SOL)
// - nullifier: 32-byte field element
// - root: Merkle root of the note tree
//
// The off-chain client must pack public_inputs as:
//   [0..32)  -> nullifier bytes
//   [32..64) -> assetId bytes
//   [64..72) -> amount_be8
//   [72..104)-> root bytes

pragma circom 2.1.4;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";

template Withdraw(depth) {
    // PUBLIC SIGNALS (these will become Groth16 public inputs)
    signal output amount32;
    signal output assetId;
    signal output nullifier;
    signal output root;

    // PRIVATE SIGNALS
    signal input amount;      // u64 amount as field element
    signal input noteNullifier;
    signal input noteAssetId; // should be 0 for SOL

    // Merkle path witness
    signal input pathElements[depth];
    signal input pathIndex[depth];

    // Recompute leaf = Poseidon(amount, noteNullifier, noteAssetId)
    component poseidon3 = Poseidon3();
    poseidon3.in[0] <== amount;
    poseidon3.in[1] <== noteNullifier;
    poseidon3.in[2] <== noteAssetId;

    signal leaf;
    leaf <== poseidon3.out;

    amount32 <== amount;
    assetId <== noteAssetId;
    nullifier <== noteNullifier;

    // Enforce membership in tree with root
    component merkle = MerkleMembership(depth);
    merkle.leaf <== leaf;

    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndex[i] <== pathIndex[i];
    }

    root <== merkle.root;
}

component main = Withdraw(30);

