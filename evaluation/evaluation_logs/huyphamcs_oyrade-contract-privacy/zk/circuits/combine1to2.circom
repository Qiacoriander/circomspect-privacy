// Combine 1->2 circuit for Solnado.
// Public outputs (match on-chain verify_one_null_two_leaves):
//   n1      : nullifier of spent note
//   leaf1   : first output leaf
//   leaf2   : second output leaf
//   root    : Merkle root of the input note tree
//
// On-chain, public_inputs are packed as:
//   [0..32)   -> n1
//   [32..64)  -> leaf1
//   [64..96)  -> leaf2
//   [96..128) -> root

pragma circom 2.1.4;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";

template Combine1To2(depth) {
    // PUBLIC SIGNALS
    signal output n1;
    signal output leaf1;
    signal output leaf2;
    signal output root;

    // PRIVATE INPUT NOTE (spent)
    signal input inAmount;
    signal input inNullifier;
    signal input inAssetId; // 0 for SOL

    // PRIVATE OUTPUT NOTES (created)
    signal input outAmount1;
    signal input outNullifier1;
    signal input outAssetId1;

    signal input outAmount2;
    signal input outNullifier2;
    signal input outAssetId2;

    // Merkle path for input note
    signal input pathElements[depth];
    signal input pathIndex[depth];

    // --- Recompute input leaf ---
    component hIn = Poseidon3();
    hIn.in[0] <== inAmount;
    hIn.in[1] <== inNullifier;
    hIn.in[2] <== inAssetId;

    signal inLeaf;
    inLeaf <== hIn.out;

    // --- Enforce membership of input leaf ---
    component merkle = MerkleMembership(depth);
    merkle.leaf <== inLeaf;

    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndex[i] <== pathIndex[i];
    }

    root <== merkle.root;

    // --- Recompute output leaves ---
    component hOut1 = Poseidon3();
    hOut1.in[0] <== outAmount1;
    hOut1.in[1] <== outNullifier1;
    hOut1.in[2] <== outAssetId1;

    component hOut2 = Poseidon3();
    hOut2.in[0] <== outAmount2;
    hOut2.in[1] <== outNullifier2;
    hOut2.in[2] <== outAssetId2;

    leaf1 <== hOut1.out;
    leaf2 <== hOut2.out;
    n1 <== inNullifier;

    // --- Value conservation & asset equality constraints ---
    // inAmount = outAmount1 + outAmount2  (no fee modeled inside notes)
    // All assets must match.
    inAmount === outAmount1 + outAmount2;

    inAssetId === outAssetId1;
    inAssetId === outAssetId2;
}

component main = Combine1To2(30);

