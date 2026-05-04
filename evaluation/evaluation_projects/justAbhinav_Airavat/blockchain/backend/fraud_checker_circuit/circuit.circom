pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// --- Helper: ConditionalSelector ---
template ConditionalSelector() {
    signal input selector; // Must be 0 or 1
    signal input input0;
    signal input input1;
    signal output selectedValue;
    selector * (selector - 1) === 0;
    signal sel_times_in1;
    signal one_minus_sel_times_in0;
    sel_times_in1 <== selector * input1;
    one_minus_sel_times_in0 <== (1 - selector) * input0;
    selectedValue <== sel_times_in1 + one_minus_sel_times_in0;
}

// --- Helper: PoseidonHash2 ---
template PoseidonHash2() {
    signal input in0;
    signal input in1;
    signal output out;
    component hasher = Poseidon(2);
    hasher.inputs[0] <== in0;
    hasher.inputs[1] <== in1;
    out <== hasher.out;
}

// --- MerkleProofInclusion ---
// Computes the Merkle root for a given leaf and path.
template MerkleProofInclusion(treeDepth) {
    signal input leaf;
    signal input pathElements[treeDepth];
    signal input pathIndices[treeDepth];
    signal output root;

    signal hash_chain[treeDepth + 1];
    hash_chain[0] <== leaf;

    component hashers[treeDepth];
    component muxLeft[treeDepth];
    component muxRight[treeDepth];

    for (var i = 0; i < treeDepth; i++) {
        hashers[i] = PoseidonHash2();
        muxLeft[i] = ConditionalSelector();
        muxLeft[i].selector <== pathIndices[i];
        muxLeft[i].input0 <== hash_chain[i];
        muxLeft[i].input1 <== pathElements[i];
        hashers[i].in0 <== muxLeft[i].selectedValue;

        muxRight[i] = ConditionalSelector();
        muxRight[i].selector <== pathIndices[i];
        muxRight[i].input0 <== pathElements[i];
        muxRight[i].input1 <== hash_chain[i];
        hashers[i].in1 <== muxRight[i].selectedValue;

        hash_chain[i + 1] <== hashers[i].out;
    }
    root <== hash_chain[treeDepth];
}

// --- FraudCheck ---
// Proves that userHash is NOT in the blacklist Merkle tree.
template FraudCheck(treeDepth) {
    // Public inputs
    signal input blacklistRoot;

    // Private inputs
    signal input userHash; // Poseidon hash of user identifier
    signal input pathElements[treeDepth];
    signal input pathIndices[treeDepth];

    // Compute the root for the given userHash and path
    component mp = MerkleProofInclusion(treeDepth);
    mp.leaf <== userHash;
    for (var i = 0; i < treeDepth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i] <== pathIndices[i];
    }

    // If computed root == blacklistRoot, user IS blacklisted
    component eq = IsEqual();
    eq.in[0] <== mp.root;
    eq.in[1] <== blacklistRoot;
    signal isBlacklisted;
    isBlacklisted <== eq.out;

    // Output: isClean = 1 - isBlacklisted
    signal output isClean;
    isClean <== 1 - isBlacklisted;
}

component main { public [blacklistRoot] } = FraudCheck(10);