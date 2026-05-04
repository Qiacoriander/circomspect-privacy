pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";  // for comparator

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
// Computes Poseidon( in0, in1 ).
template PoseidonHash2() {
    signal input in0;
    signal input in1;
    signal output out;
    component hasher = Poseidon(2);
    hasher.inputs[0] <== in0;
    hasher.inputs[1] <== in1;
    out <== hasher.out;
}

// --- MerkleProof ---
template MerkleProof(treeDepth) {
    signal input userIndex;
    signal input authPath[treeDepth + 2]; 
    component indexBits = Num2Bits(treeDepth);
    indexBits.in <== userIndex;
    for (var i = 0; i < treeDepth; i++) {
        indexBits.out[i] * (indexBits.out[i] - 1) === 0;
    }
    signal hash_chain[treeDepth + 1];
    hash_chain[0] <== authPath[0];  // Start with the provided leaf.
    component hashers[treeDepth];
    component muxLeft[treeDepth];
    component muxRight[treeDepth];
    for (var i = 0; i < treeDepth; i++) {
        hashers[i] = PoseidonHash2();
        muxLeft[i] = ConditionalSelector();
        muxLeft[i].selector <== indexBits.out[i];
        muxLeft[i].input0 <== hash_chain[i];
        muxLeft[i].input1 <== authPath[i + 1];
        hashers[i].in0 <== muxLeft[i].selectedValue;
        muxRight[i] = ConditionalSelector();
        muxRight[i].selector <== indexBits.out[i];
        muxRight[i].input0 <== authPath[i + 1];
        muxRight[i].input1 <== hash_chain[i];
        hashers[i].in1 <== muxRight[i].selectedValue;
        hash_chain[i + 1] <== hashers[i].out;
    }
    hash_chain[treeDepth] === authPath[treeDepth + 1];
}

// --- CIBILScoreCircuit ---
// This circuit proves that a user's CIBIL score exceeds a given threshold.
template CIBILScoreCircuit(treeDepth, cibilBits) {
    // Public inputs.
    signal input merkleRoot;
    signal input threshold;  // threshold for the CIBIL score.
    // Private inputs.
    signal input userIndex;
    signal input authPath[treeDepth + 2];
    signal input userIDHash;
    signal input userCIBILScore; // CIBIL score (typically 300-900 range)

    // The CIBIL score is used directly as the final score
    signal finalScore;
    finalScore <== userCIBILScore;

    // Recompute the leaf hash using userIDHash and finalScore.
    component leafHasher = PoseidonHash2();
    leafHasher.in0 <== userIDHash;
    leafHasher.in1 <== finalScore;
    // The computed leaf must equal the first element of the authentication path.
    leafHasher.out === authPath[0];

    // Verify the Merkle proof.
    component merkleProof = MerkleProof(treeDepth);
    merkleProof.userIndex <== userIndex;
    merkleProof.authPath <== authPath;
    authPath[treeDepth + 1] === merkleRoot;

    // Compare finalScore with threshold.
    component cmp = LessThan(cibilBits);
    cmp.in[0] <== threshold;
    cmp.in[1] <== finalScore;

    // Output: 1 if finalScore > threshold, else 0.
    signal output result;
    result <== cmp.out;
}

component main { public [merkleRoot, threshold] } = CIBILScoreCircuit(10, 16);
