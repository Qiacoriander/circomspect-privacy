include "./node_modules/circomlib/circuits/mimcsponge.circom";
include "./node_modules/circomlib/circuits/Poseidon.circom";

// Computes MiMC([left, right])
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;
    signal output hash2;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;


    hash <== hasher.out;

    //log("Poseidon Left",left);
    //log("Poseidon Right",right);
    //log("Poseidon hash",hash);

    
    //component hasher2 = MiMCSponge(2,2,1);
    //hasher2.ins[0] <== left;
    //hasher2.ins[1] <== right;
    //hasher2.k <== 0;
    //hash2 <== hasher2.outs[0];

    //log("MiMC Left",left);
    //log("MiMC Right",right);
    //log("MiMC hash",hash2);

  
}

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    log("Leaf",leaf);
    log("Root",root);
    //log("pathElements[levels]",pathElements[levels]);
    //log("pathElements[levels]",pathIndices[levels]);


    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRight();
        hashers[i].left <== selectors[i].out[0];
        hashers[i].right <== selectors[i].out[1];
    }
    
    log("Tomatch",hashers[levels - 1].hash);

    root === hashers[levels - 1].hash;
    log("Root matches successfully");

}
