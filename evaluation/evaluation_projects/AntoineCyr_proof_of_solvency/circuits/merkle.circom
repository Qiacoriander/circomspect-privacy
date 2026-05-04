pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/mimcsponge.circom";
include "./utils.circom";

template MerkleSum() {
    signal input L;
    signal input R;
    signal input sumL;
    signal input sumR;
    signal output root;
    signal output sum;

    // Constants for MiMC sponge parameters
    var MIMC_INPUTS = 4; 
    var MIMC_ROUNDS = 220;    
    var MIMC_OUTPUTS = 1;  

    component hasher = MiMCSponge(MIMC_INPUTS, MIMC_ROUNDS, MIMC_OUTPUTS);
    hasher.ins[0] <== L;
    hasher.ins[1] <== sumL;
    hasher.ins[2] <== R;
    hasher.ins[3] <== sumR;
    hasher.k <== 0;
    root <== hasher.outs[0];
    sum <== sumL + sumR;
}

// Combined Merkle sum level with switcher and binary constraint
template MerkleSumLevel() {
    signal input hashNode;
    signal input sumNode;
    signal input neighborHash;
    signal input neighborSum;
    signal input neighborBinary;

    signal output hashOut;
    signal output sumOut;

    // Constrain neighborBinary to be binary (0 or 1)
    neighborBinary * (neighborBinary - 1) === 0;

    // Switch hash values based on neighborBinary
    component switcherHash = Switcher();
    switcherHash.sel <== neighborBinary;
    switcherHash.L <== hashNode;
    switcherHash.R <== neighborHash;

    // Switch sum values based on neighborBinary
    component switcherSum = Switcher();
    switcherSum.sel <== neighborBinary;
    switcherSum.L <== sumNode;
    switcherSum.R <== neighborSum;

    // Compute Merkle sum
    component merklesum = MerkleSum();
    merklesum.L <== switcherHash.outL;
    merklesum.R <== switcherHash.outR;
    merklesum.sumL <== switcherSum.outL;
    merklesum.sumR <== switcherSum.outR;

    hashOut <== merklesum.root;
    sumOut <== merklesum.sum;
}

