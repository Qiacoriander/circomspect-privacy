pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Init () {
    signal input energy;
    signal input salt;
    signal output hashedE;
    
    assert(energy > 0);
    assert(energy < 101);
    
    component hash = Poseidon(2);
    hash.inputs[0] <== energy;
    hash.inputs[1] <== salt;

    hashedE <== hash.out;
}

component main = Init();