pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

template Commitment() {
    signal input x;   
    signal output commitment;

    component poseidonHash = Poseidon(1);
    poseidonHash.inputs[0] <== x;
    
    0 === x * (1 - x);

    commitment <== poseidonHash.out;
}

component main = Commitment();