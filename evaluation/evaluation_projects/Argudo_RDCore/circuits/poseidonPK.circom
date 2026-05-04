pragma circom  2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

template PoseidonPK(){
    signal input x;
    signal input y;
    signal output out;

    component h = Poseidon(2); 
    h.inputs[0] <== x;
    h.inputs[1] <== y;

    out <== h.out;
}


component main = PoseidonPK();