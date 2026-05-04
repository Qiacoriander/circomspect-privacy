pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./Selector.circom";

template HashTreeLevel(){
    signal input in[2];
    signal input position;
    signal output out;

    component poseidon = Poseidon(2);
    component selector = Selector();

    selector.in[0] <== in[0];
    selector.in[1] <== in[1];
    selector.switcher <== position;

    selector.out[0] ==> poseidon.inputs[0];
    selector.out[1] ==> poseidon.inputs[1];

    poseidon.out ==> out;

}

