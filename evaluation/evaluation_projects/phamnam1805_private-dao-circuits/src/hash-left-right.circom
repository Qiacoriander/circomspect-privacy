pragma circom 2.1.4;
// include "./libs/poseidon.circom";
include "./libs/poseidon.circom";

template HashLeftRight() {
    signal input left;
    signal input right;
    signal output out;

    // component hasher = Poseidon(2, 3, 8, 57);
    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    out <== hasher.out;
    log(out);
}

component main {public [left, right]} = HashLeftRight();