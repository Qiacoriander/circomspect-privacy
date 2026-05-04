pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template AgeOver() {
    signal input age;
    signal input threshold;
    signal input salt;
    signal output ageHash;
    signal output isOver;

    // Hash the age with salt for privacy
    component hasher = Poseidon(2);
    hasher.inputs[0] <== age;
    hasher.inputs[1] <== salt;
    ageHash <== hasher.out;

    // Check if age >= threshold
    component gte = GreaterEqThan(8);
    gte.in[0] <== age;
    gte.in[1] <== threshold;
    isOver <== gte.out;
}

component main {public [threshold]} = AgeOver();
