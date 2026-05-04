pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template VerifyShot() {
    // Public inputs
    signal input guessX;
    signal input guessY;
    signal input isHit;
    signal input commitment;

    // Private inputs
    signal input x;
    signal input y;
    signal input salt;

    // 1. Verify commitment
    component hasher = Poseidon(3);
    hasher.inputs[0] <== x;
    hasher.inputs[1] <== y;
    hasher.inputs[2] <== salt;
    hasher.out === commitment;

    // 2. Verify isHit
    component eqX = IsEqual();
    eqX.in[0] <== x;
    eqX.in[1] <== guessX;

    component eqY = IsEqual();
    eqY.in[0] <== y;
    eqY.in[1] <== guessY;

    signal matchX;
    matchX <== eqX.out;
    signal matchY;
    matchY <== eqY.out;

    isHit === matchX * matchY;
}

component main {public [guessX, guessY, isHit, commitment]} = VerifyShot();
