pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template ClearanceLevel() {
    signal input actualLevel;
    signal input requiredLevel;
    signal input salt;
    signal output clearanceHash;
    signal output hasAccess;

    // Hash the clearance level with salt for privacy
    component hasher = Poseidon(2);
    hasher.inputs[0] <== actualLevel;
    hasher.inputs[1] <== salt;
    clearanceHash <== hasher.out;

    // Check if actualLevel >= requiredLevel
    component gte = GreaterEqThan(8);
    gte.in[0] <== actualLevel;
    gte.in[1] <== requiredLevel;
    hasAccess <== gte.out;
}

component main {public [requiredLevel]} = ClearanceLevel();
