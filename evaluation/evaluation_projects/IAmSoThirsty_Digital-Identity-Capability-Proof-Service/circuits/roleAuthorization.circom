pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template RoleAuthorization() {
    signal input userRole;
    signal input requiredRole;
    signal input salt;
    signal output roleHash;
    signal output isAuthorized;

    // Hash the role with salt for privacy
    component hasher = Poseidon(2);
    hasher.inputs[0] <== userRole;
    hasher.inputs[1] <== salt;
    roleHash <== hasher.out;

    // Check if roles match
    component eq = IsEqual();
    eq.in[0] <== userRole;
    eq.in[1] <== requiredRole;
    isAuthorized <== eq.out;
}

component main {public [requiredRole]} = RoleAuthorization();
