pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

// Profundidad fija del árbol Merkle
template MTVerifier(depth) {
    signal input root;
    signal input private_key;
    signal input siblings[depth];
    signal output valid;
    signal output generated_root;

    // Generar clave pública desde la clave privada
    component babyjub = BabyPbk();
    babyjub.in <== private_key;

    component GenPK = GenPubKey();
    GenPK.x <== babyjub.Ax;
    GenPK.y <== babyjub.Ay;

    var partial_root = GenPK.out;

    component hash[depth];

    for (var i = 0; i < depth; i++) {
        hash[i] = SMTHash2();
        hash[i].L <== partial_root;
        hash[i].R <== siblings[i];
        partial_root = hash[i].out;
    }

    generated_root <== partial_root;

    component check = IsEqual();
    check.in[0] <== root;
    check.in[1] <== partial_root;

    valid <== check.out;
}

// Hashea dos valores (L || R) con Poseidon
template SMTHash2() {
    signal input L;
    signal input R;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== L;
    h.inputs[1] <== R;
    out <== h.out;
}

// Hashea clave pública (x, y)
template GenPubKey() {
    signal input x;
    signal input y;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== x;
    h.inputs[1] <== y;
    out <== h.out;
}

component main {public [root]} = MTVerifier(16);
