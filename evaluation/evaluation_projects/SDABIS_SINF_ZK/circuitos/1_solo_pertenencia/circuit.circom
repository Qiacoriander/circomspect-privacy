pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../merkle.circom";

template EjemploCircuito(levels) {

    // -----------------------------
    // ENTRADAS PRIVADAS
    // -----------------------------
    signal input r;          // random privado
    signal input nombre[10];  // Nombre del usuario

    signal input siblings[levels];      // Prueba de pertenencia: camino a la raiz
    signal input leafIndex;

    // -----------------------------
    // ENTRADAS PÚBLICAS
    // -----------------------------
    signal output Root;   // Raíz Merkle pública

    // -----------------------------
    // V = H(r, nombre[])
    // -----------------------------
    var sizeNombre = 11;
    signal nombreInput[sizeNombre];

    nombreInput[0] <== r;
    for (var i = 0; i < 10; i++) {
        nombreInput[i+1] <== nombre[i];
    }

    component hashNombre = Poseidon(sizeNombre);
    for (var i = 0; i < sizeNombre; i++) {
        hashNombre.inputs[i] <== nombreInput[i];
    }

    // --------------------------------
    // Merkle proof verification
    // --------------------------------
    component mv = MerkleVerifier(levels);

    mv.key <== leafIndex;
    mv.value <== hashNombre.out;
    for (var i = 0; i < levels; i++) {
        mv.siblings[i]   <== siblings[i];
    }

    Root <== mv.root;
}

component main = EjemploCircuito(20);