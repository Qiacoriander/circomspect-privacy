pragma circom 2.1.6;

// VOTACIÓN PRIVADA: prueba de pertenencia a Merkle + nullifier único + opción válida.
// Público: root, nullifierHash, voteOption
// Privado: leaf, merkle path, secret, nullifier
// Nota: Usa Poseidon (circomlib) para hashing.

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "circomlib/merkle.circom";
include "circomlib/comparators.circom";

template VoteCircuit(depth, maxOptions) {
    // Public inputs
    signal input root;
    signal input nullifierHash;
    signal input voteOption; // 0..maxOptions-1

    // Private inputs
    signal input secret;      // identidad secreta del votante (commitment)
    signal input nullifier;   // sal para nullificador
    signal input pathElements[depth];
    signal input pathIndex[depth]; // 0/1

    // 1) leaf = Poseidon(secret)
    component HLeaf = Poseidon(1);
    HLeaf.inputs[0] <== secret;
    var leaf = HLeaf.out;

    // 2) membership proof
    component Merkle = MerkleTreeInclusionProof(depth);
    Merkle.root <== root;
    Merkle.leaf <== leaf;
    for (var i=0; i<depth; i++) {
        Merkle.path_elements[i] <== pathElements[i];
        Merkle.path_index[i] <== pathIndex[i];
    }
    Merkle.enableAssert <== 1;

    // 3) nullifier hash = Poseidon(nullifier, leaf)
    component HNull = Poseidon(2);
    HNull.inputs[0] <== nullifier;
    HNull.inputs[1] <== leaf;
    HNull.out === nullifierHash;

    // 4) voteOption en rango [0, maxOptions-1]
    // check voteOption < maxOptions (const)
    component lt = LessThan(254); // trabaja con valores < 2^254
    // lt.in[0] < lt.in[1] -> in[1] es maxOptions constante
    lt.in[0] <== voteOption;
    lt.in[1] <== maxOptions;
    lt.out === 1;
}

component main = VoteCircuit(20, 4);

