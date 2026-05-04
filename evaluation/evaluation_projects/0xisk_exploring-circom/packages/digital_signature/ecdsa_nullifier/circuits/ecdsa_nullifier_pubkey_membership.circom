pragma circom 2.1.2;

include "./ecdsa_nullifier.circom";
include "../../../data_structure/merkle_tree/circuits/tree.circom";

template ECDSANullifierPubKeyMembership(DEPTH) {
    // Private signals
    signal input s;
    signal input secret;
    signal input pathIndices[DEPTH];
    signal input siblings[DEPTH];
    
    // Public signals
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;
    signal input root;

    // Output signals
    signal output nullifier;

    // Calculate the nullifier of the signature
    // Using Poseidon circomlib version
    component ecdsaNullifier = ECDSANullifier();
    ecdsaNullifier.s <== s;
    ecdsaNullifier.secret <== secret;
    ecdsaNullifier.Tx <== Tx;
    ecdsaNullifier.Ty <== Ty;
    ecdsaNullifier.Ux <== Ux;
    ecdsaNullifier.Uy <== Uy;
    
    nullifier <== ecdsaNullifier.nullifier;

    // Check the Nullifier membership
    // Using Poseidon secp256p1 version
    component tree = MerkleTreeInclusionProof(DEPTH)(nullifier, pathIndices, siblings);

    root === tree.root;
}

component main { public[ Tx, Ty, Ux, Uy ]} = ECDSANullifier();
