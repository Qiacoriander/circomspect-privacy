pragma circom  2.1.0;

include "../../../protocols/rln_poseidon_circomlib/circuits/rln.circom";
include "../../efficient_ecdsa/circuits/ecdsa_to_addr.circom";

template ECDSARLN(DEPTH, LIMIT_BIT_SIZE) {
    // Private inputs
    signal input s;
    signal input userMessageLimit;
    signal input messageId;
    signal input pathIndices[DEPTH];
    signal input siblings[DEPTH];

    // Public inputs
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;
    signal input root;
    signal input x;
    signal input externalNullifier;

    // Outputs
    signal output y;
    signal output nullifier;

    // Check the signature public key membership and extract the address
    signal address <== ECDSAToAddr(DEPTH)(s, Tx, Ty, Ux, Uy);

    // Using RLN to calculate the nullifier for that address according to the message limit and message id.
    component rln = RLN(LIMIT_BIT_SIZE);
    rln.identitySecret <== address;
    rln.userMessageLimit <== userMessageLimit;
    rln.messageId <== messageId;
    rln.pathElements <== siblings;
    rln.identityPathIndex <== pathIndices
    rln.x <== x;
    rln.externalNullifier <== externalNullifier;

    y <== rln.y;
    nullifier <== rln.nullifier;
    root === rln.root;
}

component main { public [Tx, Ty, Ux, Uy, root, x, externalNullifier] } = ECDSARLN(20, 16);
