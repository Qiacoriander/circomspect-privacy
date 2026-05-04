pragma circom 2.1.8;
include "circomlib/circuits/comparators.circom";
include "merkleTree/merkleTree.circom";
include "signature/signature.circom";

template CheckKeyAndInclusion(levels) {
    signal input root;

    // 4x64 bits each
    signal input r[4];
    signal input s[4];
    signal input msgHash[4];
    // x, y, 4x64 bits each
    signal input pk[2][4];

    // inclusion proof, path is {0 = left, 1 = right}
    signal input proof[levels];
    signal input path[levels];

    signal output out;

    signal isSignatureCorrect <== CheckSignature()(r, s, pk, msgHash);
    signal isProofCorrect <== CheckInclusionProof(levels)(pk, root, proof, path);

    out <== isSignatureCorrect * isProofCorrect;
}

component main {public [root, msgHash]} = CheckKeyAndInclusion(4);

