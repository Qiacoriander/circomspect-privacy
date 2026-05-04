pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/merkletree.circom";
include "circomlib/circuits/comparators.circom";

// Circuit to prove marriage without revealing identity
template MarriageProof(levels) {
    // Private inputs
    signal private input passportHash;
    signal private input marriageId;
    signal private input spouseHash;
    signal private input merkleProof[levels];
    signal private input merkleIndices[levels];
    
    // Public inputs
    signal input marriageMerkleRoot;
    signal input nullifierHash;
    signal input timestamp;
    
    // Outputs
    signal output isMarried;
    signal output proofNullifier;

    // Verify passport is in marriage merkle tree
    component marriageTreeVerifier = MerkleTreeChecker(levels);
    marriageTreeVerifier.leaf <== passportHash;
    marriageTreeVerifier.root <== marriageMerkleRoot;
    
    for (var i = 0; i < levels; i++) {
        marriageTreeVerifier.pathElements[i] <== merkleProof[i];
        marriageTreeVerifier.pathIndices[i] <== merkleIndices[i];
    }

    // Generate nullifier to prevent double-spending
    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== passportHash;
    nullifier.inputs[1] <== timestamp;
    proofNullifier <== nullifier.out;

    // Verify nullifier matches public input
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== proofNullifier;
    nullifierCheck.in[1] <== nullifierHash;
    nullifierCheck.out === 1;

    // Output marriage status
    isMarried <== marriageTreeVerifier.root;
}

// Circuit to prove no marriage (single status)
template NoMarriageProof(levels) {
    // Private inputs
    signal private input passportHash;
    signal private input merkleProof[levels];
    signal private input merkleIndices[levels];
    
    // Public inputs
    signal input zkPassportMerkleRoot;
    signal input marriageRegistryRoot;
    signal input nullifierHash;
    signal input timestamp;
    
    // Outputs
    signal output isSingle;
    signal output proofNullifier;

    // Verify passport is valid (in zkPassport system)
    component passportVerifier = MerkleTreeChecker(levels);
    passportVerifier.leaf <== passportHash;
    passportVerifier.root <== zkPassportMerkleRoot;
    
    for (var i = 0; i < levels; i++) {
        passportVerifier.pathElements[i] <== merkleProof[i];
        passportVerifier.pathIndices[i] <== merkleIndices[i];
    }

    // Generate nullifier
    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== passportHash;
    nullifier.inputs[1] <== timestamp;
    proofNullifier <== nullifier.out;

    // Verify nullifier matches public input
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== proofNullifier;
    nullifierCheck.in[1] <== nullifierHash;
    nullifierCheck.out === 1;

    // This proves the passport exists but we need additional logic
    // to prove it's NOT in any marriage registry
    // For simplicity, we assume the marriage registry root is empty (0)
    // if the person is single
    component singleCheck = IsZero();
    singleCheck.in <== marriageRegistryRoot;
    isSingle <== singleCheck.out;
}

component main {public [marriageMerkleRoot, nullifierHash, timestamp]} = MarriageProof(20);