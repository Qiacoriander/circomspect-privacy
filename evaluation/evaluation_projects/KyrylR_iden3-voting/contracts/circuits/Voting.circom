pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/mux1.circom";

include "../node_modules/@solarity/circom-lib/data-structures/SparseMerkleTree.circom";

// computes Poseidon(nullifier + secret)
template CommitmentHasher() {
    signal input secret;
    signal input nullifier;
    signal input proposalId;

    signal output commitment;
    signal output nullifierHash;

    component commitmentHasher = Poseidon(3);
    component nullifierHasher = Poseidon(2);

    nullifierHasher.inputs[0] <== nullifier;
    nullifierHasher.inputs[1] <== proposalId;

    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifier;
    commitmentHasher.inputs[2] <== proposalId;

    commitment <== commitmentHasher.out;
    nullifierHash <== nullifierHasher.out;
}

// Verifies that commitment that corresponds to given secret and nullifier is included in the merkle tree of deposits
template Voting(levels) {
    signal input root;
    signal input nullifierHash;

    signal input voter; // not taking part in any computations
    signal input proposalId;

    signal input secret;
    signal input nullifier;

    signal input siblings[levels];

    signal input auxKey;
    signal input auxValue;
    // 1 if the aux node is empty, 0 otherwise
    signal input auxIsEmpty;

    // 1 if we are checking for exclusion, 0 if we are checking for inclusion
    signal input isExclusion;

    component hasher = CommitmentHasher();

    hasher.secret <== secret;
    hasher.nullifier <== nullifier;
    hasher.proposalId <== proposalId;

    hasher.nullifierHash === nullifierHash;

    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== hasher.commitment;

    component smtVerifier = SparseMerkleTreeVerifier(levels);
    smtVerifier.siblings <== siblings;

    smtVerifier.key <== leafHasher.out;
    smtVerifier.value <== hasher.commitment;

    smtVerifier.auxKey <== auxKey;
    smtVerifier.auxValue <== auxValue;
    smtVerifier.auxIsEmpty <== auxIsEmpty;

    smtVerifier.isExclusion <== isExclusion;

    smtVerifier.root <== root;

    // Add hidden signals to make sure that tampering with recipient or fee will invalidate the snark proof
    // Most likely it is not required, but it's better to stay on the safe side and it only takes 2 constraints
    // Squares are used to prevent optimizer from removing those constraints
    signal voterSquare <== voter * voter;
    signal proposalIdSquare <== proposalId * proposalId;
}

component main {public [root, nullifierHash, voter, proposalId]} = Voting(80);
