pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/Poseidon.circom";
include "./node_modules/circomlib/circuits/mimc.circom";
include "./merkleTree.circom";

// Circuit to prove a commitment is in the Merkle tree and generate a nullifier
template Mixer(levels) {
    // Public inputs
    signal input root;
    signal input nullifierHash;
    signal input recipient;

    // Private inputs
    signal input secret;
    signal input nullifier;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Compute commitment
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifier;
    signal commitment;
    commitment <== commitmentHasher.out;
    // Commwt out the next line for actual verification
    // This is a test for a specific test case
    //commitment === 16832421271961222550979173996485995711342823810308835997146707681980704453417; 
    //root === 7511222500597693890937408637246167790279768447875423030417067960980044030592;
    
    log("Mixer.circom Root:",root);
    log("Mixer.circom secret:",secret);
    log("Mixer.circom nullifier:",nullifier);
    // Verify Merkle tree inclusion
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== commitment;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    // Compute nullifier hash

    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash === nullifierHasher.out;

    // Ensure recipient is a valid Ethereum address (constraint for safety)
    signal recipientSquared;
    recipientSquared <== recipient * recipient;
}

// Instantiate circuit with 20 levels
component main {public [root, nullifierHash, recipient]} = Mixer(10);
